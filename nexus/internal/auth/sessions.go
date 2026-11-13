package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

const LegacyPrincipal = "legacy-admin"

var ErrUnauthorized = errors.New("authentication required or session expired")
var ErrCredentials = errors.New("invalid credentials")
var ErrConfigWrite = errors.New("legacy configuration could not be saved; activate the owner locally or update the deployment configuration")
var ErrMFAEnabled = errors.New("MFA is already enabled; disable it with your current code before enrolling another factor")
var ErrStepUp = errors.New("sign out and sign in again with MFA before changing credentials")

type State struct {
	ID                int
	Mode, OwnerUserID string
	ActivatedAt       *time.Time
}

func (State) TableName() string { return "auth_state" }

type Credentials struct {
	UserID, TotpSecretEnc string
	TotpEnabled           bool
	RecoveryRequired      bool
	Version               int
}

func (Credentials) TableName() string { return "auth_credentials" }

type Session struct {
	ID              string     `json:"id"`
	PrincipalID     string     `json:"-"`
	TokenHash       string     `json:"-"`
	CredentialEpoch string     `json:"-"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastUsedAt      time.Time  `json:"lastUsedAt"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	RevokedAt       *time.Time `json:"revokedAt,omitempty"`
	MFAAt           *time.Time `json:"-"`
	DeviceLabel     string     `json:"deviceLabel"`
	ClientIP        string     `json:"clientIP"`
}

func (Session) TableName() string { return "auth_sessions" }

type challenge struct {
	TokenHash                                                   string `gorm:"primaryKey"`
	PrincipalID, CredentialEpoch, Purpose, SessionID, SecretEnc string
	ExpiresAt                                                   time.Time
}

func (challenge) TableName() string { return "auth_challenges" }

type account struct {
	User          models.User
	Epoch, Secret string
	MFA           bool
	Mode          string
}
type Access struct {
	CheckAuthorization func() bool
	User               models.User
	Session            Session
	Mode               string
	service            *Service
}
type accessKey struct{}

func FromContext(ctx context.Context) (*Access, bool) {
	a, ok := ctx.Value(accessKey{}).(*Access)
	return a, ok
}
func WithAccess(r *http.Request, a *Access) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), accessKey{}, a))
}

type Service struct {
	DB                   *gorm.DB
	Config               *config.Config
	IdleTTL, AbsoluteTTL time.Duration
	now                  func() time.Time
}

func NewService(db *gorm.DB, cfg *config.Config) *Service {
	idle, absolute := cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL
	if idle == 0 {
		idle = 12 * time.Hour
	}
	if absolute == 0 {
		absolute = 7 * 24 * time.Hour
	}
	return &Service{DB: db, Config: cfg, IdleTTL: idle, AbsoluteTTL: absolute, now: func() time.Time { return time.Now().UTC() }}
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *Service) load(tx *gorm.DB, ids ...string) (account, error) {
	return s.loadAccount(tx, false, ids...)
}
func (s *Service) loadAccount(tx *gorm.DB, allowRecovery bool, ids ...string) (account, error) {
	var state State
	if err := tx.First(&state, "id=1").Error; err != nil {
		return account{}, err
	}
	if state.Mode == "legacy" {
		if len(ids) > 0 && ids[0] != LegacyPrincipal {
			return account{}, ErrUnauthorized
		}
		hash, secret, enabled := s.Config.AuthSnapshot()
		epoch := tokenHash(fmt.Sprintf("nexus-legacy-credential-epoch-v1\x00%s\x00%s\x00%t", hash, secret, enabled))
		return account{User: models.User{ID: LegacyPrincipal, Username: "admin", DisplayName: "Administrator", PasswordHash: hash, Status: "active"}, Epoch: epoch, Secret: secret, MFA: enabled, Mode: "legacy"}, nil
	}
	if state.Mode != "owner" {
		return account{}, ErrUnauthorized
	}
	id := state.OwnerUserID
	if len(ids) > 0 {
		id = ids[0]
	}
	var user models.User
	if err := tx.First(&user, "id = ? AND status='active'", id).Error; err != nil {
		return account{}, ErrUnauthorized
	}
	var admitted int64
	if err := tx.Table("account_admissions").Where("user_id=?", user.ID).Count(&admitted).Error; err != nil || admitted != 1 {
		return account{}, ErrUnauthorized
	}
	if user.ID == state.OwnerUserID {
		var marker struct{ OwnerUserID string }
		if err := tx.Table("identity_bootstrap").Where("id=1").Take(&marker).Error; err != nil || marker.OwnerUserID != user.ID {
			return account{}, ErrUnauthorized
		}
	}
	var credential Credentials
	if err := tx.First(&credential, "user_id = ?", user.ID).Error; err != nil {
		return account{}, ErrUnauthorized
	}
	if credential.RecoveryRequired && !allowRecovery {
		return account{}, ErrUnauthorized
	}
	secret := ""
	if credential.TotpEnabled {
		decrypted, err := nexuscrypto.Decrypt(s.Config.EncryptionKey, credential.TotpSecretEnc)
		if err != nil {
			return account{}, ErrUnauthorized
		}
		secret = string(decrypted)
		if secret == "" {
			return account{}, ErrUnauthorized
		}
	}
	return account{User: user, Epoch: tokenHash(fmt.Sprintf("nexus-owner-credential-epoch-v1\x00%s\x00%d\x00%s\x00%t", user.PasswordHash, credential.Version, credential.TotpSecretEnc, credential.TotpEnabled)), Secret: secret, MFA: credential.TotpEnabled, Mode: "owner"}, nil
}
func (s *Service) issue(tx *gorm.DB, a account, device, ip string, mfa bool) (string, error) {
	now := s.now()
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	// Keep a bounded number of active devices; trim expired data opportunistically.
	if err := tx.Where("expires_at <= ? OR (revoked_at IS NOT NULL AND revoked_at < ?)", now, now.Add(-30*24*time.Hour)).Delete(&Session{}).Error; err != nil {
		return "", err
	}
	var active []Session
	if err := tx.Where("principal_id=? AND revoked_at IS NULL", a.User.ID).Order("created_at desc").Find(&active).Error; err != nil {
		return "", err
	}
	for _, old := range active[min(len(active), 15):] {
		if err := tx.Model(&Session{}).Where("id=?", old.ID).Update("revoked_at", now).Error; err != nil {
			return "", err
		}
	}
	device = strings.TrimSpace(device)
	if len(device) > 120 {
		device = device[:120]
	}
	if device == "" {
		device = "Browser"
	}
	if len(ip) > 80 {
		ip = ip[:80]
	}
	session := Session{ID: id, PrincipalID: a.User.ID, TokenHash: tokenHash(token), CredentialEpoch: a.Epoch, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(s.AbsoluteTTL), DeviceLabel: device, ClientIP: ip}
	if mfa {
		session.MFAAt = &now
	}
	if err := tx.Create(&session).Error; err != nil {
		return "", err
	}
	if a.Mode == "owner" {
		if err := tx.Model(&models.User{}).Where("id=?", a.User.ID).Update("last_login_at", now).Error; err != nil {
			return "", err
		}
	}
	return token, nil
}

type LoginResult struct {
	Token        string
	PendingToken string
	MFARequired  bool
}

func (s *Service) Login(username, password, device, ip string) (LoginResult, error) {
	var result LoginResult
	var failure error
	if len(password) > 1024 || len(username) > 64 {
		return result, ErrCredentials
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		name := strings.ToLower(strings.TrimSpace(username))
		var state State
		if err := tx.First(&state, "id=1").Error; err != nil {
			return err
		}
		id := LegacyPrincipal
		if state.Mode == "owner" {
			var user models.User
			if err := tx.Where("username=?", name).Take(&user).Error; err != nil {
				identity.VerifyPassword(dummyPasswordHash, []byte(password))
				failure = ErrCredentials
				return s.event(tx, "", "auth.login", "denied")
			}
			id = user.ID
		} else if name != "" && name != "admin" {
			identity.VerifyPassword(dummyPasswordHash, []byte(password))
			failure = ErrCredentials
			return s.event(tx, "", "auth.login", "denied")
		}
		if s.locked(tx, id) {
			failure = ErrCredentials
			return s.event(tx, id, "auth.login", "locked")
		}
		a, err := s.load(tx, id)
		if err != nil {
			identity.VerifyPassword(dummyPasswordHash, []byte(password))
			failure = ErrCredentials
			return s.event(tx, "", "auth.login", "denied")
		}
		if !identity.VerifyPassword(a.User.PasswordHash, []byte(password)) {
			failure = ErrCredentials
			return s.loginFailure(tx, id)
		}
		if a.MFA {
			if a.Secret == "" {
				failure = ErrCredentials
				return s.loginFailure(tx, id)
			}
			token, err := s.newChallenge(tx, a, "login", "", "")
			if err != nil {
				return err
			}
			result = LoginResult{PendingToken: token, MFARequired: true}
			return s.event(tx, id, "auth.login", "mfa_pending")
		}
		if err := s.clearFailures(tx, id); err != nil {
			return err
		}
		result.Token, err = s.issue(tx, a, device, ip, false)
		if err != nil {
			return err
		}
		return s.event(tx, id, "auth.login", "succeeded")
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, failure
}

func (s *Service) newChallenge(tx *gorm.DB, a account, purpose, sessionID, secret string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := tx.Where("expires_at <= ? OR (principal_id=? AND purpose=?)", s.now(), a.User.ID, purpose).Delete(&challenge{}).Error; err != nil {
		return "", err
	}
	return token, tx.Create(&challenge{TokenHash: tokenHash(token), PrincipalID: a.User.ID, CredentialEpoch: a.Epoch, Purpose: purpose, SessionID: sessionID, SecretEnc: secret, ExpiresAt: s.now().Add(5 * time.Minute)}).Error
}
func (s *Service) validate(tx *gorm.DB, session Session) (*Access, error) {
	now := s.now()
	if session.RevokedAt != nil || !now.Before(session.ExpiresAt) || !now.Before(session.LastUsedAt.Add(s.IdleTTL)) {
		return nil, ErrUnauthorized
	}
	a, err := s.load(tx, session.PrincipalID)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if session.PrincipalID != a.User.ID || session.CredentialEpoch != a.Epoch {
		return nil, ErrUnauthorized
	}
	return &Access{User: a.User, Session: session, Mode: a.Mode, service: s}, nil
}
func (s *Service) Authenticate(token string) (*Access, error) {
	if len(token) != 64 {
		return nil, ErrUnauthorized
	}
	var access *Access
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var session Session
		if err := tx.First(&session, "token_hash=?", tokenHash(token)).Error; err != nil {
			return ErrUnauthorized
		}
		var err error
		access, err = s.validate(tx, session)
		if err != nil {
			return err
		}
		return tx.Model(&Session{}).Where("id=? AND revoked_at IS NULL", session.ID).Update("last_used_at", s.now()).Error
	})
	return access, err
}

// WatchAccess closes privileged streams after revocation, expiry or disablement.
// Traffic does not refresh idle expiry: a fresh HTTP session check must do that.
func WatchAccess(r *http.Request, closeStream func()) func() {
	access, ok := FromContext(r.Context())
	if !ok {
		closeStream()
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-r.Context().Done():
				closeStream()
				return
			case <-ticker.C:
				var session Session
				if err := access.service.DB.First(&session, "id=?", access.Session.ID).Error; err != nil {
					closeStream()
					return
				}
				if _, err := access.service.validate(access.service.DB, session); err != nil || (access.CheckAuthorization != nil && !access.CheckAuthorization()) {
					closeStream()
					return
				}
			}
		}
	}()
	return func() { close(stop) }
}
func (s *Service) Revoke(access *Access, id string, all bool) error {
	query := s.DB.Model(&Session{}).Where("principal_id=? AND revoked_at IS NULL", access.User.ID)
	if !all {
		query = query.Where("id=?", id)
	}
	result := query.Update("revoked_at", s.now())
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 && !all {
		return gorm.ErrRecordNotFound
	}
	return nil
}
func (s *Service) Sessions(access *Access) ([]Session, error) {
	sessions := []Session{}
	err := s.DB.Where("principal_id=? AND revoked_at IS NULL AND expires_at>? AND last_used_at>?", access.User.ID, s.now(), s.now().Add(-s.IdleTTL)).Order("created_at desc").Limit(16).Find(&sessions).Error
	return sessions, err
}
