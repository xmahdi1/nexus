package auth

import (
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/identity"
	"gorm.io/gorm"
)

type Reset struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	UserID          string     `json:"userId"`
	TokenHash       string     `json:"-"`
	Kind            string     `json:"kind"`
	CredentialEpoch string     `json:"-"`
	RequestedBy     string     `json:"requestedBy"`
	Reason          string     `json:"reason"`
	CreatedAt       time.Time  `json:"createdAt"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	UsedAt          *time.Time `json:"usedAt"`
	RevokedAt       *time.Time `json:"revokedAt"`
}

func (Reset) TableName() string { return "account_resets" }

type resetEnrollment struct {
	TokenHash                        string `gorm:"primaryKey"`
	ResetID, SecretEnc, PasswordHash string
	ExpiresAt                        time.Time
}

func (resetEnrollment) TableName() string { return "account_reset_enrollments" }

type ResetResult struct {
	Reset Reset  `json:"reset"`
	Token string `json:"token"`
}

func (s *Service) IssueReset(access *Access, id, kind, reason, request string) (ResetResult, error) {
	var result ResetResult
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if !authorization.New(tx).All(a.User.ID, "", "users.manage", "roles.manage") {
			return authorization.ErrDenied
		}
		if kind == "mfa" && (!a.MFA || access.Session.MFAAt == nil || !s.now().Before(access.Session.MFAAt.Add(5*time.Minute))) {
			return ErrStepUp
		}
		result, err = s.issueReset(tx, a.User.ID, id, kind, reason, request, false)
		return err
	})
	return result, err
}
func (s *Service) issueReset(tx *gorm.DB, actor, id, kind, reason, request string, local bool) (ResetResult, error) {
	var result ResetResult
	reason = strings.TrimSpace(reason)
	if (kind != "password" && kind != "mfa") || reason == "" || len(reason) > 240 || strings.ContainsAny(reason, "\r\n\x00") {
		return result, authorization.ErrInvalid
	}
	a, err := s.loadAccount(tx, true, id)
	if err != nil || a.Mode != "owner" {
		return result, authorization.ErrInvalid
	}
	if err := tx.Model(&Credentials{}).Where("user_id=?", id).Updates(map[string]any{"version": gorm.Expr("version+1"), "recovery_required": true}).Error; err != nil {
		return result, err
	}
	if !local && !authorization.AdministratorRemains(tx) {
		return result, authorization.ErrLastAdmin
	}
	if !local && actor == id {
		return result, authorization.ErrInvalid
	}
	a, err = s.loadAccount(tx, true, id)
	if err != nil {
		return result, err
	}
	if err := s.clearFailures(tx, id); err != nil {
		return result, err
	}
	if err := s.revokeUser(tx, id); err != nil {
		return result, err
	}
	if err := tx.Model(&Reset{}).Where("user_id=? AND used_at IS NULL AND revoked_at IS NULL", id).Update("revoked_at", s.now()).Error; err != nil {
		return result, err
	}
	token, err := randomToken()
	if err != nil {
		return result, err
	}
	resetID, err := randomToken()
	if err != nil {
		return result, err
	}
	reset := Reset{ID: resetID, UserID: id, TokenHash: tokenHash(token), Kind: kind, CredentialEpoch: a.Epoch, RequestedBy: actor, Reason: reason, CreatedAt: s.now(), ExpiresAt: s.now().Add(30 * time.Minute)}
	if err := tx.Create(&reset).Error; err != nil {
		return result, err
	}
	action := "users.reset." + kind
	if local {
		action += ".local"
	}
	if err := authorization.New(tx).Record(actor, action, id, "requested", request); err != nil {
		return result, err
	}
	return ResetResult{reset, token}, nil
}
func (s *Service) LocalRecovery(username, reason string) (ResetResult, error) {
	var result ResetResult
	name, err := identity.NormalizeUsername(username)
	if err != nil {
		return result, err
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var row struct{ ID string }
		if err := tx.Table("users").Where("username=? AND status='active'", name).Take(&row).Error; err != nil {
			return err
		}
		var err error
		result, err = s.issueReset(tx, "local-cli", row.ID, "mfa", reason, "", true)
		return err
	})
	return result, err
}
func (s *Service) resetByToken(tx *gorm.DB, token string) (Reset, account, error) {
	var reset Reset
	if len(token) != 64 {
		return reset, account{}, ErrCredentials
	}
	if err := tx.Where("token_hash=?", tokenHash(token)).Take(&reset).Error; err != nil {
		return reset, account{}, ErrCredentials
	}
	a, err := s.validReset(tx, reset)
	return reset, a, err
}
func (s *Service) validReset(tx *gorm.DB, reset Reset) (account, error) {
	if reset.UsedAt != nil || reset.RevokedAt != nil || !s.now().Before(reset.ExpiresAt) {
		return account{}, ErrCredentials
	}
	if reset.RequestedBy != "local-cli" && !authorization.New(tx).All(reset.RequestedBy, "", "users.manage", "roles.manage") {
		return account{}, ErrCredentials
	}
	a, err := s.loadAccount(tx, true, reset.UserID)
	if err != nil || a.Epoch != reset.CredentialEpoch {
		return account{}, ErrCredentials
	}
	var c Credentials
	if err := tx.First(&c, "user_id=?", reset.UserID).Error; err != nil || !c.RecoveryRequired {
		return account{}, ErrCredentials
	}
	return a, nil
}
func (s *Service) ResetInfo(token string) (map[string]any, error) {
	var info map[string]any
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		reset, a, err := s.resetByToken(tx, token)
		if err != nil {
			return err
		}
		info = map[string]any{"kind": reset.Kind, "username": a.User.Username, "mfaRequired": a.MFA}
		return nil
	})
	return info, err
}
func (s *Service) CompletePasswordReset(token, password, code string) ([]string, error) {
	var codes []string
	var failure error
	if len(password) < 12 || len(password) > 1024 {
		return nil, ErrCredentials
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		reset, a, err := s.resetByToken(tx, token)
		if err != nil {
			return err
		}
		if reset.Kind != "password" {
			return ErrCredentials
		}
		if s.locked(tx, a.User.ID) {
			return ErrCredentials
		}
		if a.MFA && !s.secondFactor(tx, a, code) {
			failure = ErrCredentials
			return s.loginFailure(tx, a.User.ID)
		}
		hash, err := identity.HashPassword([]byte(password))
		if err != nil {
			return err
		}
		if err := s.replace(tx, a, hash, a.Secret, a.MFA); err != nil {
			return err
		}
		if err := tx.Model(&Credentials{}).Where("user_id=?", a.User.ID).Update("recovery_required", false).Error; err != nil {
			return err
		}
		if a.MFA {
			codes, err = s.newRecoveryCodes(tx, a.User.ID)
			if err != nil {
				return err
			}
		}
		if err := tx.Model(&reset).Update("used_at", s.now()).Error; err != nil {
			return err
		}
		if err := s.clearFailures(tx, a.User.ID); err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "users.reset.password.complete", "succeeded")
	})
	if err != nil {
		return nil, err
	}
	return codes, failure
}
func (s *Service) BeginMFAReset(token, password string) (Enrollment, error) {
	var result Enrollment
	if len(password) < 12 || len(password) > 1024 {
		return result, ErrCredentials
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		reset, a, err := s.resetByToken(tx, token)
		if err != nil {
			return err
		}
		if reset.Kind != "mfa" {
			return ErrCredentials
		}
		if s.locked(tx, a.User.ID) {
			return ErrCredentials
		}
		hash, err := identity.HashPassword([]byte(password))
		if err != nil {
			return err
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Nexus", AccountName: a.User.Username})
		if err != nil {
			return err
		}
		secret, err := nexuscrypto.Encrypt(s.Config.EncryptionKey, []byte(key.Secret()))
		if err != nil {
			return err
		}
		setup, err := randomToken()
		if err != nil {
			return err
		}
		if err := tx.Where("reset_id=?", reset.ID).Delete(&resetEnrollment{}).Error; err != nil {
			return err
		}
		if err := tx.Create(&resetEnrollment{TokenHash: tokenHash(setup), ResetID: reset.ID, SecretEnc: secret, PasswordHash: hash, ExpiresAt: s.now().Add(5 * time.Minute)}).Error; err != nil {
			return err
		}
		result = Enrollment{Secret: key.Secret(), URI: key.URL(), SetupToken: setup}
		return nil
	})
	return result, err
}
func (s *Service) ConfirmMFAReset(setup, code string) ([]string, error) {
	if len(setup) != 64 {
		return nil, ErrCredentials
	}
	var codes []string
	var failure error
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var enrollment resetEnrollment
		if err := tx.Where("token_hash=?", tokenHash(setup)).Take(&enrollment).Error; err != nil {
			return ErrCredentials
		}
		if err := tx.Delete(&enrollment).Error; err != nil {
			return err
		}
		var reset Reset
		if err := tx.First(&reset, "id=?", enrollment.ResetID).Error; err != nil {
			return err
		}
		a, err := s.validReset(tx, reset)
		if err != nil || reset.Kind != "mfa" || !s.now().Before(enrollment.ExpiresAt) {
			failure = ErrCredentials
			return nil
		}
		if s.locked(tx, a.User.ID) {
			failure = ErrCredentials
			return nil
		}
		secret, err := nexuscrypto.Decrypt(s.Config.EncryptionKey, enrollment.SecretEnc)
		if err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM auth_totp_steps WHERE principal_id=?", a.User.ID).Error; err != nil {
			return err
		}
		if !useTOTP(tx, a.User.ID, string(secret), code, s.now()) {
			failure = ErrCredentials
			return s.loginFailure(tx, a.User.ID)
		}
		if err := s.replace(tx, a, enrollment.PasswordHash, string(secret), true); err != nil {
			return err
		}
		if err := tx.Model(&Credentials{}).Where("user_id=?", a.User.ID).Update("recovery_required", false).Error; err != nil {
			return err
		}
		codes, err = s.newRecoveryCodes(tx, a.User.ID)
		if err != nil {
			return err
		}
		if err := tx.Model(&reset).Update("used_at", s.now()).Error; err != nil {
			return err
		}
		if err := s.clearFailures(tx, a.User.ID); err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "users.reset.mfa.complete", "succeeded")
	})
	if err != nil {
		return nil, err
	}
	return codes, failure
}
