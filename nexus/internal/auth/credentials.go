package auth

import (
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func useTOTP(tx *gorm.DB, id, secret, code string, now time.Time) bool {
	if len(code) != 6 || secret == "" {
		return false
	}
	for delta := int64(-1); delta <= 1; delta++ {
		step := now.Unix()/30 + delta
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(step*30, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(code)) != 1 {
			continue
		}
		result := tx.Exec(`INSERT INTO auth_totp_steps(principal_id,last_step) VALUES(?,?) ON CONFLICT(principal_id) DO UPDATE SET last_step=excluded.last_step WHERE auth_totp_steps.last_step < excluded.last_step`, id, step)
		return result.Error == nil && result.RowsAffected == 1
	}
	return false
}
func (s *Service) VerifyMFA(pending, code, device, ip string) (LoginResult, error) {
	var result LoginResult
	var failure error
	if len(pending) != 64 {
		return result, ErrCredentials
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var ch challenge
		if err := tx.First(&ch, "token_hash=? AND purpose='login'", tokenHash(pending)).Error; err != nil {
			return ErrCredentials
		}
		if err := tx.Delete(&ch).Error; err != nil {
			return err
		}
		a, err := s.load(tx, ch.PrincipalID)
		if err != nil || s.locked(tx, ch.PrincipalID) || ch.PrincipalID != a.User.ID || ch.CredentialEpoch != a.Epoch || !s.now().Before(ch.ExpiresAt) || !a.MFA {
			failure = ErrCredentials
			return nil
		}
		if !useTOTP(tx, a.User.ID, a.Secret, code, s.now()) {
			failure = ErrCredentials
			return s.loginFailure(tx, ch.PrincipalID)
		}
		if err := s.clearFailures(tx, a.User.ID); err != nil {
			return err
		}
		result.Token, err = s.issue(tx, a, device, ip, true)
		if err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "auth.mfa", "succeeded")
	})
	if err != nil {
		return result, err
	}
	return result, failure
}
func (s *Service) current(tx *gorm.DB, access *Access) (account, error) {
	var session Session
	if err := tx.First(&session, "id=?", access.Session.ID).Error; err != nil {
		return account{}, ErrUnauthorized
	}
	if _, err := s.validate(tx, session); err != nil {
		return account{}, err
	}
	return s.load(tx, access.User.ID)
}
func (s *Service) replace(tx *gorm.DB, a account, hash, secret string, enabled bool) error {
	if a.Mode == "owner" {
		encrypted := ""
		if enabled {
			var err error
			encrypted, err = nexuscrypto.Encrypt(s.Config.EncryptionKey, []byte(secret))
			if err != nil {
				return err
			}
		}
		if err := tx.Model(&models.User{}).Where("id=?", a.User.ID).Updates(map[string]any{"password_hash": hash, "updated_at": s.now()}).Error; err != nil {
			return err
		}
		if err := tx.Model(&Credentials{}).Where("user_id=?", a.User.ID).Updates(map[string]any{"totp_secret_enc": encrypted, "totp_enabled": enabled, "version": gorm.Expr("version+1")}).Error; err != nil {
			return err
		}
	} else {
		// The config file is external to SQLite. Epoch validation still rejects old
		// sessions even if the subsequent SQL commit fails after a config update.
		if hash != a.User.PasswordHash {
			if err := s.Config.UpdatePasswordHash(hash); err != nil {
				return ErrConfigWrite
			}
		}
		if enabled != a.MFA || secret != a.Secret {
			if err := s.Config.UpdateTOTP(secret, enabled); err != nil {
				return ErrConfigWrite
			}
		}
	}
	if err := tx.Model(&Session{}).Where("principal_id=? AND revoked_at IS NULL", a.User.ID).Update("revoked_at", s.now()).Error; err != nil {
		return err
	}
	return tx.Where("principal_id=?", a.User.ID).Delete(&challenge{}).Error
}
func (s *Service) ChangePassword(access *Access, current, next string) error {
	if len(current) > 1024 {
		return ErrCredentials
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if !identity.VerifyPassword(a.User.PasswordHash, []byte(current)) {
			return ErrCredentials
		}
		if a.MFA && (access.Session.MFAAt == nil || !s.now().Before(access.Session.MFAAt.Add(5*time.Minute))) {
			return ErrStepUp
		}
		hash, err := identity.HashPassword([]byte(next))
		if err != nil {
			return err
		}
		// Legacy auth also understands Argon2id through this service after this slice.
		return s.replace(tx, a, hash, a.Secret, a.MFA)
	})
}

type Enrollment struct {
	Secret     string `json:"secret"`
	URI        string `json:"uri"`
	SetupToken string `json:"setupToken"`
}

func (s *Service) SetupMFA(access *Access, password string) (Enrollment, error) {
	var result Enrollment
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if a.MFA {
			return ErrMFAEnabled
		}
		if !identity.VerifyPassword(a.User.PasswordHash, []byte(password)) {
			return ErrCredentials
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Nexus", AccountName: a.User.Username})
		if err != nil {
			return err
		}
		encrypted, err := nexuscrypto.Encrypt(s.Config.EncryptionKey, []byte(key.Secret()))
		if err != nil {
			return err
		}
		token, err := s.newChallenge(tx, a, "enroll", access.Session.ID, encrypted)
		if err != nil {
			return err
		}
		result = Enrollment{key.Secret(), key.URL(), token}
		return nil
	})
	return result, err
}
func (s *Service) EnableMFA(access *Access, token, code string) ([]string, error) {
	if len(token) != 64 {
		return nil, ErrCredentials
	}
	var failure error
	var codes []string
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		var ch challenge
		if err := tx.First(&ch, "token_hash=? AND purpose='enroll' AND session_id=?", tokenHash(token), access.Session.ID).Error; err != nil {
			return ErrCredentials
		}
		if err := tx.Delete(&ch).Error; err != nil {
			return err
		}
		if a.MFA || ch.PrincipalID != a.User.ID || ch.CredentialEpoch != a.Epoch || !s.now().Before(ch.ExpiresAt) {
			failure = ErrCredentials
			return nil
		}
		secret, err := nexuscrypto.Decrypt(s.Config.EncryptionKey, ch.SecretEnc)
		if err != nil {
			return err
		}
		// A prior disabled factor's replay counter must not block a fresh factor.
		if err := tx.Exec("DELETE FROM auth_totp_steps WHERE principal_id=?", a.User.ID).Error; err != nil {
			return err
		}
		if !useTOTP(tx, a.User.ID, string(secret), code, s.now()) {
			failure = ErrCredentials
			return nil
		}
		if err := s.replace(tx, a, a.User.PasswordHash, string(secret), true); err != nil {
			return err
		}
		codes, err = s.newRecoveryCodes(tx, a.User.ID)
		if err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "auth.mfa.enable", "succeeded")
	})
	if err != nil {
		return nil, err
	}
	return codes, failure
}
func (s *Service) DisableMFA(access *Access, code string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if !a.MFA || !s.secondFactor(tx, a, code) {
			return ErrCredentials
		}
		if err := tx.Where("user_id=?", a.User.ID).Delete(&recoveryCode{}).Error; err != nil {
			return err
		}
		if err := s.replace(tx, a, a.User.PasswordHash, "", false); err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "auth.mfa.disable", "succeeded")
	})
}
func (s *Service) MFAEnabled(access *Access) (bool, error) {
	a, err := s.load(s.DB, access.User.ID)
	return a.MFA, err
}

// ActivateOwner reconciles the live legacy credentials at the explicit local
// cutover. It never accepts an older dormant password or bypasses legacy MFA.
func ActivateOwner(database *gorm.DB, cfg *config.Config, username string) error {
	normalized, err := identity.NormalizeUsername(username)
	if err != nil {
		return err
	}
	hash, secret, enabled := cfg.AuthSnapshot()
	if err := identity.ValidatePasswordHash(hash); err != nil {
		return err
	}
	encrypted := ""
	if enabled {
		if strings.TrimSpace(secret) == "" {
			return errors.New("enabled legacy MFA has no usable secret")
		}
		if _, err := totp.GenerateCode(secret, time.Now()); err != nil {
			return errors.New("legacy MFA secret is invalid")
		}
		encrypted, err = nexuscrypto.Encrypt(cfg.EncryptionKey, []byte(secret))
		if err != nil {
			return err
		}
	}
	return database.Transaction(func(tx *gorm.DB) error {
		var state State
		if err := tx.First(&state, "id=1").Error; err != nil {
			return err
		}
		if state.Mode != "legacy" {
			return errors.New("account login is already active; credentials were not changed")
		}
		var marker struct{ OwnerUserID string }
		if err := tx.Table("identity_bootstrap").Where("id=1").Take(&marker).Error; err != nil {
			return errors.New("bootstrap the owner locally before activation")
		}
		var user models.User
		if err := tx.First(&user, "id=? AND username=? AND status='active'", marker.OwnerUserID, normalized).Error; err != nil {
			return errors.New("owner state does not match; no credentials were changed")
		}
		if err := tx.Model(&user).Updates(map[string]any{"password_hash": hash, "updated_at": time.Now().UTC()}).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO account_admissions(user_id,source,admitted_at) VALUES(?,'owner',?)", user.ID, time.Now().UTC()).Error; err != nil {
			return err
		}
		if err := tx.Create(&Credentials{UserID: user.ID, TotpSecretEnc: encrypted, TotpEnabled: enabled, Version: 1}).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM auth_challenges").Error; err != nil {
			return err
		}
		if err := tx.Model(&Session{}).Where("revoked_at IS NULL").Update("revoked_at", time.Now().UTC()).Error; err != nil {
			return err
		}
		// Explicit compatibility grants and legacy task identities follow the local
		// owner cutover atomically; there is no permanent owner bypass.
		if err := tx.Exec("UPDATE OR IGNORE role_grants SET principal_id=?,principal_kind='user' WHERE principal_id=? AND principal_kind='legacy'", user.ID, LegacyPrincipal).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM role_grants WHERE principal_id=? AND principal_kind='legacy'", LegacyPrincipal).Error; err != nil {
			return err
		}
		if err := tx.Exec("UPDATE scheduled_tasks SET actor_id=? WHERE actor_id=?", user.ID, LegacyPrincipal).Error; err != nil {
			return err
		}
		// Carry over replay protection when preserving the same authenticator.
		if enabled {
			if err := tx.Exec(`INSERT INTO auth_totp_steps(principal_id,last_step) SELECT ?,last_step FROM auth_totp_steps WHERE principal_id=? ON CONFLICT(principal_id) DO UPDATE SET last_step=excluded.last_step`, user.ID, LegacyPrincipal).Error; err != nil {
				return err
			}
		}
		if err := tx.Exec("INSERT INTO authorization_events(at,actor_id,action,resource_id,outcome,request_id) VALUES(?,'local-cli','owner.activate',?,'succeeded','')", time.Now().UTC(), user.ID).Error; err != nil {
			return err
		}
		return tx.Model(&state).Updates(map[string]any{"mode": "owner", "owner_user_id": user.ID, "activated_at": time.Now().UTC()}).Error
	})
}

// RequirePassword protects authorization administration with current credential
// proof and recent MFA when enabled, without allowing a session-only escalation.
func (s *Service) RequirePassword(access *Access, password string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if !identity.VerifyPassword(a.User.PasswordHash, []byte(password)) {
			return ErrCredentials
		}
		if a.MFA && (access.Session.MFAAt == nil || !s.now().Before(access.Session.MFAAt.Add(5*time.Minute))) {
			return ErrStepUp
		}
		return nil
	})
}
