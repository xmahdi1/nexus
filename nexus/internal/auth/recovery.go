package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/identity"
	"gorm.io/gorm"
)

type recoveryCode struct {
	UserID    string `gorm:"primaryKey"`
	CodeHash  string `gorm:"primaryKey"`
	CreatedAt time.Time
	UsedAt    *time.Time
}

func (recoveryCode) TableName() string { return "auth_recovery_codes" }
func (s *Service) newRecoveryCodes(tx *gorm.DB, id string) ([]string, error) {
	if err := tx.Where("user_id=?", id).Delete(&recoveryCode{}).Error; err != nil {
		return nil, err
	}
	codes := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		raw := hex.EncodeToString(random)
		formatted := raw[:8] + "-" + raw[8:16] + "-" + raw[16:24] + "-" + raw[24:]
		codes = append(codes, formatted)
		if err := tx.Create(&recoveryCode{UserID: id, CodeHash: tokenHash("recovery-code-v1:" + raw), CreatedAt: s.now()}).Error; err != nil {
			return nil, err
		}
	}
	return codes, nil
}
func (s *Service) useRecovery(tx *gorm.DB, id, code string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(normalized) != 32 {
		return false
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return false
	}
	result := tx.Model(&recoveryCode{}).Where("user_id=? AND code_hash=? AND used_at IS NULL", id, tokenHash("recovery-code-v1:"+normalized)).Update("used_at", s.now())
	return result.Error == nil && result.RowsAffected == 1
}
func (s *Service) secondFactor(tx *gorm.DB, a account, code string) bool {
	return useTOTP(tx, a.User.ID, a.Secret, code, s.now()) || s.useRecovery(tx, a.User.ID, code)
}
func (s *Service) RecoveryRemaining(id string) (int64, error) {
	var count int64
	err := s.DB.Model(&recoveryCode{}).Where("user_id=? AND used_at IS NULL", id).Count(&count).Error
	return count, err
}
func (s *Service) RegenerateRecovery(access *Access, password string) ([]string, error) {
	var codes []string
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if !identity.VerifyPassword(access.User.PasswordHash, []byte(password)) {
			return ErrCredentials
		}
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if !a.MFA || access.Session.MFAAt == nil || !s.now().Before(access.Session.MFAAt.Add(5*time.Minute)) {
			return ErrStepUp
		}
		codes, err = s.newRecoveryCodes(tx, a.User.ID)
		if err != nil {
			return err
		}
		if err := s.revokeUser(tx, a.User.ID); err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "auth.recovery_codes.regenerate", "succeeded")
	})
	return codes, err
}
func (s *Service) VerifyRecovery(pending, code, device, ip string) (LoginResult, error) {
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
		if err != nil || s.locked(tx, ch.PrincipalID) || !s.now().Before(ch.ExpiresAt) || ch.CredentialEpoch != a.Epoch || !a.MFA {
			failure = ErrCredentials
			return nil
		}
		if !s.useRecovery(tx, a.User.ID, code) {
			failure = ErrCredentials
			return s.loginFailure(tx, a.User.ID)
		}
		if err := s.revokeUser(tx, a.User.ID); err != nil {
			return err
		}
		if err := s.clearFailures(tx, a.User.ID); err != nil {
			return err
		}
		result.Token, err = s.issue(tx, a, device, ip, true)
		if err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "auth.recovery_code.use", a.User.ID, "succeeded", "")
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, failure
}
