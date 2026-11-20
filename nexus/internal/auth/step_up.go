package auth

import (
	"github.com/xmahdi1/nexus/internal/identity"
	"gorm.io/gorm"
	"time"
)

func (a *Access) RecentMFA() bool {
	return a.Session.MFAAt != nil && a.service != nil && a.service.now().Before(a.Session.MFAAt.Add(5*time.Minute))
}
func (s *Service) StepUp(access *Access, password, code string) error {
	var failure error
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		a, err := s.current(tx, access)
		if err != nil {
			return err
		}
		if s.locked(tx, a.User.ID) {
			return ErrCredentials
		}
		if !a.MFA || !identity.VerifyPassword(a.User.PasswordHash, []byte(password)) || !s.secondFactor(tx, a, code) {
			failure = ErrCredentials
			return s.loginFailure(tx, a.User.ID)
		}
		if err := tx.Model(&Session{}).Where("id=? AND revoked_at IS NULL", access.Session.ID).Update("mfa_at", s.now()).Error; err != nil {
			return err
		}
		if err := s.clearFailures(tx, a.User.ID); err != nil {
			return err
		}
		return s.event(tx, a.User.ID, "auth.step_up", "succeeded", access.Session.ID)
	})
	if err != nil {
		return err
	}
	return failure
}
