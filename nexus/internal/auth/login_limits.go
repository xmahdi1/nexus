package auth

import (
	"github.com/xmahdi1/nexus/internal/authorization"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"time"
)

// Not an account or a default password: this hash only equalizes unknown-name work.
var dummyPasswordHash = func() string {
	hash, err := bcrypt.GenerateFromPassword([]byte("not-a-login-credential"), 12)
	if err != nil {
		panic(err)
	}
	return string(hash)
}()

type loginLimit struct {
	KeyHash     string `gorm:"primaryKey"`
	Failures    int
	LockedUntil *time.Time
	UpdatedAt   time.Time
}

func (loginLimit) TableName() string { return "auth_login_limits" }
func (s *Service) locked(tx *gorm.DB, id string) bool {
	var row loginLimit
	err := tx.First(&row, "key_hash=?", tokenHash("login-limit:"+id)).Error
	if err == gorm.ErrRecordNotFound {
		return false
	}
	if err != nil {
		return true
	}
	return row.LockedUntil != nil && s.now().Before(*row.LockedUntil)
}
func (s *Service) loginFailure(tx *gorm.DB, id string) error {
	key := tokenHash("login-limit:" + id)
	var row loginLimit
	err := tx.First(&row, "key_hash=?", key).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if !s.now().Before(row.UpdatedAt.Add(15 * time.Minute)) {
		row.Failures = 0
		row.LockedUntil = nil
	}
	row.KeyHash = key
	row.Failures++
	row.UpdatedAt = s.now()
	if row.Failures >= 5 {
		until := s.now().Add(15 * time.Minute)
		row.LockedUntil = &until
	}
	if err := tx.Exec("INSERT INTO auth_login_limits(key_hash,failures,locked_until,updated_at) VALUES(?,?,?,?) ON CONFLICT(key_hash) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,updated_at=excluded.updated_at", row.KeyHash, row.Failures, row.LockedUntil, row.UpdatedAt).Error; err != nil {
		return err
	}
	return s.event(tx, id, "auth.login", "denied")
}
func (s *Service) clearFailures(tx *gorm.DB, id string) error {
	return tx.Where("key_hash=?", tokenHash("login-limit:"+id)).Delete(&loginLimit{}).Error
}
func (s *Service) event(tx *gorm.DB, actor, action, outcome string, sessions ...string) error {
	return authorization.New(tx).Record(actor, action, actor, outcome, "", sessions...)
}
