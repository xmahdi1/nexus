package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

var (
	ErrBootstrapConflict = errors.New("owner bootstrap already exists or account state requires recovery; no accounts were changed")
	usernamePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,63}$`)
)

func NormalizeUsername(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !usernamePattern.MatchString(username) {
		return "", errors.New("username must be 3–64 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit")
	}
	return username, nil
}

type BootstrapOptions struct{ Username, DisplayName, PasswordHash string }
type BootstrapResult struct {
	User    models.User
	Created bool
}
type ownerBootstrap struct {
	ID          int
	OwnerUserID string
	CreatedAt   time.Time
	Source      string
}

func (ownerBootstrap) TableName() string { return "identity_bootstrap" }

// BootstrapOwner is a local-only first-owner operation. BEGIN IMMEDIATE from
// db.Init serializes contenders; account and marker commit or roll back together.
// The marker records future ownership, not a current authorization bypass.
func BootstrapOwner(database *gorm.DB, options BootstrapOptions) (BootstrapResult, error) {
	var result BootstrapResult
	username, err := NormalizeUsername(options.Username)
	if err != nil {
		return result, err
	}
	display := strings.TrimSpace(options.DisplayName)
	if display == "" {
		display = username
	}
	if !utf8.ValidString(display) || utf8.RuneCountInString(display) > 120 || strings.ContainsAny(display, "\x00\r\n") {
		return result, errors.New("display name must be at most 120 characters without NUL or line breaks")
	}
	if err := ValidatePasswordHash(options.PasswordHash); err != nil {
		return result, err
	}
	err = database.Transaction(func(tx *gorm.DB) error {
		var marker ownerBootstrap
		err := tx.First(&marker, "id = ?", 1).Error
		if err == nil {
			var owner models.User
			if err := tx.First(&owner, "id = ?", marker.OwnerUserID).Error; err != nil {
				return ErrBootstrapConflict
			}
			if owner.Username != username || owner.Status != "active" || ValidatePasswordHash(owner.PasswordHash) != nil {
				return ErrBootstrapConflict
			}
			result.User = owner
			return nil // Idempotent: never replace password, identity, name or status.
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var count int64
		if err := tx.Model(&models.User{}).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrBootstrapConflict
		} // Never silently promote an existing account.
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		now := time.Now().UTC()
		user := models.User{ID: hex.EncodeToString(random), Username: username, DisplayName: display, PasswordHash: options.PasswordHash, Status: "active", CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		if err := tx.Create(&ownerBootstrap{ID: 1, OwnerUserID: user.ID, CreatedAt: now, Source: "local_cli"}).Error; err != nil {
			return err
		}
		result = BootstrapResult{User: user, Created: true}
		return nil
	})
	if err != nil {
		return BootstrapResult{}, err
	}
	return result, nil
}
