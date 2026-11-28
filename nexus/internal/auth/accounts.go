package auth

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

var ErrActivationRequired = errors.New("activate the database owner locally before inviting accounts")

type Invitation struct {
	ID         string     `gorm:"primaryKey" json:"id"`
	UserID     string     `json:"userId"`
	TokenHash  string     `json:"-"`
	InviterID  string     `json:"inviterId"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RedeemedAt *time.Time `json:"redeemedAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
}

func (Invitation) TableName() string { return "account_invitations" }

type InviteOptions struct {
	Username, DisplayName, Email, RoleID, ScopeType, ScopeID string
	ExpiresHours                                             int
}
type InviteResult struct {
	Invitation Invitation `json:"invitation"`
	Username   string     `json:"username"`
	Token      string     `json:"token"`
}

func validDisplay(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) <= 120 && !strings.ContainsAny(name, "\x00\r\n")
}
func (s *Service) CreateInvitation(access *Access, input InviteOptions, request string) (InviteResult, error) {
	var result InviteResult
	username, err := identity.NormalizeUsername(input.Username)
	if err != nil {
		return result, authorization.ErrInvalid
	}
	display := strings.TrimSpace(input.DisplayName)
	if display == "" {
		display = username
	}
	if !validDisplay(display) {
		return result, authorization.ErrInvalid
	}
	var email *string
	if input.Email != "" {
		value := strings.TrimSpace(input.Email)
		parsed, err := mail.ParseAddress(value)
		if err != nil || len(value) > 254 || parsed.Address != value {
			return result, authorization.ErrInvalid
		}
		email = &value
	}
	if input.ExpiresHours == 0 {
		input.ExpiresHours = 24
	}
	if input.ExpiresHours < 1 || input.ExpiresHours > 72 {
		return result, authorization.ErrInvalid
	}
	if input.RoleID == "collector" {
		return result, authorization.ErrInvalid
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := s.current(tx, access); err != nil {
			return err
		}
		if !authorization.New(tx).All(access.User.ID, "", "users.manage", "roles.manage") {
			return authorization.ErrDenied
		}
		var state State
		if err := tx.First(&state, "id=1").Error; err != nil {
			return err
		}
		if state.Mode != "owner" {
			return ErrActivationRequired
		}
		var user models.User
		err := tx.Where("username=?", username).Take(&user).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && user.Status != "invited" {
			return authorization.ErrInvalid
		}
		now := s.now()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			id, err := randomToken()
			if err != nil {
				return err
			}
			user = models.User{ID: id, Username: username, DisplayName: display, Email: email, Status: "invited", CreatedAt: now, UpdatedAt: now}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}
		} else {
			if err := tx.Model(&user).Updates(map[string]any{"display_name": display, "email": email, "updated_at": now}).Error; err != nil {
				return err
			}
		}
		if err := tx.Model(&Invitation{}).Where("user_id=? AND redeemed_at IS NULL AND revoked_at IS NULL", user.ID).Update("revoked_at", now).Error; err != nil {
			return err
		}
		if err := tx.Where("principal_id=? AND principal_kind='user'", user.ID).Delete(&authorization.Grant{}).Error; err != nil {
			return err
		}
		if _, err := authorization.New(tx).AddGrant(access.User.ID, user.ID, input.RoleID, input.ScopeType, input.ScopeID, request); err != nil {
			return err
		}
		id, err := randomToken()
		if err != nil {
			return err
		}
		token, err := randomToken()
		if err != nil {
			return err
		}
		invite := Invitation{ID: id, UserID: user.ID, TokenHash: tokenHash(token), InviterID: access.User.ID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(input.ExpiresHours) * time.Hour)}
		if err := tx.Create(&invite).Error; err != nil {
			return err
		}
		if err := authorization.New(tx).Record(access.User.ID, "users.invite", user.ID, "succeeded", request); err != nil {
			return err
		}
		result = InviteResult{invite, username, token}
		return nil
	})
	return result, err
}
func validInviteGrant(tx *gorm.DB, id string) bool {
	var grants []authorization.Grant
	if err := tx.Where("principal_id=? AND principal_kind='user'", id).Find(&grants).Error; err != nil {
		return false
	}
	for _, g := range grants {
		var count int64
		if err := tx.Table("role_permissions p").Joins("JOIN roles r ON r.id=p.role_id").Where("p.role_id=?", g.RoleID).Count(&count).Error; err != nil || count == 0 {
			continue
		}
		switch g.ScopeType {
		case "global":
			if g.ScopeID == "" {
				return true
			}
		case "server":
			if tx.Table("servers").Where("id=?", g.ScopeID).Count(&count).Error == nil && count == 1 {
				return true
			}
		case "server_group":
			if tx.Table("server_groups").Where("id=?", g.ScopeID).Count(&count).Error == nil && count == 1 {
				return true
			}
		}
	}
	return false
}
func (s *Service) AcceptInvitation(token, password string) (string, error) {
	if len(token) != 64 || len(password) < 12 || len(password) > 1024 {
		return "", ErrCredentials
	}
	username := ""
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var state State
		if err := tx.First(&state, "id=1").Error; err != nil || state.Mode != "owner" {
			return ErrCredentials
		}
		var invite Invitation
		if err := tx.Where("token_hash=?", tokenHash(token)).Take(&invite).Error; err != nil {
			return ErrCredentials
		}
		if invite.RevokedAt != nil || invite.RedeemedAt != nil || !s.now().Before(invite.ExpiresAt) {
			return ErrCredentials
		}
		if !authorization.New(tx).All(invite.InviterID, "", "users.manage", "roles.manage") || !validInviteGrant(tx, invite.UserID) {
			return ErrCredentials
		}
		var user models.User
		if err := tx.Where("id=? AND status='invited'", invite.UserID).Take(&user).Error; err != nil {
			return ErrCredentials
		}
		hash, err := identity.HashPassword([]byte(password))
		if err != nil {
			return err
		}
		if err := tx.Model(&user).Updates(map[string]any{"password_hash": hash, "status": "active", "updated_at": s.now()}).Error; err != nil {
			return err
		}
		if err := tx.Create(&Credentials{UserID: user.ID, Version: 1}).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO account_admissions(user_id,source,admitted_at) VALUES(?,'invitation',?)", user.ID, s.now()).Error; err != nil {
			return err
		}
		if err := tx.Model(&invite).Update("redeemed_at", s.now()).Error; err != nil {
			return err
		}
		username = user.Username
		return s.event(tx, user.ID, "users.invite.accept", "succeeded")
	})
	return username, err
}
func (s *Service) RevokeInvitation(access *Access, id, request string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := s.current(tx, access); err != nil {
			return err
		}
		if !authorization.New(tx).All(access.User.ID, "", "users.manage", "roles.manage") {
			return authorization.ErrDenied
		}
		var invite Invitation
		if err := tx.First(&invite, "id=? AND redeemed_at IS NULL", id).Error; err != nil {
			return err
		}
		if err := tx.Model(&invite).Update("revoked_at", s.now()).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(access.User.ID, "users.invite.revoke", invite.UserID, "succeeded", request)
	})
}
func (s *Service) revokeUser(tx *gorm.DB, id string) error {
	if err := tx.Model(&Session{}).Where("principal_id=? AND revoked_at IS NULL", id).Update("revoked_at", s.now()).Error; err != nil {
		return err
	}
	if err := tx.Where("principal_id=?", id).Delete(&challenge{}).Error; err != nil {
		return err
	}
	return nil
}
func (s *Service) ChangeStatus(access *Access, id, status, request string) error {
	if status != "active" && status != "disabled" {
		return authorization.ErrInvalid
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := s.current(tx, access); err != nil {
			return err
		}
		if !authorization.New(tx).All(access.User.ID, "", "users.manage", "roles.manage") {
			return authorization.ErrDenied
		}
		var user models.User
		if err := tx.First(&user, "id=? AND status IN ?", id, []string{"active", "disabled"}).Error; err != nil {
			return err
		}
		var count int64
		if err := tx.Table("account_admissions").Where("user_id=?", id).Count(&count).Error; err != nil || count != 1 {
			return authorization.ErrInvalid
		}
		if err := tx.Model(&user).Updates(map[string]any{"status": status, "updated_at": s.now()}).Error; err != nil {
			return err
		}
		if !authorization.AdministratorRemains(tx) {
			return authorization.ErrLastAdmin
		}
		if err := tx.Model(&Credentials{}).Where("user_id=?", id).Update("version", gorm.Expr("version+1")).Error; err != nil {
			return err
		}
		if err := s.revokeUser(tx, id); err != nil {
			return err
		}
		if err := tx.Model(&Invitation{}).Where("inviter_id=? AND redeemed_at IS NULL AND revoked_at IS NULL", id).Update("revoked_at", s.now()).Error; err != nil {
			return err
		}
		if err := tx.Model(&Reset{}).Where("(user_id=? OR requested_by=?) AND used_at IS NULL AND revoked_at IS NULL", id, id).Update("revoked_at", s.now()).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(access.User.ID, "users.status."+status, id, "succeeded", request)
	})
}
func (s *Service) Unlock(access *Access, id, request string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if _, err := s.current(tx, access); err != nil {
			return err
		}
		if !authorization.New(tx).All(access.User.ID, "", "users.manage", "roles.manage") {
			return authorization.ErrDenied
		}
		var user models.User
		if err := tx.First(&user, "id=?", id).Error; err != nil {
			return err
		}
		if err := s.clearFailures(tx, id); err != nil {
			return err
		}
		return authorization.New(tx).Record(access.User.ID, "users.unlock", id, "succeeded", request)
	})
}
