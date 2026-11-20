package authorization

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
)

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (s *Service) validateScope(kind, id string) bool {
	if kind == "global" {
		return id == ""
	}
	var count int64
	switch kind {
	case "server":
		return s.DB.Table("servers").Where("id=?", id).Count(&count).Error == nil && count == 1
	case "server_group":
		return s.DB.Table("server_groups").Where("id=?", id).Count(&count).Error == nil && count == 1
	}
	return false
}
func invalidate(tx *gorm.DB, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := tx.Table("auth_sessions").Where("principal_id IN ? AND revoked_at IS NULL", ids).Update("revoked_at", time.Now().UTC()).Error; err != nil {
		return err
	}
	return tx.Exec("DELETE FROM auth_challenges WHERE principal_id IN ?", ids).Error
}

// AdministratorRemains counts only admitted, active, login-capable administrators.
func AdministratorRemains(tx *gorm.DB) bool {
	var state struct{ Mode string }
	if err := tx.Table("auth_state").Where("id=1").Take(&state).Error; err != nil {
		return false
	}
	if state.Mode == "legacy" {
		return New(tx).All(LegacyPrincipal, "", "roles.manage", "users.manage")
	}
	if state.Mode != "owner" {
		return false
	}
	var ids []string
	if err := tx.Table("users u").Joins("JOIN account_admissions a ON a.user_id=u.id").Joins("JOIN auth_credentials c ON c.user_id=u.id").Where("u.status='active' AND c.recovery_required=0 AND length(u.password_hash)>0").Pluck("u.id", &ids).Error; err != nil {
		return false
	}
	for _, id := range ids {
		if New(tx).All(id, "", "roles.manage", "users.manage") {
			return true
		}
	}
	return false
}

func (s *Service) AddGrant(actor, principal, role, scope, id, request string) (Grant, error) {
	var grant Grant
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		service := New(tx)
		if !service.Check(actor, "roles.manage", "") {
			return ErrDenied
		}
		kind, ok := service.principal(principal, true)
		if !ok || !service.validateScope(scope, id) {
			return ErrInvalid
		}
		var count int64
		if err := tx.Table("roles").Where("id=?", role).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return ErrInvalid
		}
		// The built-in collector cannot be elevated into an execution identity.
		if kind == "service" && role != "collector" {
			return ErrInvalid
		}
		generated, err := newID()
		if err != nil {
			return err
		}
		grant = Grant{ID: generated, PrincipalID: principal, PrincipalKind: kind, RoleID: role, ScopeType: scope, ScopeID: id, CreatedBy: actor, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&grant).Error; err != nil {
			return err
		}
		if err := invalidate(tx, []string{principal}); err != nil {
			return err
		}
		return service.Record(actor, "grants.create", grant.ID, "succeeded", request)
	})
	return grant, err
}
func (s *Service) DeleteGrant(actor, id, request string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		service := New(tx)
		if !service.Check(actor, "roles.manage", "") {
			return ErrDenied
		}
		var grant Grant
		if err := tx.First(&grant, "id=?", id).Error; err != nil {
			return err
		}
		if err := tx.Delete(&grant).Error; err != nil {
			return err
		}
		if !AdministratorRemains(tx) {
			return ErrLastAdmin
		}
		if err := invalidate(tx, []string{grant.PrincipalID}); err != nil {
			return err
		}
		return service.Record(actor, "grants.delete", id, "succeeded", request)
	})
}
func (s *Service) CreateGroup(actor, name, request string) (Group, error) {
	var group Group
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 80 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
		return group, ErrInvalid
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		service := New(tx)
		if !service.Check(actor, "groups.manage", "") {
			return ErrDenied
		}
		id, err := newID()
		if err != nil {
			return err
		}
		group = Group{RequireMFA: strings.EqualFold(strings.TrimSpace(name), "production"), ID: id, Name: name, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&group).Error; err != nil {
			return err
		}
		return service.Record(actor, "groups.create", id, "succeeded", request)
	})
	return group, err
}
func (s *Service) Membership(actor, group, server string, remove bool, request string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		service := New(tx)
		if !service.All(actor, "", "groups.manage", "roles.manage") {
			return ErrDenied
		}
		if !service.validateScope("server_group", group) || !service.validateScope("server", server) {
			return gorm.ErrRecordNotFound
		}
		if remove {
			if err := tx.Exec("DELETE FROM server_group_members WHERE group_id=? AND server_id=?", group, server).Error; err != nil {
				return err
			}
		} else {
			if err := tx.Exec("INSERT INTO server_group_members(group_id,server_id) VALUES(?,?) ON CONFLICT DO NOTHING", group, server).Error; err != nil {
				return err
			}
		}
		var principals []string
		if err := tx.Table("role_grants").Where("scope_type='server_group' AND scope_id=?", group).Distinct().Pluck("principal_id", &principals).Error; err != nil {
			return err
		}
		if err := invalidate(tx, principals); err != nil {
			return err
		}
		return service.Record(actor, "groups.membership", group, "succeeded", request)
	})
}
func (s *Service) DeleteGroup(actor, group, request string) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		service := New(tx)
		if !service.All(actor, "", "groups.manage", "roles.manage") {
			return ErrDenied
		}
		if !service.validateScope("server_group", group) {
			return gorm.ErrRecordNotFound
		}
		var principals []string
		if err := tx.Table("role_grants").Where("scope_type='server_group' AND scope_id=?", group).Distinct().Pluck("principal_id", &principals).Error; err != nil {
			return err
		}
		if err := invalidate(tx, principals); err != nil {
			return err
		}
		for _, query := range []string{"DELETE FROM server_group_members WHERE group_id=?", "DELETE FROM role_grants WHERE scope_type='server_group' AND scope_id=?", "DELETE FROM server_groups WHERE id=?"} {
			if err := tx.Exec(query, group).Error; err != nil {
				return err
			}
		}
		return service.Record(actor, "groups.delete", group, "succeeded", request)
	})
}
