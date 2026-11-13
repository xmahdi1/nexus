package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/mattn/go-sqlite3"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"gorm.io/gorm"
)

type AuthorizationHandler struct {
	db       *gorm.DB
	policy   *authorization.Service
	sessions *auth.Service
}

func NewAuthorizationHandler(db *gorm.DB, cfg *config.Config) *AuthorizationHandler {
	return &AuthorizationHandler{db, authorization.New(db), auth.NewService(db, cfg)}
}
func (h *AuthorizationHandler) Permissions(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	global := map[string]bool{}
	for _, ps := range authorization.RoleTemplates {
		for _, p := range ps {
			global[p] = h.policy.Check(a.User.ID, p, "")
		}
	}
	ids, err := h.policy.VisibleIDs(a.User.ID, "servers.read")
	if err != nil {
		writeErr(w, "Could not load permissions.", "internal", 500)
		return
	}
	scoped := map[string][]string{}
	for _, id := range ids {
		for permission := range global {
			if h.policy.Check(a.User.ID, permission, id) {
				scoped[id] = append(scoped[id], permission)
			}
		}
		sort.Strings(scoped[id])
	}
	writeJSON(w, map[string]any{"global": global, "servers": scoped}, 200)
}
func (h *AuthorizationHandler) Roles(w http.ResponseWriter, r *http.Request) {
	roles := []authorization.Role{}
	if err := h.db.Order("id").Find(&roles).Error; err != nil {
		writeErr(w, "Could not load roles.", "internal", 500)
		return
	}
	type role struct {
		authorization.Role
		Permissions []string `json:"permissions"`
	}
	result := []role{}
	for _, entry := range roles {
		permissions := []string{}
		if err := h.db.Table("role_permissions").Where("role_id=?", entry.ID).Order("permission_key").Pluck("permission_key", &permissions).Error; err != nil {
			writeErr(w, "Could not load permissions.", "internal", 500)
			return
		}
		result = append(result, role{entry, permissions})
	}
	writeJSON(w, result, 200)
}
func (h *AuthorizationHandler) Grants(w http.ResponseWriter, r *http.Request) {
	items := []authorization.Grant{}
	if err := h.db.Order("created_at").Find(&items).Error; err != nil {
		writeErr(w, "Could not load grants.", "internal", 500)
		return
	}
	writeJSON(w, items, 200)
}
func (h *AuthorizationHandler) Groups(w http.ResponseWriter, r *http.Request) {
	items := []authorization.Group{}
	if err := h.db.Order("name").Find(&items).Error; err != nil {
		writeErr(w, "Could not load groups.", "internal", 500)
		return
	}
	type group struct {
		authorization.Group
		ServerIDs []string `json:"serverIds"`
	}
	result := []group{}
	for _, item := range items {
		ids := []string{}
		if err := h.db.Table("server_group_members").Where("group_id=?", item.ID).Order("server_id").Pluck("server_id", &ids).Error; err != nil {
			writeErr(w, "Could not load members.", "internal", 500)
			return
		}
		result = append(result, group{item, ids})
	}
	writeJSON(w, result, 200)
}

type authorizationInput struct{ CurrentPassword, PrincipalID, RoleID, ScopeType, ScopeID, Name string }

func (h *AuthorizationHandler) proof(w http.ResponseWriter, r *http.Request) (authorizationInput, *auth.Access, bool) {
	var input authorizationInput
	a, _ := auth.FromContext(r.Context())
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeErr(w, "Current password is required.", "bad_request", 400)
		return input, a, false
	}
	if err := h.sessions.RequirePassword(a, input.CurrentPassword); err != nil {
		status := 403
		if errors.Is(err, auth.ErrUnauthorized) {
			status = 401
		}
		writeErr(w, "Confirm the current password and sign in again with MFA when enabled.", "step_up_required", status)
		return input, a, false
	}
	return input, a, true
}
func (h *AuthorizationHandler) failure(w http.ResponseWriter, err error) {
	if errors.Is(err, authorization.ErrDenied) {
		writeErr(w, "Access denied.", "permission_denied", 403)
	} else if errors.Is(err, authorization.ErrLastAdmin) {
		writeErr(w, err.Error(), "last_administrator", 409)
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		writeErr(w, "Resource not found.", "not_found", 404)
	} else if errors.Is(err, authorization.ErrInvalid) {
		writeErr(w, "Invalid authorization change.", "invalid_policy", 400)
	} else {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && (sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique || sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey) {
			writeErr(w, "This group or grant already exists.", "policy_conflict", 409)
		} else {
			writeErr(w, "Authorization storage unavailable.", "authorization_unavailable", 503)
		}
	}
}
func (h *AuthorizationHandler) AddGrant(w http.ResponseWriter, r *http.Request) {
	input, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	grant, err := h.policy.AddGrant(a.User.ID, input.PrincipalID, input.RoleID, input.ScopeType, input.ScopeID, w.Header().Get("X-Request-ID"))
	if err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, grant, 201)
}
func (h *AuthorizationHandler) DeleteGrant(w http.ResponseWriter, r *http.Request) {
	_, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	if err := h.policy.DeleteGrant(a.User.ID, chi.URLParam(r, "grantId"), w.Header().Get("X-Request-ID")); err != nil {
		h.failure(w, err)
		return
	}
	w.WriteHeader(204)
}
func (h *AuthorizationHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	input, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	group, err := h.policy.CreateGroup(a.User.ID, input.Name, w.Header().Get("X-Request-ID"))
	if err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, group, 201)
}
func (h *AuthorizationHandler) Membership(w http.ResponseWriter, r *http.Request) {
	_, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	if err := h.policy.Membership(a.User.ID, chi.URLParam(r, "gid"), chi.URLParam(r, "serverId"), r.Method == "DELETE", w.Header().Get("X-Request-ID")); err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AuthorizationHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	_, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	if err := h.policy.DeleteGroup(a.User.ID, chi.URLParam(r, "gid"), w.Header().Get("X-Request-ID")); err != nil {
		h.failure(w, err)
		return
	}
	w.WriteHeader(204)
}
func (h *AuthorizationHandler) Events(w http.ResponseWriter, r *http.Request) {
	items := []authorization.Event{}
	if err := h.db.Order("id desc").Limit(100).Find(&items).Error; err != nil {
		writeErr(w, "Could not load decisions.", "internal", 500)
		return
	}
	writeJSON(w, items, 200)
}
