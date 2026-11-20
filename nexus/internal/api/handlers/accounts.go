package handlers

import (
	"encoding/json"
	"errors"
	"github.com/xmahdi1/nexus/internal/audit"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/httpx"
	"gorm.io/gorm"
)

type AccountHandler struct {
	db           *gorm.DB
	service      *auth.Service
	proofHandler *AuthorizationHandler
	authHandler  *AuthHandler
}

func NewAccountHandler(db *gorm.DB, cfg *config.Config) *AccountHandler {
	return &AccountHandler{db, auth.NewService(db, cfg), NewAuthorizationHandler(db, cfg), NewAuthHandler(cfg, db)}
}
func (h *AccountHandler) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrActivationRequired) {
		writeErr(w, err.Error(), "owner_activation_required", 409)
	} else if errors.Is(err, auth.ErrCredentials) || errors.Is(err, auth.ErrUnauthorized) || errors.Is(err, auth.ErrStepUp) {
		h.authHandler.fail(w, err)
	} else {
		h.proofHandler.failure(w, err)
	}
}

type accountInput struct {
	CurrentPassword, Username, DisplayName, Email, RoleID, ScopeType, ScopeID, Status, Kind, Reason string
	ExpiresHours                                                                                    int
}

func (h *AccountHandler) proof(w http.ResponseWriter, r *http.Request) (accountInput, *auth.Access, bool) {
	var input accountInput
	a, _ := auth.FromContext(r.Context())
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeErr(w, "Valid request and current password required.", "bad_request", 400)
		return input, a, false
	}
	if err := h.service.RequirePassword(a, input.CurrentPassword); err != nil {
		if errors.Is(err, auth.ErrCredentials) || errors.Is(err, auth.ErrStepUp) {
			writeErr(w, "Confirm the current password and recent MFA.", "step_up_required", 403)
			return input, a, false
		}
		h.fail(w, err)
		return input, a, false
	}
	return input, a, true
}
func (h *AccountHandler) Users(w http.ResponseWriter, r *http.Request) {
	type user struct {
		ID               string     `json:"id"`
		Username         string     `json:"username"`
		DisplayName      string     `json:"displayName"`
		Email            *string    `json:"email"`
		Status           string     `json:"status"`
		CreatedAt        time.Time  `json:"createdAt"`
		LastLoginAt      *time.Time `json:"lastLoginAt"`
		MFAEnabled       bool       `json:"mfaEnabled"`
		RecoveryRequired bool       `json:"recoveryRequired"`
		Admitted         bool       `json:"admitted"`
	}
	users := []user{}
	if err := h.db.Table("users u").Select("u.id,u.username,u.display_name,u.email,u.status,u.created_at,u.last_login_at,COALESCE(c.totp_enabled,0) AS mfa_enabled,COALESCE(c.recovery_required,0) AS recovery_required,EXISTS(SELECT 1 FROM account_admissions a WHERE a.user_id=u.id) AS admitted").Joins("LEFT JOIN auth_credentials c ON c.user_id=u.id").Order("u.username").Limit(1000).Scan(&users).Error; err != nil {
		writeErr(w, "Could not load accounts.", "internal", 500)
		return
	}
	writeJSON(w, users, 200)
}
func (h *AccountHandler) Invitations(w http.ResponseWriter, r *http.Request) {
	rows := []auth.Invitation{}
	if err := h.db.Order("created_at desc").Limit(100).Find(&rows).Error; err != nil {
		writeErr(w, "Could not load invitations.", "internal", 500)
		return
	}
	writeJSON(w, rows, 200)
}
func (h *AccountHandler) Invite(w http.ResponseWriter, r *http.Request) {
	input, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	result, err := h.service.CreateInvitation(a, auth.InviteOptions{Username: input.Username, DisplayName: input.DisplayName, Email: input.Email, RoleID: input.RoleID, ScopeType: input.ScopeType, ScopeID: input.ScopeID, ExpiresHours: input.ExpiresHours}, w.Header().Get("X-Request-ID"))
	if err != nil {
		h.fail(w, err)
		return
	}
	audit.MarkResource(r.Context(), "invitation", result.Invitation.ID)
	writeJSON(w, result, 201)
}
func (h *AccountHandler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	_, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	if err := h.service.RevokeInvitation(a, chi.URLParam(r, "inviteId"), w.Header().Get("X-Request-ID")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(204)
}
func (h *AccountHandler) Status(w http.ResponseWriter, r *http.Request) {
	input, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	if err := h.service.ChangeStatus(a, chi.URLParam(r, "uid"), input.Status, w.Header().Get("X-Request-ID")); err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AccountHandler) Reset(w http.ResponseWriter, r *http.Request) {
	input, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	result, err := h.service.IssueReset(a, chi.URLParam(r, "uid"), input.Kind, input.Reason, w.Header().Get("X-Request-ID"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, result, 201)
}
func (h *AccountHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	_, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	if err := h.service.Unlock(a, chi.URLParam(r, "uid"), w.Header().Get("X-Request-ID")); err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AccountHandler) Accept(w http.ResponseWriter, r *http.Request) {
	var body struct{ Token, Password string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid invitation request.", "bad_request", 400)
		return
	}
	username, err := h.service.AcceptInvitation(body.Token, body.Password)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "username": username}, 200)
}
func (h *AccountHandler) RecoveryLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ PendingToken, Code, DeviceLabel string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request.", "bad_request", 400)
		return
	}
	result, err := h.service.VerifyRecovery(body.PendingToken, body.Code, body.DeviceLabel, httpx.ClientIP(r, h.authHandler.cfg.TrustProxy))
	if err != nil {
		h.fail(w, err)
		return
	}
	h.authHandler.setCookie(w, r, result.Token)
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AccountHandler) Regenerate(w http.ResponseWriter, r *http.Request) {
	input, a, ok := h.proof(w, r)
	if !ok {
		return
	}
	codes, err := h.service.RegenerateRecovery(a, input.CurrentPassword)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.authHandler.setCookie(w, r, "")
	writeJSON(w, map[string]any{"ok": true, "recoveryCodes": codes, "reauthenticate": true}, 200)
}
func (h *AccountHandler) ResetInfo(w http.ResponseWriter, r *http.Request) {
	var body struct{ Token string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request.", "bad_request", 400)
		return
	}
	result, err := h.service.ResetInfo(body.Token)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, result, 200)
}
func (h *AccountHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct{ Token, Password, Code string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request.", "bad_request", 400)
		return
	}
	codes, err := h.service.CompletePasswordReset(body.Token, body.Password, body.Code)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "recoveryCodes": codes}, 200)
}
func (h *AccountHandler) ResetMFASetup(w http.ResponseWriter, r *http.Request) {
	var body struct{ Token, Password string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request.", "bad_request", 400)
		return
	}
	result, err := h.service.BeginMFAReset(body.Token, body.Password)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, result, 200)
}
func (h *AccountHandler) ResetMFAConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct{ SetupToken, Code string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request.", "bad_request", 400)
		return
	}
	codes, err := h.service.ConfirmMFAReset(body.SetupToken, body.Code)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "recoveryCodes": codes}, 200)
}
