package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	nexusMW "github.com/xmahdi1/nexus/internal/api/middleware"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/httpx"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type AuthHandler struct {
	cfg      *config.Config
	db       *gorm.DB
	sessions *auth.Service
}

func NewAuthHandler(cfg *config.Config, db *gorm.DB) *AuthHandler {
	return &AuthHandler{cfg: cfg, db: db, sessions: auth.NewService(db, cfg)}
}
func (h *AuthHandler) fail(w http.ResponseWriter, err error) {
	status, code, message := 500, "auth_unavailable", "Authentication service unavailable. Try again."
	if errors.Is(err, auth.ErrCredentials) {
		status, code, message = 401, "invalid_credentials", "Invalid credentials or expired verification challenge. Restart sign-in if needed."
	}
	if errors.Is(err, auth.ErrUnauthorized) {
		status, code, message = 401, "invalid_session", "Sign in again."
	}
	if errors.Is(err, auth.ErrStepUp) {
		status, code, message = 403, "step_up_required", err.Error()
	}
	if errors.Is(err, auth.ErrConfigWrite) || errors.Is(err, auth.ErrMFAEnabled) {
		status, code, message = 409, "configuration_conflict", err.Error()
	}
	writeErr(w, message, code, status)
}
func (h *AuthHandler) setCookie(w http.ResponseWriter, r *http.Request, token string) {
	maxAge := int(h.sessions.AbsoluteTTL.Seconds())
	expiry := time.Now().Add(h.sessions.AbsoluteTTL)
	if token == "" {
		maxAge = -1
		expiry = time.Unix(0, 0)
	}
	http.SetCookie(w, &http.Cookie{Name: auth.CookieName(), Value: token, HttpOnly: true, Secure: nexusMW.SecureRequest(r, h.cfg.TrustProxy), SameSite: http.SameSiteStrictMode, Path: "/", Expires: expiry, MaxAge: maxAge})
	// Expire the obsolete JWT cookie. It is never accepted by the new middleware.
	http.SetCookie(w, &http.Cookie{Name: "nexus_token", Value: "", HttpOnly: true, Secure: nexusMW.SecureRequest(r, h.cfg.TrustProxy), SameSite: http.SameSiteStrictMode, Path: "/", Expires: time.Unix(0, 0), MaxAge: -1})
}
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password, DeviceLabel string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request body.", "bad_request", 400)
		return
	}
	result, err := h.sessions.Login(body.Username, body.Password, body.DeviceLabel, httpx.ClientIP(r, h.cfg.TrustProxy))
	if err != nil {
		h.logEvent(r, false, "bad_password")
		h.fail(w, err)
		return
	}
	if result.MFARequired {
		h.logEvent(r, false, "mfa_required")
		writeJSON(w, map[string]any{"ok": false, "mfaRequired": true, "pendingToken": result.PendingToken}, 200)
		return
	}
	h.logEvent(r, true, "ok")
	h.setCookie(w, r, result.Token)
	writeJSON(w, map[string]any{"ok": true, "mfaRequired": false}, 200)
}
func (h *AuthHandler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	var body struct{ PendingToken, Code, DeviceLabel string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request body.", "bad_request", 400)
		return
	}
	result, err := h.sessions.VerifyMFA(body.PendingToken, body.Code, body.DeviceLabel, httpx.ClientIP(r, h.cfg.TrustProxy))
	if err != nil {
		h.logEvent(r, false, "bad_mfa")
		h.fail(w, err)
		return
	}
	h.logEvent(r, true, "ok")
	h.setCookie(w, r, result.Token)
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	writeJSON(w, map[string]any{"ok": true, "mode": a.Mode, "user": a.User, "session": a.Session}, 200)
}
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	if err := h.sessions.Revoke(a, a.Session.ID, false); err != nil {
		h.fail(w, err)
		return
	}
	h.logEvent(r, true, "logout")
	h.setCookie(w, r, "")
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	if err := h.sessions.Revoke(a, "", true); err != nil {
		h.fail(w, err)
		return
	}
	h.logEvent(r, true, "logout_all")
	h.setCookie(w, r, "")
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AuthHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	sessions, err := h.sessions.Sessions(a)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, sessions, 200)
}
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	id := chi.URLParam(r, "sid")
	if err := h.sessions.Revoke(a, id, false); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeErr(w, "Session not found.", "not_found", 404)
		} else {
			h.fail(w, err)
		}
		return
	}
	if id == a.Session.ID {
		h.setCookie(w, r, "")
	}
	h.logEvent(r, true, "session_revoked")
	w.WriteHeader(204)
}
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct{ CurrentPassword, NewPassword string }
	if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.NewPassword) < 12 || len(body.NewPassword) > 1024 {
		writeErr(w, "New password must contain 12 to 1024 bytes.", "bad_request", 400)
		return
	}
	a, _ := auth.FromContext(r.Context())
	if err := h.sessions.ChangePassword(a, body.CurrentPassword, body.NewPassword); err != nil {
		h.fail(w, err)
		return
	}
	h.logEvent(r, true, "password_changed")
	h.setCookie(w, r, "")
	writeJSON(w, map[string]bool{"ok": true, "reauthenticate": true}, 200)
}
func (h *AuthHandler) MFAStatus(w http.ResponseWriter, r *http.Request) {
	a, _ := auth.FromContext(r.Context())
	enabled, err := h.sessions.MFAEnabled(a)
	if err != nil {
		h.fail(w, err)
		return
	}
	remaining, err := h.sessions.RecoveryRemaining(a.User.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"enabled": enabled, "recoveryCodesRemaining": remaining}, 200)
}
func (h *AuthHandler) MFASetup(w http.ResponseWriter, r *http.Request) {
	var body struct{ CurrentPassword string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Current password is required.", "bad_request", 400)
		return
	}
	a, _ := auth.FromContext(r.Context())
	result, err := h.sessions.SetupMFA(a, body.CurrentPassword)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, result, 200)
}
func (h *AuthHandler) MFAEnable(w http.ResponseWriter, r *http.Request) {
	var body struct{ SetupToken, Code string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request body.", "bad_request", 400)
		return
	}
	a, _ := auth.FromContext(r.Context())
	codes, err := h.sessions.EnableMFA(a, body.SetupToken, body.Code)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.logEvent(r, true, "mfa_enabled")
	h.setCookie(w, r, "")
	writeJSON(w, map[string]any{"ok": true, "reauthenticate": true, "recoveryCodes": codes}, 200)
}
func (h *AuthHandler) MFADisable(w http.ResponseWriter, r *http.Request) {
	var body struct{ Code string }
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, "Invalid request body.", "bad_request", 400)
		return
	}
	a, _ := auth.FromContext(r.Context())
	if err := h.sessions.DisableMFA(a, body.Code); err != nil {
		h.fail(w, err)
		return
	}
	h.logEvent(r, true, "mfa_disabled")
	h.setCookie(w, r, "")
	writeJSON(w, map[string]bool{"ok": true, "reauthenticate": true}, 200)
}
func (h *AuthHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 100 {
		limit = n
	}
	events := []models.LoginEvent{}
	if err := h.db.Order("created_at desc").Limit(limit).Find(&events).Error; err != nil {
		writeErr(w, "Could not load login events.", "internal", 500)
		return
	}
	writeJSON(w, events, 200)
}
func (h *AuthHandler) logEvent(r *http.Request, success bool, reason string) {
	h.db.Create(&models.LoginEvent{IP: httpx.ClientIP(r, h.cfg.TrustProxy), Success: success, Reason: reason})
}
func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, msg, code string, status int) {
	writeJSON(w, map[string]string{"error": msg, "message": msg, "code": code, "request_id": w.Header().Get("X-Request-ID")}, status)
}
