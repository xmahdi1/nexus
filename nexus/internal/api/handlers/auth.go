package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/httpx"
	"github.com/xmahdi1/nexus/internal/models"
)

type AuthHandler struct {
	cfg *config.Config
	db  *gorm.DB
}

func NewAuthHandler(cfg *config.Config, db *gorm.DB) *AuthHandler {
	db.AutoMigrate(&models.LoginEvent{})
	return &AuthHandler{cfg: cfg, db: db}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	ip := httpx.ClientIP(r, h.cfg.TrustProxy)

	if !auth.CheckPassword(h.cfg.PasswordHash, body.Password) {
		h.logEvent(ip, false, "bad_password")
		writeErr(w, "invalid credentials", "unauthorized", http.StatusUnauthorized)
		return
	}

	if h.cfg.TOTPEnabled && h.cfg.TOTPSecret != "" {
		pending := auth.NewPendingToken()
		if pending == "" {
			writeErr(w, "could not start MFA challenge", "internal", http.StatusInternalServerError)
			return
		}
		h.logEvent(ip, false, "mfa_required")
		writeJSON(w, map[string]any{
			"ok":           false,
			"mfaRequired":  true,
			"pendingToken": pending,
		}, http.StatusOK)
		return
	}

	h.logEvent(ip, true, "ok")
	h.issueSession(w)
}

func (h *AuthHandler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PendingToken string `json:"pendingToken"`
		Code         string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	ip := httpx.ClientIP(r, h.cfg.TrustProxy)

	if !auth.ConsumePendingToken(body.PendingToken) {
		h.logEvent(ip, false, "session_expired")
		writeErr(w, "session expired — please log in again", "session_expired", http.StatusUnauthorized)
		return
	}
	if !totp.Validate(body.Code, h.cfg.TOTPSecret) {
		h.logEvent(ip, false, "bad_mfa")
		writeErr(w, "invalid code", "invalid_code", http.StatusUnauthorized)
		return
	}

	h.logEvent(ip, true, "ok")
	h.issueSession(w)
}

func (h *AuthHandler) MFASetup(w http.ResponseWriter, r *http.Request) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Nexus", AccountName: "admin"})
	if err != nil {
		writeErr(w, "failed to generate secret", "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"secret": key.Secret(), "uri": key.URL()}, http.StatusOK)
}

func (h *AuthHandler) MFAEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	if body.Secret == "" || body.Code == "" {
		writeErr(w, "secret and code are required", "bad_request", http.StatusBadRequest)
		return
	}
	if !totp.Validate(body.Code, body.Secret) {
		writeErr(w, "invalid code", "invalid_code", http.StatusUnauthorized)
		return
	}
	if err := h.cfg.UpdateTOTP(body.Secret, true); err != nil {
		writeErr(w, "failed to save MFA config: "+err.Error(), "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *AuthHandler) MFADisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	if !h.cfg.TOTPEnabled || h.cfg.TOTPSecret == "" {
		writeErr(w, "MFA is not enabled", "not_enabled", http.StatusBadRequest)
		return
	}
	if !totp.Validate(body.Code, h.cfg.TOTPSecret) {
		writeErr(w, "invalid code", "invalid_code", http.StatusUnauthorized)
		return
	}
	if err := h.cfg.UpdateTOTP("", false); err != nil {
		writeErr(w, "failed to disable MFA: "+err.Error(), "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *AuthHandler) MFAStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"enabled": h.cfg.TOTPEnabled}, http.StatusOK)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	if body.CurrentPassword == "" || body.NewPassword == "" {
		writeErr(w, "currentPassword and newPassword are required", "bad_request", http.StatusBadRequest)
		return
	}
	if len(body.NewPassword) < 8 {
		writeErr(w, "password must be at least 8 characters", "bad_request", http.StatusBadRequest)
		return
	}
	if !auth.CheckPassword(h.cfg.PasswordHash, body.CurrentPassword) {
		writeErr(w, "current password is incorrect", "unauthorized", http.StatusUnauthorized)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), 12)
	if err != nil {
		writeErr(w, "failed to hash password", "internal", http.StatusInternalServerError)
		return
	}
	if err := h.cfg.UpdatePasswordHash(string(hash)); err != nil {
		writeErr(w, "failed to update config: "+err.Error(), "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *AuthHandler) AuditLog(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	var events []models.LoginEvent
	h.db.Order("created_at desc").Limit(limit).Find(&events)
	if events == nil {
		events = []models.LoginEvent{}
	}
	writeJSON(w, events, http.StatusOK)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName(),
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *AuthHandler) issueSession(w http.ResponseWriter) {
	token, err := auth.GenerateToken(h.cfg.EncryptionKey)
	if err != nil {
		writeErr(w, "could not issue token", "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName(),
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(auth.TokenTTL()),
	})
	writeJSON(w, map[string]any{"ok": true, "mfaRequired": false}, http.StatusOK)
}

func (h *AuthHandler) logEvent(ip string, success bool, reason string) {
	h.db.Create(&models.LoginEvent{IP: ip, Success: success, Reason: reason})
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg, code string, status int) {
	writeJSON(w, map[string]string{"error": msg, "code": code}, status)
}
