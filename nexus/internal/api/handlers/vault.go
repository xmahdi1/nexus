package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/xmahdi1/nexus/internal/audit"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/vault"
	"gorm.io/gorm"
)

type VaultHandler struct {
	db      *gorm.DB
	key     []byte
	pool    *nexusssh.Pool
	enabled bool
}

func NewVaultHandler(db *gorm.DB, key []byte, pool *nexusssh.Pool, enabled bool) *VaultHandler {
	return &VaultHandler{db, key, pool, enabled}
}
func (h *VaultHandler) available(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !h.enabled {
		writeErr(w, "Vault integration is disabled.", "feature_disabled", 409)
		return false
	}
	var count int64
	if h.db.Model(&models.Server{}).Where("id=?", chi.URLParam(r, "id")).Count(&count).Error != nil || count != 1 {
		writeErr(w, "Server not found.", "not_found", 404)
		return false
	}
	return true
}
func (h *VaultHandler) Read(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	var p vault.Profile
	err := h.db.First(&p, "server_id=?", chi.URLParam(r, "id")).Error
	if err == gorm.ErrRecordNotFound {
		writeJSON(w, map[string]any{"configured": false}, 200)
		return
	}
	if err != nil {
		writeErr(w, "Could not read Vault connection.", "internal", 500)
		return
	}
	writeJSON(w, map[string]any{"configured": true, "profile": p}, 200)
}
func (h *VaultHandler) Save(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	var p vault.Profile
	r.Body = http.MaxBytesReader(w, r.Body, 70000)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || p.Validate() != nil {
		writeErr(w, "Valid port, TLS server name and CA certificate required.", "bad_request", 400)
		return
	}
	if p.Namespace != "" {
		writeErr(w, "Namespace management is not supported in this slice.", "unsupported_capability", 400)
		return
	}
	p.ServerID = chi.URLParam(r, "id")
	if h.db.Save(&p).Error != nil {
		writeErr(w, "Could not save Vault connection.", "internal", 500)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *VaultHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	if h.db.Where("server_id=?", chi.URLParam(r, "id")).Delete(&vault.Profile{}).Error != nil {
		writeErr(w, "Could not remove Vault connection.", "internal", 500)
		return
	}
	w.WriteHeader(204)
}
func (h *VaultHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10000)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		writeErr(w, "Invalid Vault inspection request.", "bad_request", 400)
		return
	}
	defer func() { body.Token = "" }()
	h.remote(w, r, false, func(ctx context.Context, client *http.Client, p vault.Profile, _ func() bool) (any, error) {
		return vault.Inspect(ctx, client, p, body.Token)
	})
}

func (h *VaultHandler) remote(w http.ResponseWriter, r *http.Request, mutation bool, call func(context.Context, *http.Client, vault.Profile, func() bool) (any, error)) {
	var p vault.Profile
	if h.db.First(&p, "server_id=?", chi.URLParam(r, "id")).Error != nil {
		writeErr(w, "Configure Vault first.", "not_found", 404)
		return
	}
	if p.Namespace != "" {
		writeErr(w, "Namespace management is unavailable.", "unsupported_capability", 400)
		return
	}
	var server models.Server
	if h.db.First(&server, "id=?", p.ServerID).Error != nil || h.pool == nil {
		writeErr(w, "Vault transport unavailable.", "transport_unavailable", 502)
		return
	}
	key, err := nexuscrypto.Decrypt(h.key, server.PrivateKeyEnc)
	if err != nil {
		writeErr(w, "Vault transport unavailable.", "transport_unavailable", 502)
		return
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	stopWatching := auth.WatchAccess(r, cancel)
	defer stopWatching()
	ssh, err := h.pool.GetContext(ctx, nexusssh.ServerConfig{ID: server.ID, Host: server.Host, Port: server.Port, User: server.Username, PrivKey: key})
	access, _ := auth.FromContext(r.Context())
	if access == nil || access.CheckAuthorization == nil || !access.AuthorizedNow() || ctx.Err() != nil {
		writeErr(w, "Vault access revoked.", "forbidden", 403)
		return
	}
	if err != nil {
		writeErr(w, "Vault transport unavailable.", "transport_unavailable", 502)
		return
	}
	client, err := vault.NewClient(p, ssh.DialContext)
	if err != nil {
		writeErr(w, "Invalid Vault connection settings.", "bad_request", 400)
		return
	}
	defer client.CloseIdleConnections()
	allowed := func() bool {
		return access != nil && access.CheckAuthorization != nil && access.AuthorizedNow() && ctx.Err() == nil
	}
	result, err := call(ctx, client, p, allowed)
	if errors.Is(err, vault.ErrRemoteUnknown) {
		audit.MarkRemoteUnknown(r.Context())
	}
	if !allowed() {
		if mutation {
			audit.MarkRemoteUnknown(r.Context())
			writeErr(w, "Access changed during a Vault write. Inspect remote state before retrying.", "remote_unknown", 502)
		} else {
			writeErr(w, "Vault access revoked.", "forbidden", 403)
		}
		return
	}
	if err != nil {
		status, code := 502, "vault_unavailable"
		switch {
		case errors.Is(err, vault.ErrDenied):
			status, code = 403, "vault_denied"
		case errors.Is(err, vault.ErrInvalidAdmin):
			status, code = 400, "bad_request"
		case errors.Is(err, vault.ErrNotFound):
			status, code = 404, "vault_not_found"
		case errors.Is(err, vault.ErrConflict):
			status, code = 409, "vault_conflict"
		case errors.Is(err, vault.ErrRemoteUnknown):
			code = "remote_unknown"
		}
		writeErr(w, err.Error(), code, status)
		return
	}
	writeJSON(w, result, 200)
}
