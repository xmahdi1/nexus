package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/vault"
)

func (h *VaultHandler) AuthMethods(w http.ResponseWriter, r *http.Request) { h.access(w, r, "auth") }
func (h *VaultHandler) Policies(w http.ResponseWriter, r *http.Request)    { h.access(w, r, "policies") }
func (h *VaultHandler) Policy(w http.ResponseWriter, r *http.Request)      { h.access(w, r, "policy") }
func (h *VaultHandler) Capabilities(w http.ResponseWriter, r *http.Request) {
	h.access(w, r, "capabilities")
}
func (h *VaultHandler) access(w http.ResponseWriter, r *http.Request, action string) {
	if !h.available(w, r) {
		return
	}
	var input vault.AccessRequest
	r.Body = http.MaxBytesReader(w, r.Body, 45000)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || input.Validate(action) != nil {
		writeErr(w, "Valid access-inspection fields and token required.", "bad_request", 400)
		return
	}
	defer func() { input.Token = "" }()
	digest := sha256.Sum256([]byte(action + "\x00" + input.Name + "\x00" + strings.Join(input.Paths, "\x00")))
	audit.MarkResource(r.Context(), "vault_control", hex.EncodeToString(digest[:]))
	h.remote(w, r, false, func(ctx context.Context, client *http.Client, p vault.Profile, _ func() bool) (any, error) {
		return vault.Access(ctx, client, p, action, input)
	})
}
