package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/vault"
)

func (h *VaultHandler) AdminOperations(w http.ResponseWriter, r *http.Request) {
	if !h.available(w, r) {
		return
	}
	access, ok := auth.FromContext(r.Context())
	if !ok || !access.AuthorizedNow() {
		writeErr(w, "Vault access revoked.", "forbidden", 403)
		return
	}
	service := authorization.New(h.db)
	operations := []vault.AdminOperation{}
	for _, op := range vault.AdminOperations() {
		if service.All(access.User.ID, chi.URLParam(r, "id"), op.Permissions...) {
			operations = append(operations, op)
		}
	}
	writeJSON(w, map[string]any{"operations": operations, "supportedEdition": "community", "namespaces": false}, 200)
}

// Admin binds an operation at route registration time. The request body cannot
// select another action, URL or upstream HTTP method.
func (h *VaultHandler) Admin(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.available(w, r) {
			return
		}
		op, ok := vault.AdminOperationByID(id)
		if !ok {
			writeErr(w, "Unknown Vault operation.", "not_found", 404)
			return
		}
		var input vault.AdminRequest
		r.Body = http.MaxBytesReader(w, r.Body, 150000)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Validate(op) != nil {
			writeErr(w, "Valid management fields, token and confirmation required.", "bad_request", 400)
			return
		}
		defer func() {
			input.Token = ""
			for key, value := range input.Params {
				clear(value)
				delete(input.Params, key)
			}
		}()
		// Only a one-way resource identity is retained, never policy source,
		// passwords, tokens, CSR contents, certificate keys or secret values.
		identity := id
		for _, key := range []string{"mount", "name", "path", "id", "canonical_id", "issuer", "prefix", "accessor", "lease_id", "serial_number"} {
			var value string
			if raw, ok := input.Params[key]; ok {
				if json.Unmarshal(raw, &value) != nil {
					writeErr(w, "Invalid resource identity.", "bad_request", 400)
					return
				}
			}
			identity += "\x00" + value
		}
		digest := sha256.Sum256([]byte(identity))
		audit.MarkResource(r.Context(), "vault_control", hex.EncodeToString(digest[:]))
		h.remote(w, r, op.Mutation, func(ctx context.Context, client *http.Client, p vault.Profile, allowed func() bool) (any, error) {
			return vault.Admin(ctx, client, p, id, input, allowed)
		})
	}
}
