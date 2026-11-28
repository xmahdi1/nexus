package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/vault"
)

func (h *VaultHandler) KVList(w http.ResponseWriter, r *http.Request)     { h.kv(w, r, "list") }
func (h *VaultHandler) KVMetadata(w http.ResponseWriter, r *http.Request) { h.kv(w, r, "metadata") }
func (h *VaultHandler) KVRead(w http.ResponseWriter, r *http.Request)     { h.kv(w, r, "read") }
func (h *VaultHandler) KVWrite(w http.ResponseWriter, r *http.Request)    { h.kv(w, r, "write") }
func (h *VaultHandler) kv(w http.ResponseWriter, r *http.Request, action string) {
	if !h.available(w, r) {
		return
	}
	var body struct {
		vault.KVRequest
		DataJSON *string `json:"dataJson,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 150000)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		writeErr(w, "Invalid Vault KV request.", "bad_request", 400)
		return
	}
	input := body.KVRequest
	if body.DataJSON != nil {
		if action != "write" || len(input.Data) != 0 {
			writeErr(w, "Use one secret JSON representation.", "bad_request", 400)
			return
		}
		input.Data = json.RawMessage(*body.DataJSON)
	}
	if err := input.Validate(action); err != nil {
		writeErr(w, err.Error(), "bad_request", 400)
		return
	}
	defer func() { input.Token = ""; body.Token = ""; body.DataJSON = nil; clear(input.Data) }()
	// Secret paths can contain sensitive names. Audit a stable identity, not the
	// request payload, path, token, or values.
	digest := sha256.Sum256([]byte(input.Mount + "/" + input.Path))
	audit.MarkResource(r.Context(), "vault_kv", hex.EncodeToString(digest[:]))
	h.remote(w, r, action == "write", func(ctx context.Context, client *http.Client, p vault.Profile, allowed func() bool) (any, error) {
		result, err := vault.KV(ctx, client, p, action, input, allowed)
		if err != nil {
			return nil, err
		}
		// JSON text preserves number spelling across the browser's JSON parser.
		// Do not decode secret numbers into JavaScript Number on either boundary.
		response := struct {
			Keys                  []string          `json:"keys,omitempty"`
			Metadata              *vault.KVMetadata `json:"metadata,omitempty"`
			DataJSON              string            `json:"dataJson,omitempty"`
			AutomaticRetryAllowed bool              `json:"automaticRetryAllowed"`
		}{Keys: result.Keys, Metadata: result.Metadata}
		if action == "read" {
			response.DataJSON = string(result.Data)
		}
		return response, nil
	})
}
