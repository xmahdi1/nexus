package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/inventory"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type InventoryHandler struct {
	enabled bool
	service *inventory.Service
}

func (h *InventoryHandler) Relationships(w http.ResponseWriter, r *http.Request) { h.page(w, r, false) }
func (h *InventoryHandler) History(w http.ResponseWriter, r *http.Request)       { h.page(w, r, true) }
func (h *InventoryHandler) page(w http.ResponseWriter, r *http.Request, history bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.enabled {
		writeErr(w, "Inventory is disabled.", "feature_disabled", 404)
		return
	}
	access, ok := auth.FromContext(r.Context())
	if !ok || !access.AuthorizedNow() {
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeErr(w, "Invalid inventory page.", "bad_request", 400)
			return
		}
		limit = parsed
	}
	var result any
	var err error
	server := chi.URLParam(r, "id")
	if history {
		result, err = h.service.History(access.User.ID, server, r.URL.Query().Get("resourceId"), r.URL.Query().Get("before"), limit)
	} else {
		result, err = h.service.Relationships(access.User.ID, server, r.URL.Query().Get("after"), limit)
	}
	if errors.Is(err, inventory.ErrPage) {
		writeErr(w, "Invalid inventory page.", "bad_request", 400)
		return
	}
	if errors.Is(err, authorization.ErrDenied) || !access.AuthorizedNow() {
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
		return
	}
	if err != nil {
		writeErr(w, "Inventory unavailable.", "inventory_unavailable", 503)
		return
	}
	writeJSON(w, result, 200)
}

func NewInventoryHandler(db *gorm.DB, cfg *config.Config, pool *nexusssh.Pool) *InventoryHandler {
	return &InventoryHandler{
		enabled: cfg.InventoryEnabled,
		service: &inventory.Service{
			DB: db, Sessions: auth.NewService(db, cfg),
			Adapter: &inventory.SSHAdapter{DB: db, Key: cfg.EncryptionKey, Pool: pool},
		},
	}
}
func (h *InventoryHandler) Policy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.enabled {
		writeErr(w, "Inventory is disabled.", "feature_disabled", 404)
		return
	}
	access, ok := auth.FromContext(r.Context())
	if !ok || !access.AuthorizedNow() {
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
		return
	}
	server := chi.URLParam(r, "id")
	var result inventory.Policy
	var err error
	if r.Method == http.MethodPut {
		var input inventory.PolicyInput
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			writeErr(w, "Invalid collection policy.", "bad_request", 400)
			return
		}
		result, err = h.service.SavePolicy(r.Context(), access, server, input)
	} else {
		result, err = h.service.Policy(access.User.ID, server)
	}
	switch {
	case errors.Is(err, authorization.ErrDenied) || !access.AuthorizedNow():
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
	case errors.Is(err, inventory.ErrPolicyInput):
		writeErr(w, "Use intervals of 5–1440 minutes, freshness of 5–10080 minutes, and retention of 0–3650 days.", "bad_request", 400)
	case errors.Is(err, inventory.ErrPolicyConflict):
		writeErr(w, "Collection settings changed. Reload before saving.", "inventory_policy_conflict", 409)
	case errors.Is(err, inventory.ErrPolicyProtected):
		writeErr(w, "Protected hosts require interactive collection. Disable the schedule to save these settings.", "inventory_policy_protected", 422)
	case err != nil:
		writeErr(w, "Collection settings unavailable.", "inventory_unavailable", 503)
	default:
		writeJSON(w, result, 200)
	}
}
func (h *InventoryHandler) Documentation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.enabled {
		writeErr(w, "Inventory is disabled.", "feature_disabled", 404)
		return
	}
	access, ok := auth.FromContext(r.Context())
	if !ok || !access.AuthorizedNow() {
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
		return
	}
	server := chi.URLParam(r, "id")
	var result any
	var err error
	if r.Method == http.MethodPut {
		var input struct {
			Notes    *string `json:"notes"`
			Revision *int    `json:"revision"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 6*inventory.MaxNoteBytes+1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Notes == nil || input.Revision == nil {
			writeErr(w, "Provide notes and their current revision.", "bad_request", 400)
			return
		}
		result, err = h.service.SaveDocumentNotes(r.Context(), access, server, *input.Notes, *input.Revision)
	} else {
		result, err = h.service.Document(r.Context(), access.User.ID, server)
	}
	switch {
	case errors.Is(err, authorization.ErrDenied) || !access.AuthorizedNow():
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
	case errors.Is(err, inventory.ErrDocumentInput):
		writeErr(w, "Notes must be valid text and at most 32 KiB.", "bad_request", 400)
	case errors.Is(err, inventory.ErrDocumentConflict):
		writeErr(w, "The saved notes changed. Load the latest revision before saving.", "inventory_document_conflict", 409)
	case err != nil:
		writeErr(w, "Infrastructure documentation unavailable.", "inventory_unavailable", 503)
	default:
		writeJSON(w, result, 200)
	}
}
func (h *InventoryHandler) Read(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.enabled {
		writeErr(w, "Inventory is disabled.", "feature_disabled", 404)
		return
	}
	a, ok := auth.FromContext(r.Context())
	if !ok || !a.AuthorizedNow() {
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
		return
	}
	limit := 100
	var parseErr error
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, parseErr = strconv.Atoi(value)
	}
	if parseErr != nil || limit < 1 || limit > 200 || len(r.URL.Query().Get("after")) > 64 {
		writeErr(w, "Invalid inventory page.", "bad_request", 400)
		return
	}
	snapshot, err := h.service.ReadPage(a.User.ID, chi.URLParam(r, "id"), r.URL.Query().Get("after"), limit)
	if errors.Is(err, inventory.ErrPage) {
		writeErr(w, "Invalid inventory page.", "bad_request", 400)
		return
	}
	if errors.Is(err, authorization.ErrDenied) || !a.AuthorizedNow() {
		writeErr(w, "Inventory access revoked.", "forbidden", 403)
		return
	}
	if err != nil {
		writeErr(w, "Inventory unavailable.", "inventory_unavailable", 503)
		return
	}
	writeJSON(w, snapshot, 200)
}
func (h *InventoryHandler) Discover(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		writeErr(w, "Inventory is disabled.", "feature_disabled", 404)
		return
	}
	a, _ := auth.FromContext(r.Context())
	run, err := h.service.Discover(r.Context(), a.User.ID, chi.URLParam(r, "id"))
	if run.ID != "" {
		audit.MarkResource(r.Context(), "discovery_run", run.ID)
	}
	if err != nil {
		status := 503
		if errors.Is(err, inventory.ErrBusy) {
			status = 409
		}
		writeErr(w, "Discovery unavailable or no longer authorized.", "discovery_unavailable", status)
		return
	}
	if run.Status != "succeeded" {
		audit.MarkFailed(r.Context())
	}
	writeJSON(w, run, 200)
}
