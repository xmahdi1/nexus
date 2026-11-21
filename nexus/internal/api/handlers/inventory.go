package handlers

import (
	"errors"
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
	return &InventoryHandler{cfg.InventoryEnabled, &inventory.Service{DB: db, Adapter: &inventory.SSHAdapter{DB: db, Key: cfg.EncryptionKey, Pool: pool}}}
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
