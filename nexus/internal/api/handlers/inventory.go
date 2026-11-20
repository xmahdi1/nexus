package handlers

import (
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/inventory"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
	"net/http"
	"strconv"
)

type InventoryHandler struct {
	enabled bool
	service *inventory.Service
}

func NewInventoryHandler(db *gorm.DB, cfg *config.Config, pool *nexusssh.Pool) *InventoryHandler {
	return &InventoryHandler{cfg.InventoryEnabled, &inventory.Service{DB: db, Adapter: &inventory.SSHAdapter{DB: db, Key: cfg.EncryptionKey, Pool: pool}}}
}
func (h *InventoryHandler) Read(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		writeErr(w, "Inventory is disabled.", "feature_disabled", 404)
		return
	}
	a, _ := auth.FromContext(r.Context())
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
