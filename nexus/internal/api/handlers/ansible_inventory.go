package handlers

import (
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/automation"
)

type AnsibleInventoryHandler struct {
	Service *automation.InventoryService
	Enabled bool
}

func (h *AnsibleInventoryHandler) Groups(w http.ResponseWriter, r *http.Request) {
	a, ok := h.access(w, r)
	if !ok {
		return
	}
	rows, err := h.Service.Groups(a)
	if err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, rows, 200)
}
func (h *AnsibleInventoryHandler) access(w http.ResponseWriter, r *http.Request) (*auth.Access, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.Enabled {
		writeErr(w, "Automation is disabled.", "feature_disabled", 404)
		return nil, false
	}
	a, ok := auth.FromContext(r.Context())
	if !ok || !a.AuthorizedNow() {
		writeErr(w, "Automation access unavailable.", "forbidden", 403)
		return nil, false
	}
	return a, true
}
func (h *AnsibleInventoryHandler) Preview(w http.ResponseWriter, r *http.Request) {
	a, ok := h.access(w, r)
	if !ok {
		return
	}
	result, err := h.Service.Build(a, r.URL.Query().Get("groupId"))
	if err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, result, 200)
}
func (h *AnsibleInventoryHandler) Inventory(w http.ResponseWriter, r *http.Request) {
	a, ok := h.access(w, r)
	if !ok {
		return
	}
	group, ok := automation.InventoryGroup(r.Context())
	if !ok {
		writeErr(w, "An inventory credential is required.", "forbidden", 403)
		return
	}
	// Group selection is bound to the credential. Query parameters cannot expand it.
	if len(r.URL.Query()) != 0 {
		writeErr(w, "Inventory parameters are not accepted.", "bad_request", 400)
		return
	}
	result, err := h.Service.Build(a, group)
	if err != nil {
		h.failure(w, err)
		return
	}
	if err := authorization.New(h.Service.DB).Record(a.User.ID, "ansible.inventory.read", group, "allowed", w.Header().Get("X-Request-ID"), a.Session.ID); err != nil {
		h.failure(w, err)
		return
	}
	if !a.AuthorizedNow() {
		h.failure(w, automation.ErrDenied)
		return
	}
	writeJSON(w, result.Inventory, 200)
}
func (h *AnsibleInventoryHandler) Issue(w http.ResponseWriter, r *http.Request) {
	a, ok := h.access(w, r)
	if !ok {
		return
	}
	var body struct {
		GroupID    string `json:"groupId"`
		TTLSeconds int    `json:"ttlSeconds"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		writeErr(w, "Invalid inventory credential request.", "bad_request", 400)
		return
	}
	if body.TTLSeconds < 60 || body.TTLSeconds > 900 {
		writeErr(w, "Lifetime must be 60–900 seconds.", "bad_request", 400)
		return
	}
	row, token, err := h.Service.Issue(a, body.GroupID, time.Duration(body.TTLSeconds)*time.Second)
	if err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, struct {
		automation.InventoryToken
		Token string `json:"token"`
	}{row, token}, 201)
}
func (h *AnsibleInventoryHandler) List(w http.ResponseWriter, r *http.Request) {
	a, ok := h.access(w, r)
	if !ok {
		return
	}
	rows := []automation.InventoryToken{}
	if err := h.Service.DB.Where("actor_id=? AND expires_at>?", a.User.ID, time.Now().UTC()).Order("created_at DESC").Limit(32).Find(&rows).Error; err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, rows, 200)
}
func (h *AnsibleInventoryHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	a, ok := h.access(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "tokenId")
	err := h.Service.DB.Transaction(func(tx *gorm.DB) error {
		if err := authorization.New(tx).Record(a.User.ID, "ansible.inventory.token.revoke", id, "revoked", w.Header().Get("X-Request-ID"), a.Session.ID); err != nil {
			return err
		}
		return tx.Where("actor_id=? AND id=?", a.User.ID, id).Delete(&automation.InventoryToken{}).Error
	})
	if err != nil {
		h.failure(w, err)
		return
	}
	w.WriteHeader(204)
}
func (h *AnsibleInventoryHandler) failure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, automation.ErrDenied):
		writeErr(w, "No authorized automation targets or credential expired.", "forbidden", 403)
	case errors.Is(err, automation.ErrInventory):
		writeErr(w, "Fix invalid server address, user, port or group/tag metadata before exporting inventory.", "invalid_inventory", 422)
	default:
		writeErr(w, "Automation inventory unavailable.", "unavailable", 503)
	}
}
