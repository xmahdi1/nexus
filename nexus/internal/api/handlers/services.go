package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/xmahdi1/nexus/internal/audit"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type ServicesHandler struct {
	db *gorm.DB
}

func NewServicesHandler(db *gorm.DB) *ServicesHandler {
	return &ServicesHandler{db: db}
}

func (h *ServicesHandler) List(w http.ResponseWriter, r *http.Request) {
	var services []models.Service
	h.db.Order("sort_order asc, created_at asc").Find(&services)
	if services == nil {
		services = []models.Service{}
	}
	writeJSON(w, services, http.StatusOK)
}

func (h *ServicesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Icon        string `json:"icon"`
		Description string `json:"description"`
		Category    string `json:"category"`
		Color       string `json:"color"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.URL == "" {
		writeErr(w, "name and url are required", "bad_request", http.StatusBadRequest)
		return
	}

	id := make([]byte, 8)
	rand.Read(id)
	svc := models.Service{
		ID:          hex.EncodeToString(id),
		Name:        body.Name,
		URL:         body.URL,
		Icon:        body.Icon,
		Description: body.Description,
		Category:    body.Category,
		Color:       body.Color,
		CreatedAt:   time.Now(),
	}
	if err := h.db.Create(&svc).Error; err != nil {
		writeErr(w, err.Error(), "internal", http.StatusInternalServerError)
		return
	}
	audit.MarkResource(r.Context(), "service", svc.ID)
	writeJSON(w, svc, http.StatusCreated)
}

func (h *ServicesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var svc models.Service
	if err := h.db.First(&svc, "id = ?", id).Error; err != nil {
		writeErr(w, "not found", "not_found", http.StatusNotFound)
		return
	}
	var body struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Icon        string `json:"icon"`
		Description string `json:"description"`
		Category    string `json:"category"`
		Color       string `json:"color"`
		SortOrder   int    `json:"sortOrder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid body", "bad_request", http.StatusBadRequest)
		return
	}
	if err := h.db.Model(&svc).Updates(map[string]any{
		"name":        body.Name,
		"url":         body.URL,
		"icon":        body.Icon,
		"description": body.Description,
		"category":    body.Category,
		"color":       body.Color,
		"sort_order":  body.SortOrder,
	}).Error; err != nil {
		writeErr(w, "Could not update service.", "storage_unavailable", 503)
		return
	}
	h.db.First(&svc, "id = ?", id)
	writeJSON(w, svc, http.StatusOK)
}

func (h *ServicesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.db.Delete(&models.Service{}, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		writeErr(w, "Could not delete service.", "storage_unavailable", 503)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
