package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/monitor"
	"gorm.io/gorm"
)

type MonitorHandler struct {
	db  *gorm.DB
	mon *monitor.Monitor
}

func NewMonitorHandler(db *gorm.DB, mon *monitor.Monitor) *MonitorHandler {
	return &MonitorHandler{db: db, mon: mon}
}

func (h *MonitorHandler) Status(w http.ResponseWriter, r *http.Request) {
	var ids []string
	if err := authorization.ScopedServers(r, h.db, "metrics.read").Pluck("servers.id", &ids).Error; err != nil {
		writeErr(w, "Could not load scoped status.", "internal", 500)
		return
	}
	visible := map[string]bool{}
	for _, id := range ids {
		visible[id] = true
	}
	statuses := []monitor.ServerStatus{}
	if h.mon != nil {
		for _, status := range h.mon.GetStatuses() {
			if visible[status.ServerID] {
				statuses = append(statuses, status)
			}
		}
	}
	if statuses == nil {
		statuses = []monitor.ServerStatus{}
	}
	writeJSON(w, statuses, http.StatusOK)
}

func (h *MonitorHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg models.AlertConfig
	if err := h.db.First(&cfg, "id = ?", "default").Error; err != nil {
		writeErr(w, "config not found", "not_found", http.StatusNotFound)
		return
	}
	if cfg.TelegramToken != "" {
		cfg.TelegramToken = "••••" + cfg.TelegramToken[max(0, len(cfg.TelegramToken)-4):]
	}
	writeJSON(w, cfg, http.StatusOK)
}

func (h *MonitorHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TelegramEnabled  *bool  `json:"telegramEnabled"`
		TelegramToken    string `json:"telegramToken"`
		TelegramChatID   string `json:"telegramChatId"`
		NotifyServerDown *bool  `json:"notifyServerDown"`
		NotifyServerUp   *bool  `json:"notifyServerUp"`
		NotifyContainer  *bool  `json:"notifyContainer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid body", "bad_request", http.StatusBadRequest)
		return
	}

	var cfg models.AlertConfig
	h.db.FirstOrCreate(&cfg, models.AlertConfig{ID: "default"})

	updates := map[string]any{}
	if body.TelegramEnabled != nil {
		updates["telegram_enabled"] = *body.TelegramEnabled
	}
	if body.TelegramToken != "" && body.TelegramToken != "••••"+body.TelegramToken[max(0, len(body.TelegramToken)-4):] {
		updates["telegram_token"] = body.TelegramToken
	}
	if body.TelegramChatID != "" {
		updates["telegram_chat_id"] = body.TelegramChatID
	}
	if body.NotifyServerDown != nil {
		updates["notify_server_down"] = *body.NotifyServerDown
	}
	if body.NotifyServerUp != nil {
		updates["notify_server_up"] = *body.NotifyServerUp
	}
	if body.NotifyContainer != nil {
		updates["notify_container"] = *body.NotifyContainer
	}

	if err := h.db.Model(&cfg).Updates(updates).Error; err != nil {
		writeErr(w, "Could not save monitor configuration.", "storage_unavailable", 503)
		return
	}
	if h.mon != nil {
		h.mon.ReloadBot()
	}

	h.db.First(&cfg, "id = ?", "default")
	if cfg.TelegramToken != "" {
		cfg.TelegramToken = "••••" + cfg.TelegramToken[max(0, len(cfg.TelegramToken)-4):]
	}
	writeJSON(w, cfg, http.StatusOK)
}

func (h *MonitorHandler) TestTelegram(w http.ResponseWriter, r *http.Request) {
	var cfg models.AlertConfig
	if err := h.db.First(&cfg, "id = ?", "default").Error; err != nil {
		writeErr(w, "config not found", "not_found", http.StatusNotFound)
		return
	}
	if !cfg.TelegramEnabled || cfg.TelegramToken == "" || cfg.TelegramChatID == "" {
		writeErr(w, "Telegram not configured", "not_configured", http.StatusBadRequest)
		return
	}
	bot := monitor.NewBot(cfg.TelegramToken, cfg.TelegramChatID)
	if err := bot.Test(); err != nil {
		writeErr(w, err.Error(), "telegram_error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"ok": "message sent"}, http.StatusOK)
}

func (h *MonitorHandler) ListMonitored(w http.ResponseWriter, r *http.Request) {
	var list []models.MonitoredContainer
	h.db.Where("server_id = ?", chi.URLParam(r, "id")).Find(&list)
	if list == nil {
		list = []models.MonitoredContainer{}
	}
	writeJSON(w, list, http.StatusOK)
}

func (h *MonitorHandler) AddMonitored(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var body struct {
		ContainerID string `json:"containerId"`
		Name        string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !containerIDRe.MatchString(body.ContainerID) {
		writeErr(w, "containerId required", "bad_request", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		body.Name = body.ContainerID
	}
	var existing models.MonitoredContainer
	if h.db.First(&existing, "server_id = ? AND name = ?", serverID, body.Name).Error == nil {
		if err := h.db.Model(&existing).Update("container_id", body.ContainerID).Error; err != nil {
			writeErr(w, "Could not update monitored container.", "storage_unavailable", 503)
			return
		}
		existing.ContainerID = body.ContainerID
		if h.mon != nil {
			go h.mon.SeedContainer(serverID, body.ContainerID, body.Name)
		}
		writeJSON(w, existing, http.StatusOK)
		return
	}

	id := make([]byte, 8)
	rand.Read(id)
	mc := models.MonitoredContainer{
		ID:          hex.EncodeToString(id),
		ServerID:    serverID,
		ContainerID: body.ContainerID,
		Name:        body.Name,
	}
	if err := h.db.Create(&mc).Error; err != nil {
		writeErr(w, "Could not save monitored container.", "storage_unavailable", 503)
		return
	}

	if h.mon != nil {
		go h.mon.SeedContainer(serverID, body.ContainerID, body.Name)
	}

	writeJSON(w, mc, http.StatusCreated)
}

func (h *MonitorHandler) RemoveMonitored(w http.ResponseWriter, r *http.Request) {
	if err := h.db.Delete(&models.MonitoredContainer{},
		"server_id = ? AND name = ?", chi.URLParam(r, "id"), chi.URLParam(r, "containerId")).Error; err != nil {
		writeErr(w, "Could not remove monitored container.", "storage_unavailable", 503)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *MonitorHandler) GetServerAlerts(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var cfg models.ServerAlertConfig
	if h.db.First(&cfg, "id = ?", serverID).Error != nil {
		cfg = models.ServerAlertConfig{
			ID:            serverID,
			CPUThreshold:  90,
			RAMThreshold:  90,
			DiskThreshold: 85,
			SSLDaysBefore: 14,
		}
	}
	writeJSON(w, cfg, http.StatusOK)
}

func (h *MonitorHandler) UpdateServerAlerts(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var body models.ServerAlertConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid body", "bad_request", http.StatusBadRequest)
		return
	}
	body.ID = serverID
	body.UpdatedAt = time.Now()

	var existing models.ServerAlertConfig
	if h.db.First(&existing, "id = ?", serverID).Error != nil {
		if err := h.db.Create(&body).Error; err != nil {
			writeErr(w, "Could not save server alert configuration.", "storage_unavailable", 503)
			return
		}
	} else {
		if err := h.db.Model(&existing).Updates(map[string]any{
			"cpu_enabled":     body.CPUEnabled,
			"cpu_threshold":   body.CPUThreshold,
			"ram_enabled":     body.RAMEnabled,
			"ram_threshold":   body.RAMThreshold,
			"disk_enabled":    body.DiskEnabled,
			"disk_threshold":  body.DiskThreshold,
			"ssl_enabled":     body.SSLEnabled,
			"ssl_days_before": body.SSLDaysBefore,
			"updated_at":      body.UpdatedAt,
		}).Error; err != nil {
			writeErr(w, "Could not update server alerts.", "storage_unavailable", 503)
			return
		}
		h.db.First(&body, "id = ?", serverID)
	}
	writeJSON(w, body, http.StatusOK)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
