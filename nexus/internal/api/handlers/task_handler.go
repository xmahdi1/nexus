package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type TasksHandler struct {
	db *gorm.DB
}

func NewTasksHandler(db *gorm.DB) *TasksHandler {
	db.AutoMigrate(&models.ScheduledTask{})
	return &TasksHandler{db: db}
}

func (h *TasksHandler) List(w http.ResponseWriter, r *http.Request) {
	var tasks []models.ScheduledTask
	h.db.Where("server_id = ?", chi.URLParam(r, "id")).Order("created_at desc").Find(&tasks)
	if tasks == nil {
		tasks = []models.ScheduledTask{}
	}
	writeJSON(w, tasks, http.StatusOK)
}

func (h *TasksHandler) Create(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var body struct {
		Name            string `json:"name"`
		Command         string `json:"command"`
		IntervalMinutes int    `json:"intervalMinutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Command == "" {
		writeErr(w, "command required", "bad_request", http.StatusBadRequest)
		return
	}
	if body.IntervalMinutes <= 0 {
		body.IntervalMinutes = 60
	}

	id := make([]byte, 8)
	rand.Read(id)
	now := time.Now()
	next := now.Add(time.Duration(body.IntervalMinutes) * time.Minute)
	task := models.ScheduledTask{
		ID:              hex.EncodeToString(id),
		ServerID:        serverID,
		Name:            body.Name,
		Command:         body.Command,
		IntervalMinutes: body.IntervalMinutes,
		Enabled:         true,
		NextRunAt:       &next,
		LastStatus:      "pending",
		CreatedAt:       now,
	}
	h.db.Create(&task)
	writeJSON(w, task, http.StatusCreated)
}

func (h *TasksHandler) Update(w http.ResponseWriter, r *http.Request) {
	tid := chi.URLParam(r, "tid")
	var task models.ScheduledTask
	if err := h.db.First(&task, "id = ?", tid).Error; err != nil {
		writeErr(w, "not found", "not_found", http.StatusNotFound)
		return
	}
	var body struct {
		Name            string `json:"name"`
		Command         string `json:"command"`
		IntervalMinutes int    `json:"intervalMinutes"`
		Enabled         *bool  `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	updates := map[string]any{}
	if body.Name != "" {
		updates["name"] = body.Name
	}
	if body.Command != "" {
		updates["command"] = body.Command
	}
	if body.IntervalMinutes > 0 {
		next := time.Now().Add(time.Duration(body.IntervalMinutes) * time.Minute)
		updates["interval_minutes"] = body.IntervalMinutes
		updates["next_run_at"] = &next
	}
	if body.Enabled != nil {
		updates["enabled"] = *body.Enabled
		if *body.Enabled {
			next := time.Now().Add(time.Duration(task.IntervalMinutes) * time.Minute)
			updates["next_run_at"] = &next
		}
	}

	h.db.Model(&task).Updates(updates)
	h.db.First(&task, "id = ?", tid)
	writeJSON(w, task, http.StatusOK)
}

func (h *TasksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	h.db.Delete(&models.ScheduledTask{}, "id = ?", chi.URLParam(r, "tid"))
	w.WriteHeader(http.StatusNoContent)
}

func (h *TasksHandler) RunNow(w http.ResponseWriter, r *http.Request) {
	tid := chi.URLParam(r, "tid")
	var task models.ScheduledTask
	if err := h.db.First(&task, "id = ?", tid).Error; err != nil {
		writeErr(w, "not found", "not_found", http.StatusNotFound)
		return
	}
	past := time.Now().Add(-1 * time.Second)
	h.db.Model(&task).Updates(map[string]any{"next_run_at": &past, "last_status": "pending"})
	writeJSON(w, map[string]string{"ok": "triggered"}, http.StatusOK)
}
