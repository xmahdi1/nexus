package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xmahdi1/nexus/internal/audit"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type TasksHandler struct {
	db                 *gorm.DB
	supervisionEnabled bool
}

func NewTasksHandler(db *gorm.DB, enabled ...bool) *TasksHandler {
	h := &TasksHandler{db: db}
	if len(enabled) > 0 {
		h.supervisionEnabled = enabled[0]
	}
	return h
}
func (h *TasksHandler) List(w http.ResponseWriter, r *http.Request) {
	tasks := []models.ScheduledTask{}
	if err := h.db.Where("server_id=?", chi.URLParam(r, "id")).Order("created_at desc").Find(&tasks).Error; err != nil {
		writeErr(w, "Could not load tasks.", "internal", 500)
		return
	}
	writeJSON(w, tasks, 200)
}

type taskInput struct {
	Name, Command   string
	IntervalMinutes int
	Enabled         *bool
	Supervised      *bool
}

func validTask(input taskInput) bool {
	return len(input.Name) <= 120 && len(input.Command) <= 16<<10 && input.IntervalMinutes >= 0 && input.IntervalMinutes <= 525600
}
func (h *TasksHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input taskInput
	if json.NewDecoder(r.Body).Decode(&input) != nil || strings.TrimSpace(input.Command) == "" || !validTask(input) {
		writeErr(w, "Valid command and bounded interval required.", "bad_request", 400)
		return
	}
	if input.IntervalMinutes == 0 {
		input.IntervalMinutes = 60
	}
	if input.Supervised != nil && *input.Supervised && !h.supervisionEnabled {
		writeErr(w, "Job supervision is disabled.", "feature_disabled", 409)
		return
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		writeErr(w, "Could not create task.", "internal", 500)
		return
	}
	access, _ := auth.FromContext(r.Context())
	now := time.Now().UTC()
	next := now.Add(time.Duration(input.IntervalMinutes) * time.Minute)
	task := models.ScheduledTask{ID: hex.EncodeToString(id), ServerID: chi.URLParam(r, "id"), ActorID: access.User.ID, CreatedBy: access.User.ID, Name: input.Name, Command: input.Command, IntervalMinutes: input.IntervalMinutes, Enabled: true, NextRunAt: &next, LastStatus: "pending", CreatedAt: now}
	if input.Supervised != nil {
		task.Supervised = *input.Supervised
	}
	if err := h.db.Create(&task).Error; err != nil {
		writeErr(w, "Could not save task.", "internal", 500)
		return
	}
	audit.MarkResource(r.Context(), "task", task.ID)
	writeJSON(w, task, 201)
}
func (h *TasksHandler) Update(w http.ResponseWriter, r *http.Request) {
	var input taskInput
	if json.NewDecoder(r.Body).Decode(&input) != nil || !validTask(input) {
		writeErr(w, "Invalid task input.", "bad_request", 400)
		return
	}
	if input.Supervised != nil && *input.Supervised && !h.supervisionEnabled {
		writeErr(w, "Job supervision is disabled.", "feature_disabled", 409)
		return
	}
	access, _ := auth.FromContext(r.Context())
	var task models.ScheduledTask
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&task, "id=? AND server_id=?", chi.URLParam(r, "tid"), chi.URLParam(r, "id")).Error; err != nil {
			return err
		}
		if taskBlocked(task) {
			return errTaskRunning
		}
		updates := map[string]any{"actor_id": access.User.ID}
		if input.Supervised != nil {
			updates["supervised"] = *input.Supervised
		}
		if input.Name != "" {
			updates["name"] = input.Name
		}
		if input.Command != "" {
			updates["command"] = input.Command
		}
		interval := task.IntervalMinutes
		if input.IntervalMinutes > 0 {
			interval = input.IntervalMinutes
			updates["interval_minutes"] = interval
		}
		if input.Enabled != nil {
			updates["enabled"] = *input.Enabled
		}
		next := time.Now().UTC().Add(time.Duration(interval) * time.Minute)
		updates["next_run_at"] = &next
		if err := tx.Model(&task).Updates(updates).Error; err != nil {
			return err
		}
		return tx.First(&task, "id=? AND server_id=?", task.ID, task.ServerID).Error
	})
	if h.taskFailure(w, err) {
		return
	}
	writeJSON(w, task, 200)
}
func (h *TasksHandler) Delete(w http.ResponseWriter, r *http.Request) {
	var task models.ScheduledTask
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&task, "id=? AND server_id=?", chi.URLParam(r, "tid"), chi.URLParam(r, "id")).Error; err != nil {
			return err
		}
		if taskBlocked(task) {
			return errTaskRunning
		}
		return tx.Delete(&task).Error
	})
	if h.taskFailure(w, err) {
		return
	}
	w.WriteHeader(204)
}
func (h *TasksHandler) RunNow(w http.ResponseWriter, r *http.Request) {
	access, _ := auth.FromContext(r.Context())
	var task models.ScheduledTask
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&task, "id=? AND server_id=?", chi.URLParam(r, "tid"), chi.URLParam(r, "id")).Error; err != nil {
			return err
		}
		if taskBlocked(task) {
			return errTaskRunning
		}
		if task.Supervised && !h.supervisionEnabled {
			return errSupervisionDisabled
		}
		past := time.Now().UTC().Add(-time.Second)
		return tx.Model(&task).Updates(map[string]any{"actor_id": access.User.ID, "enabled": true, "next_run_at": past, "last_status": "pending"}).Error
	})
	if h.taskFailure(w, err) {
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}

var errTaskRunning = fmt.Errorf("task is running")
var errSupervisionDisabled = fmt.Errorf("job supervision is disabled")

func taskBlocked(task models.ScheduledTask) bool {
	return task.LastStatus == "running" || (task.Supervised && task.RunID != "")
}

func (h *TasksHandler) taskFailure(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeErr(w, "Task not found.", "not_found", 404)
	} else if errors.Is(err, errTaskRunning) {
		writeErr(w, "Task has a running or unresolved execution; inspect or cancel it before retrying.", "task_running", 409)
	} else if errors.Is(err, errSupervisionDisabled) {
		writeErr(w, "Job supervision is disabled.", "feature_disabled", 409)
	} else {
		writeErr(w, "Could not save task.", "internal", 500)
	}
	return true
}
