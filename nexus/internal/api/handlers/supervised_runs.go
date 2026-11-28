package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type SupervisedRunsHandler struct {
	db      *gorm.DB
	service *jobsupervisor.Service
}

func NewSupervisedRunsHandler(database *gorm.DB, key []byte, pool *nexusssh.Pool) *SupervisedRunsHandler {
	return &SupervisedRunsHandler{database, jobsupervisor.NewService(database, key, pool)}
}

func (h *SupervisedRunsHandler) task(r *http.Request) (models.ScheduledTask, error) {
	var task models.ScheduledTask
	err := h.db.First(&task, "id=? AND server_id=?", chi.URLParam(r, "tid"), chi.URLParam(r, "id")).Error
	return task, err
}
func (h *SupervisedRunsHandler) run(r *http.Request) (models.SupervisedRun, error) {
	var run models.SupervisedRun
	err := h.db.First(&run, "id=? AND task_id=? AND server_id=?", chi.URLParam(r, "rid"), chi.URLParam(r, "tid"), chi.URLParam(r, "id")).Error
	return run, err
}
func (h *SupervisedRunsHandler) List(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, err := h.task(r); err != nil {
		writeErr(w, "Task not found.", "not_found", 404)
		return
	}
	runs := []models.SupervisedRun{}
	if err := h.db.Where("task_id=? AND server_id=?", chi.URLParam(r, "tid"), chi.URLParam(r, "id")).Order("created_at desc,id desc").Limit(50).Find(&runs).Error; err != nil {
		writeErr(w, "Could not load run history.", "internal", 500)
		return
	}
	writeJSON(w, runs, 200)
}
func (h *SupervisedRunsHandler) Read(w http.ResponseWriter, r *http.Request) {
	h.observe(w, r, "cached")
}
func (h *SupervisedRunsHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	h.observe(w, r, "inspect")
}
func (h *SupervisedRunsHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	h.observe(w, r, "cancel")
}
func (h *SupervisedRunsHandler) Release(w http.ResponseWriter, r *http.Request) {
	h.observe(w, r, "release")
}
func (h *SupervisedRunsHandler) observe(w http.ResponseWriter, r *http.Request, action string) {
	w.Header().Set("Cache-Control", "no-store")
	if _, err := h.task(r); err != nil {
		writeErr(w, "Task not found.", "not_found", 404)
		return
	}
	run, err := h.run(r)
	if err != nil {
		writeErr(w, "Run not found.", "not_found", 404)
		return
	}
	audit.MarkResource(r.Context(), "job_run", run.ID)
	if action == "cancel" {
		if err := h.db.Model(&models.ScheduledTask{}).Where("id=? AND server_id=? AND run_id=?", run.TaskID, run.ServerID, run.ID).Update("enabled", false).Error; err != nil {
			writeErr(w, "Could not pause this task.", "internal", 500)
			return
		}
	}
	var result jobsupervisor.Snapshot
	if action == "cached" {
		result, err = h.service.Cached(run)
	} else {
		result, err = h.service.Inspect(r.Context(), run, action)
	}
	if err != nil {
		audit.MarkRemoteUnknown(r.Context())
		writeErr(w, "Run state could not be verified. The run ID is retained; do not retry the command.", "remote_unknown", 502)
		return
	}
	if result.State == "unknown" {
		audit.MarkRemoteUnknown(r.Context())
	}
	// jobs.cancel grants stopping authority, not permission to read job logs.
	if action == "cancel" {
		result.Output = ""
	}
	var latest models.SupervisedRun
	if err := h.db.First(&latest, "id=? AND server_id=? AND task_id=?", run.ID, run.ServerID, run.TaskID).Error; err != nil {
		writeErr(w, "Could not load run metadata.", "internal", 500)
		return
	}
	writeJSON(w, map[string]any{"run": latest, "observation": result, "automaticRetryAllowed": false}, 200)
}
