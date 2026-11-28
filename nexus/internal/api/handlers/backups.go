package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/backups"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type BackupsHandler struct{ Runtime *backups.Runtime }
type backupRunView struct {
	models.SupervisedRun
	PolicyID     string `json:"policyId"`
	StagingClean bool   `json:"stagingClean"`
}

func (h *BackupsHandler) runView(run models.SupervisedRun) backupRunView {
	var cleaned bool
	h.Runtime.DB.Raw("SELECT cleaned FROM backup_run_cleanup WHERE run_id=?", run.ID).Scan(&cleaned)
	return backupRunView{run, run.TaskID, cleaned}
}
func backupBody(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		writeErr(w, "Valid backup fields required.", "bad_request", 400)
		return false
	}
	return true
}
func (h *BackupsHandler) Serve(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		a, ok := auth.FromContext(r.Context())
		if !ok || !a.AuthorizedNow() {
			h.fail(w, backups.ErrDenied)
			return
		}
		server := chi.URLParam(r, "id")
		var result any
		var err error
		status := 200
		switch action {
		case "policies":
			result, err = h.Runtime.Policies(a, server)
		case "health":
			result, err = h.Runtime.Health(a, server)
		case "settings":
			result, err = h.Runtime.Settings(a, server, chi.URLParam(r, "policyId"))
		case "save-settings":
			var input struct {
				KeepLast        int `json:"keepLast"`
				MaxAgeMinutes   int `json:"maxAgeMinutes"`
				VerifyAfterDays int `json:"verifyAfterDays"`
			}
			if !backupBody(w, r, &input) {
				return
			}
			err = h.Runtime.SaveSettings(a, server, chi.URLParam(r, "policyId"), backups.PolicySettings{KeepLast: input.KeepLast, MaxAgeMinutes: input.MaxAgeMinutes, VerifyAfterDays: input.VerifyAfterDays})
			status = 204
		case "coverage":
			var input struct {
				Path      string `json:"path"`
				WatchGaps bool   `json:"watchGaps"`
			}
			if !backupBody(w, r, &input) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
			defer cancel()
			defer auth.WatchAccess(r, cancel)()
			result, err = h.Runtime.RefreshCoverage(ctx, a, server, input.Path, input.WatchGaps)
		case "create":
			var input struct {
				RequestID  string             `json:"requestId"`
				Definition backups.Definition `json:"definition"`
			}
			if !backupBody(w, r, &input) {
				return
			}
			var row backups.PolicyView
			row, err = h.Runtime.Create(a, server, input.RequestID, input.Definition)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "backup_policy", row.ID)
			}
		case "schedule":
			var input struct {
				Enabled *bool `json:"enabled"`
			}
			if !backupBody(w, r, &input) {
				return
			}
			if input.Enabled == nil {
				h.fail(w, backups.ErrInput)
				return
			}
			err = h.Runtime.SetEnabled(a, server, chi.URLParam(r, "policyId"), *input.Enabled)
			status = 204
		case "archive":
			err = h.Runtime.Archive(a, server, chi.URLParam(r, "policyId"))
			status = 204
		case "discover":
			var input struct {
				Path string `json:"path"`
			}
			if !backupBody(w, r, &input) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
			defer cancel()
			defer auth.WatchAccess(r, cancel)()
			result, err = h.Runtime.Discover(ctx, a, server, input.Path)
		case "start":
			var input struct {
				RequestID    string `json:"requestId"`
				Action       string `json:"action"`
				SnapshotID   string `json:"snapshotId"`
				PreviewRunID string `json:"previewRunId"`
			}
			if !backupBody(w, r, &input) {
				return
			}
			var run models.SupervisedRun
			if input.Action == "retention-preview" || input.Action == "retention-apply" {
				if input.SnapshotID != "" {
					h.fail(w, backups.ErrInput)
					return
				}
				run, err = h.Runtime.StartRetention(a, server, chi.URLParam(r, "policyId"), input.RequestID, input.Action, input.PreviewRunID)
			} else if input.PreviewRunID != "" {
				err = backups.ErrInput
			} else {
				run, err = h.Runtime.Start(a, server, chi.URLParam(r, "policyId"), input.RequestID, input.Action, input.SnapshotID)
			}
			result = h.runView(run)
			status = 202
			if err == nil {
				audit.MarkResource(r.Context(), "job_run", run.ID)
			}
		case "runs":
			var rows []models.SupervisedRun
			rows, err = h.Runtime.Runs(a, server)
			views := []backupRunView{}
			for _, run := range rows {
				views = append(views, h.runView(run))
			}
			result = views
		case "inspect", "cancel", "release":
			ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
			defer cancel()
			defer auth.WatchAccess(r, cancel)()
			observation, parsed, observeErr := h.Runtime.Observe(ctx, a, server, chi.URLParam(r, "rid"), action)
			err = observeErr
			if err == nil {
				run, loadErr := h.Runtime.Get(server, chi.URLParam(r, "rid"))
				err = loadErr
				result = map[string]any{"run": h.runView(run), "observation": observation, "result": parsed, "automaticRetryAllowed": false}
			}
		default:
			h.fail(w, backups.ErrInput)
			return
		}
		if err != nil {
			h.fail(w, err)
			return
		}
		if !a.AuthorizedNow() {
			h.fail(w, backups.ErrDenied)
			return
		}
		if status == 204 {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, result, status)
	}
}
func (h *BackupsHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, backups.ErrDisabled):
		writeErr(w, "Enable backups and operation supervision for remote backup jobs.", "feature_disabled", 409)
	case errors.Is(err, backups.ErrDenied):
		writeErr(w, "Backup access, ownership, source identity or current authority is unavailable.", "forbidden", 403)
	case errors.Is(err, backups.ErrInput):
		writeErr(w, "Check the selected sources, repository, times, limits and verified root SSH connection. Check the repository or complete a manual backup before enabling a schedule.", "invalid_backup_input", 400)
	case errors.Is(err, backups.ErrBusy):
		writeErr(w, "This host has an unresolved job. Inspect or stop it before starting another.", "backup_busy", 409)
	case errors.Is(err, backups.ErrConflict):
		writeErr(w, "The saved backup or request identity changed. Inspect retained history before a new request.", "backup_conflict", 409)
	case errors.Is(err, gorm.ErrRecordNotFound):
		writeErr(w, "Backup not found.", "not_found", 404)
	default:
		writeErr(w, "Backup state or protected settings unavailable. Refresh retained history before submitting another request.", "backup_unavailable", 503)
	}
}
