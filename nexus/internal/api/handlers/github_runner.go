package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/githubrunner"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/operations"
)

func (h *OperationsHandler) StartRunner(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input githubrunner.Setup
	r.Body = http.MaxBytesReader(w, r.Body, 12000)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Validate() != nil {
		writeErr(w, githubrunner.ErrInput.Error(), "bad_request", 400)
		return
	}
	a, ok := auth.FromContext(r.Context())
	if !ok || !a.AuthorizedNow() {
		writeErr(w, "Runner access revoked.", "forbidden", 403)
		return
	}
	audit.MarkResource(r.Context(), "job_run", input.RequestID)
	run, err := h.service.StartRunner(r.Context(), a.User.ID, a.Session.ID, chi.URLParam(r, "id"), input)
	input.RegistrationToken = ""
	if !a.AuthorizedNow() {
		audit.MarkRemoteUnknown(r.Context())
		writeErr(w, "Runner submission unconfirmed after access changed. Inspect its retained run ID before enrolling again.", "remote_unknown", 502)
		return
	}
	if err != nil {
		if run.ID != "" {
			audit.MarkRemoteUnknown(r.Context())
			writeJSON(w, map[string]any{"error": "Runner submission outcome is unconfirmed. Inspect this run before enrolling again.", "code": "remote_unknown", "run": run, "automaticRetryAllowed": false}, 502)
			return
		}
		switch {
		case errors.Is(err, operations.ErrRunnerHost):
			writeErr(w, err.Error(), "runner_prerequisites", 400)
		case errors.Is(err, operations.ErrDisabled):
			writeErr(w, "Enable automation and operation supervision first.", "feature_disabled", 409)
		case errors.Is(err, authorization.ErrDenied):
			writeErr(w, "Runner access denied by current authority.", "forbidden", 403)
		case errors.Is(err, operations.ErrBusy), errors.Is(err, operations.ErrConflict):
			writeErr(w, "Inspect the existing operation before starting another runner.", "operation_conflict", 409)
		default:
			writeErr(w, "Runner could not be reserved. No command was submitted by this request.", "unavailable", 503)
		}
		return
	}
	writeJSON(w, map[string]any{"run": run, "automaticRetryAllowed": false}, 202)
}
func (h *OperationsHandler) Runners(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := auth.FromContext(r.Context())
	if !ok || !a.AuthorizedNow() {
		writeErr(w, "Runner access revoked.", "forbidden", 403)
		return
	}
	runs, err := h.service.List(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, "Runner history unavailable.", "unavailable", 503)
		return
	}
	type item struct {
		Run     models.SupervisedRun       `json:"run"`
		Profile githubrunner.PublicProfile `json:"profile"`
	}
	items := []item{}
	for _, run := range runs {
		if run.Action != "github-runner" {
			continue
		}
		var profile githubrunner.PublicProfile
		if json.Unmarshal([]byte(run.OperationContext), &profile) != nil {
			writeErr(w, "Runner metadata unavailable.", "unavailable", 503)
			return
		}
		items = append(items, item{run, profile})
	}
	if !a.AuthorizedNow() {
		writeErr(w, "Runner access revoked.", "forbidden", 403)
		return
	}
	writeJSON(w, items, 200)
}
