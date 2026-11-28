package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/ansible"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
)

type AnsibleRunsHandler struct{ Runtime *ansible.Runtime }

type ansibleRunView struct {
	models.SupervisedRun
	PlanID string `json:"planId"`
}

func publicAnsibleRun(run models.SupervisedRun) ansibleRunView {
	return ansibleRunView{SupervisedRun: run, PlanID: run.OperationContext}
}

func (h *AnsibleRunsHandler) Serve(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		a, ok := auth.FromContext(r.Context())
		if !ok || !a.AuthorizedNow() {
			writeErr(w, "Ansible run access revoked.", "forbidden", 403)
			return
		}
		server := chi.URLParam(r, "id")
		if action == "queue" || action == "enqueue" || action == "cancel-queue" {
			var result any
			var err error
			status := 200
			switch action {
			case "queue":
				result, err = h.Runtime.Queue(a, server)
			case "enqueue":
				var input struct {
					RequestID  string    `json:"requestId"`
					AfterRunID string    `json:"afterRunId"`
					NotBefore  time.Time `json:"notBefore"`
				}
				if !ansibleBody(w, r, &input) {
					return
				}
				var row ansible.QueueEntry
				row, err = h.Runtime.Enqueue(a, server, chi.URLParam(r, "planId"), input.RequestID, input.AfterRunID, input.NotBefore)
				result = row
				status = 202
				if err == nil {
					audit.MarkResource(r.Context(), "ansible_queue", row.ID)
				}
			case "cancel-queue":
				err = h.Runtime.CancelQueue(a, server, chi.URLParam(r, "queueId"))
				status = 204
			}
			if err != nil {
				(&AnsibleProjectsHandler{Service: h.Runtime.Service}).fail(w, err)
				return
			}
			if !a.AuthorizedNow() {
				writeErr(w, "Ansible queue access revoked.", "forbidden", 403)
				return
			}
			if status == 204 {
				w.WriteHeader(status)
				return
			}
			writeJSON(w, result, status)
			return
		}
		if action == "list" {
			rows, err := h.Runtime.List(server)
			if err != nil {
				writeErr(w, "Run history unavailable.", "unavailable", 503)
				return
			}
			if !a.AuthorizedNow() {
				writeErr(w, "Ansible run access revoked.", "forbidden", 403)
				return
			}
			views := make([]ansibleRunView, 0, len(rows))
			for _, row := range rows {
				views = append(views, publicAnsibleRun(row))
			}
			writeJSON(w, views, 200)
			return
		}
		if action == "start" {
			var input struct {
				RequestID string            `json:"requestId"`
				Tokens    map[string]string `json:"vaultTokens"`
			}
			if !ansibleBody(w, r, &input) {
				return
			}
			defer clear(input.Tokens)
			if !ansible.ValidExecutionID(input.RequestID) {
				writeErr(w, "A 32-character hexadecimal request ID is required.", "bad_request", 400)
				return
			}
			audit.MarkResource(r.Context(), "job_run", input.RequestID)
			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			defer cancel()
			defer auth.WatchAccess(r, cancel)()
			run, err := h.Runtime.Start(ctx, a, server, chi.URLParam(r, "planId"), input.RequestID, input.Tokens)
			if !a.AuthorizedNow() {
				audit.MarkRemoteUnknown(r.Context())
				writeErr(w, "Access changed during submission. Inspect the retained request ID before any new run.", "remote_unknown", 502)
				return
			}
			if err != nil && run.ID == "" {
				switch {
				case errors.Is(err, ansible.ErrDisabled):
					writeErr(w, "Enable automation and operation supervision first.", "feature_disabled", 409)
				case errors.Is(err, ansible.ErrDenied):
					writeErr(w, "Run denied by current approval or authority.", "forbidden", 403)
				case errors.Is(err, ansible.ErrConflict), errors.Is(err, ansible.ErrBusy):
					writeErr(w, "Plan already used, changed, or a selected host is reserved. Inspect retained runs.", "run_conflict", 409)
				case errors.Is(err, ansible.ErrInput):
					writeErr(w, "Supply a valid request ID and transient tokens for exactly the referenced Vault servers.", "bad_request", 400)
				default:
					writeErr(w, "Run could not be reserved; no command was submitted by this request.", "unavailable", 503)
				}
				return
			}
			status := 202
			message := ""
			if err != nil {
				message = "Submission or private-input preparation failed. Inspect this run; never replay it."
				if run.State == "not_started" {
					message = "Nothing dispatched. Check current approvals, pinned target SSH access, distinct controller credentials and the exact Vault version/token. Prepare a fresh plan before retrying."
				}
				if run.FinishedAt == nil {
					audit.MarkRemoteUnknown(r.Context())
					status = 502
				}
			}
			writeJSON(w, map[string]any{"run": publicAnsibleRun(run), "error": message, "automaticRetryAllowed": false}, status)
			return
		}
		run, err := h.Runtime.Get(server, chi.URLParam(r, "rid"))
		if err != nil {
			writeErr(w, "Run not found.", "not_found", 404)
			return
		}
		var targets []ansible.Target
		if action == "inspect" {
			view, err := h.Runtime.Plan(a, server, run.OperationContext, false)
			if err != nil {
				writeErr(w, "Current access to every frozen target is required to inspect results.", "forbidden", 403)
				return
			}
			targets = view.Targets
			bound := a.CheckAuthorization
			a.CheckAuthorization = func() bool {
				if bound == nil || !bound() {
					return false
				}
				for _, target := range view.Targets {
					if !authorization.New(h.Runtime.DB).All(a.User.ID, target.ServerID, "servers.read") {
						return false
					}
				}
				return true
			}
		}
		audit.MarkResource(r.Context(), "job_run", run.ID)
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		defer auth.WatchAccess(r, cancel)()
		observation, err := h.Runtime.Observe(ctx, run, action)
		if err != nil || !a.AuthorizedNow() {
			audit.MarkRemoteUnknown(r.Context())
			writeErr(w, "Run state could not be verified. Inspect the retained ID; do not repeat execution.", "remote_unknown", 502)
			return
		}
		var result *ansible.ExecutionResult
		if action == "inspect" {
			result = ansible.ParseExecutionResult(observation.Output, targets)
		}
		// Results expose only the validated fixed format, never arbitrary output.
		observation.Output = ""
		var latest models.SupervisedRun
		latest, err = h.Runtime.Get(server, run.ID)
		if err != nil {
			writeErr(w, "Retained run metadata unavailable.", "unavailable", 503)
			return
		}
		writeJSON(w, map[string]any{"run": publicAnsibleRun(latest), "observation": observation, "result": result, "automaticRetryAllowed": false}, 200)
	}
}
