package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/githubactions"
)

type GitHubActionsHandler struct{ Service *githubactions.Service }

func (h *GitHubActionsHandler) Serve(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		a, ok := auth.FromContext(r.Context())
		if !ok || !a.AuthorizedNow() {
			writeErr(w, "GitHub access revoked.", "forbidden", 403)
			return
		}
		server, id := chi.URLParam(r, "id"), chi.URLParam(r, "connectionId")
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		defer auth.WatchAccess(r, cancel)()
		var result any
		var err error
		status := 200
		switch action {
		case "organizations":
			result, err = h.Service.Organizations(a, server)
		case "organization-create":
			var input githubactions.OrganizationInput
			if !githubBody(w, r, &input) {
				return
			}
			result, err = h.Service.CreateOrganization(ctx, a, server, input)
			input.PrivateKey = ""
			status = 201
		case "organization-disable":
			err = h.Service.DisableOrganization(a, server, chi.URLParam(r, "organizationId"))
			status = 204
		case "organization-runners":
			page := 1
			if value := r.URL.Query().Get("page"); value != "" {
				page, _ = strconv.Atoi(value)
			}
			result, err = h.Service.OrganizationRunners(ctx, a, server, chi.URLParam(r, "organizationId"), page)
		case "organization-changes":
			result, err = h.Service.OrganizationChanges(a, server)
		case "organization-remove", "organization-register":
			var input struct {
				RequestID string `json:"requestId"`
				githubactions.RemoveRunner
			}
			if !githubBody(w, r, &input) {
				return
			}
			kind := "runner_remove"
			if action == "organization-register" {
				kind = "registration"
			}
			if !githubactions.ValidRequestID(input.RequestID) {
				writeErr(w, "A 32-character hexadecimal request ID is required.", "bad_request", 400)
				return
			}
			audit.MarkResource(r.Context(), "github_organization_change", input.RequestID)
			var change githubactions.OrganizationChange
			var credential *githubactions.RegistrationCredential
			change, credential, err = h.Service.ChangeOrganizationRunner(ctx, a, server, chi.URLParam(r, "organizationId"), input.RequestID, kind, input.RemoveRunner)
			if change.ID != "" {
				if !a.AuthorizedNow() {
					if credential != nil {
						credential.Token = ""
					}
					audit.MarkRemoteUnknown(r.Context())
					writeErr(w, "Authority changed. Inspect the saved request before another change.", "remote_unknown", 502)
					return
				}
				if change.State == "unknown" || change.State == "submitting" {
					audit.MarkRemoteUnknown(r.Context())
				} else if change.State == "not_submitted" {
					audit.MarkFailed(r.Context())
				}
				writeJSON(w, map[string]any{"change": change, "credential": credential, "automaticRetryAllowed": false}, 202)
				if credential != nil {
					credential.Token = ""
				}
				return
			}
		case "webhook":
			result, err = h.Service.Webhook(a, server, id)
		case "webhook-rotate":
			var info githubactions.WebhookInfo
			var secret string
			info, secret, err = h.Service.RotateWebhook(a, server, id)
			result = map[string]any{"webhook": info, "secret": secret}
		case "webhook-disable":
			err = h.Service.DisableWebhook(a, server, id)
			status = 204
		case "webhook-events":
			result, err = h.Service.WebhookRuns(a, server, id)
		case "list":
			result, err = h.Service.List(a, server)
		case "create":
			var input githubactions.ConnectionInput
			if !githubBody(w, r, &input) {
				return
			}
			result, err = h.Service.Create(ctx, a, server, input)
			input.PrivateKey = ""
			status = 201
		case "disable":
			err = h.Service.Disable(a, server, id)
			status = 204
		case "workflows":
			page := 1
			if value := r.URL.Query().Get("page"); value != "" {
				page, _ = strconv.Atoi(value)
			}
			result, err = h.Service.Workflows(ctx, a, server, id, page)
		case "runs":
			page := 1
			if value := r.URL.Query().Get("page"); value != "" {
				page, _ = strconv.Atoi(value)
			}
			result, err = h.Service.Runs(ctx, a, server, id, page)
		case "jobs":
			run, _ := strconv.ParseInt(chi.URLParam(r, "runId"), 10, 64)
			page := 1
			if value := r.URL.Query().Get("page"); value != "" {
				page, _ = strconv.Atoi(value)
			}
			result, err = h.Service.Jobs(ctx, a, server, id, run, page)
		case "changes":
			result, err = h.Service.Changes(a, server)
		case "provider-runners":
			page := 1
			if value := r.URL.Query().Get("page"); value != "" {
				page, _ = strconv.Atoi(value)
			}
			result, err = h.Service.ProviderRunners(ctx, a, server, id, page)
		case "workflow-read":
			var input struct {
				Branch string `json:"branch"`
				Path   string `json:"path"`
			}
			if !githubBody(w, r, &input) {
				return
			}
			result, err = h.Service.Workflow(ctx, a, server, id, input.Branch, input.Path)
		case "workflow-publish", "runner-remove":
			var row githubactions.Change
			var requestID string
			if action == "workflow-publish" {
				var input struct {
					RequestID string `json:"requestId"`
					githubactions.WorkflowEdit
				}
				if !githubBodyLimit(w, r, &input, 98304) {
					return
				}
				requestID = input.RequestID
				if !githubactions.ValidRequestID(requestID) {
					writeErr(w, "A 32-character hexadecimal request ID is required.", "bad_request", 400)
					return
				}
				audit.MarkResource(r.Context(), "github_change", requestID)
				row, err = h.Service.PublishWorkflow(ctx, a, server, id, requestID, input.WorkflowEdit)
				input.Content = ""
			} else {
				var input struct {
					RequestID string `json:"requestId"`
					githubactions.RemoveRunner
				}
				if !githubBody(w, r, &input) {
					return
				}
				requestID = input.RequestID
				if !githubactions.ValidRequestID(requestID) {
					writeErr(w, "A 32-character hexadecimal request ID is required.", "bad_request", 400)
					return
				}
				audit.MarkResource(r.Context(), "github_change", requestID)
				row, err = h.Service.RemoveProviderRunner(ctx, a, server, id, requestID, input.RemoveRunner)
			}
			if row.ID != "" {
				if !a.AuthorizedNow() {
					audit.MarkRemoteUnknown(r.Context())
					writeErr(w, "Authority changed. Inspect the saved request before another change.", "remote_unknown", 502)
					return
				}
				if row.State != "applied" && row.State != "not_submitted" {
					audit.MarkRemoteUnknown(r.Context())
				} else if row.State == "not_submitted" {
					audit.MarkFailed(r.Context())
				}
				writeJSON(w, map[string]any{"change": row, "automaticRetryAllowed": false}, 202)
				return
			}
		case "history":
			result, err = h.Service.Submissions(a, server)
		case "cancellations":
			result, err = h.Service.Cancellations(a, server)
		case "run", "artifacts", "job-log", "artifact-download", "cancel":
			run, _ := strconv.ParseInt(chi.URLParam(r, "runId"), 10, 64)
			switch action {
			case "run":
				result, err = h.Service.Run(ctx, a, server, id, run)
			case "artifacts":
				page := 1
				if value := r.URL.Query().Get("page"); value != "" {
					page, _ = strconv.Atoi(value)
				}
				result, err = h.Service.Artifacts(ctx, a, server, id, run, page)
			case "job-log", "artifact-download":
				param := "jobId"
				if action == "artifact-download" {
					param = "artifactId"
				}
				item, _ := strconv.ParseInt(chi.URLParam(r, param), 10, 64)
				var data []byte
				data, err = h.Service.Content(ctx, a, server, id, run, item, action == "artifact-download")
				defer clear(data)
				if err == nil {
					if !a.AuthorizedNow() {
						writeErr(w, "GitHub access revoked.", "forbidden", 403)
						return
					}
					w.Header().Set("X-Content-Type-Options", "nosniff")
					if action == "artifact-download" {
						w.Header().Set("Content-Type", "application/zip")
						w.Header().Set("Content-Disposition", `attachment; filename="github-artifact-`+strconv.FormatInt(item, 10)+`.zip"`)
						w.Header().Set("Content-Length", strconv.Itoa(len(data)))
						if _, writeErr := w.Write(data); writeErr != nil {
							audit.MarkRemoteUnknown(r.Context())
						}
					} else {
						writeJSON(w, map[string]any{"content": string(data), "jobId": item, "runId": run, "redacted": false}, 200)
					}
					return
				}
			case "cancel":
				var input struct {
					RequestID  string `json:"requestId"`
					RunAttempt int64  `json:"runAttempt"`
				}
				if !githubBody(w, r, &input) {
					return
				}
				if !githubactions.ValidRequestID(input.RequestID) {
					writeErr(w, "A 32-character hexadecimal request ID is required.", "bad_request", 400)
					return
				}
				audit.MarkResource(r.Context(), "github_cancellation", input.RequestID)
				var row githubactions.Cancellation
				row, err = h.Service.Cancel(ctx, a, server, id, input.RequestID, run, input.RunAttempt)
				if row.ID != "" {
					if !a.AuthorizedNow() {
						audit.MarkRemoteUnknown(r.Context())
						writeErr(w, "Cancellation authority changed. Inspect the retained request.", "remote_unknown", 502)
						return
					}
					if row.State == "unknown" || row.State == "submitting" {
						audit.MarkRemoteUnknown(r.Context())
					}
					writeJSON(w, map[string]any{"cancellation": row, "automaticRetryAllowed": false}, 202)
					return
				}
			}
		case "dispatch":
			var input struct {
				RequestID string `json:"requestId"`
				githubactions.Dispatch
			}
			if !githubBody(w, r, &input) {
				return
			}
			if !githubactions.ValidRequestID(input.RequestID) {
				writeErr(w, "A 32-character hexadecimal request ID is required.", "bad_request", 400)
				return
			}
			audit.MarkResource(r.Context(), "github_dispatch", input.RequestID)
			row, submitErr := h.Service.Submit(ctx, a, server, id, input.RequestID, input.Dispatch)
			err = submitErr
			if row.ID != "" {
				if !a.AuthorizedNow() {
					audit.MarkRemoteUnknown(r.Context())
					writeErr(w, "Submission authority changed. Inspect the retained request ID before a new dispatch.", "remote_unknown", 502)
					return
				}
				if row.State == "unknown" || row.State == "submitting" {
					audit.MarkRemoteUnknown(r.Context())
				}
				writeJSON(w, map[string]any{"submission": row, "automaticRetryAllowed": false}, 202)
				return
			}
		}
		if !a.AuthorizedNow() {
			writeErr(w, "GitHub access revoked.", "forbidden", 403)
			return
		}
		if err != nil {
			switch {
			case errors.Is(err, githubactions.ErrDisabled):
				writeErr(w, "Enable automation first.", "feature_disabled", 409)
			case errors.Is(err, githubactions.ErrTooLarge):
				writeErr(w, "Download exceeds the supported size (logs 1 MiB; artifacts 16 MiB).", "too_large", 413)
			case errors.Is(err, githubactions.ErrInput):
				writeErr(w, "Valid GitHub App, repository, organization and workflow fields required.", "bad_request", 400)
			case errors.Is(err, githubactions.ErrDenied):
				writeErr(w, "Current Nexus/GitHub authority does not allow this operation.", "forbidden", 403)
			case errors.Is(err, githubactions.ErrConflict):
				writeErr(w, "Request identity or connection changed. Inspect history.", "request_conflict", 409)
			default:
				writeErr(w, "GitHub operation unavailable. Refresh metadata; no automatic retry is allowed.", "unavailable", 502)
			}
			return
		}
		if status == 204 {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, result, status)
	}
}

func githubBody(w http.ResponseWriter, r *http.Request, value any) bool {
	return githubBodyLimit(w, r, value, 32768)
}
func githubBodyLimit(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		writeErr(w, "Valid GitHub fields required.", "bad_request", 400)
		return false
	}
	return true
}
