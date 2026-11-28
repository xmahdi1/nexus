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
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/operations"
	"github.com/xmahdi1/nexus/internal/remoteaction"
	"gorm.io/gorm"
)

type OperationsHandler struct{ service *operations.Service }

func NewOperationsHandler(service *operations.Service) *OperationsHandler {
	return &OperationsHandler{service}
}

func (h *OperationsHandler) Start(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var input struct {
			RequestID string `json:"requestId"`
			Path      string `json:"path,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 12000)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			writeErr(w, "Valid operation fields and request ID required.", "bad_request", 400)
			return
		}
		access, ok := auth.FromContext(r.Context())
		if !ok || !access.AuthorizedNow() {
			writeErr(w, "Operation access revoked.", "forbidden", 403)
			return
		}
		if remoteaction.ValidID(input.RequestID) {
			audit.MarkResource(r.Context(), "job_run", input.RequestID)
		}
		run, err := h.service.Start(r.Context(), access.User.ID, access.Session.ID, chi.URLParam(r, "id"), input.RequestID, action, input.Path, chi.URLParam(r, "cid"))
		if !access.AuthorizedNow() {
			audit.MarkRemoteUnknown(r.Context())
			writeErr(w, "Access changed during submission. Inspect this run before retrying.", "remote_unknown", 502)
			return
		}
		if err != nil {
			if run.ID != "" {
				audit.MarkRemoteUnknown(r.Context())
				writeJSON(w, map[string]any{"error": "Submission outcome is unconfirmed. Inspect the retained run; do not resubmit the command.", "code": "remote_unknown", "run": run, "automaticRetryAllowed": false}, 502)
				return
			}
			switch {
			case errors.Is(err, operations.ErrDisabled):
				writeErr(w, err.Error(), "feature_disabled", 409)
			case errors.Is(err, remoteaction.ErrInput):
				writeErr(w, err.Error(), "bad_request", 400)
			case errors.Is(err, authorization.ErrDenied):
				writeErr(w, "Operation denied by current authority.", "forbidden", 403)
			case errors.Is(err, gorm.ErrRecordNotFound):
				writeErr(w, "Resource not found.", "not_found", 404)
			case errors.Is(err, operations.ErrBusy), errors.Is(err, operations.ErrConflict):
				writeErr(w, err.Error(), "operation_conflict", 409)
			default:
				writeErr(w, "Could not reserve this operation. No command was submitted by this request.", "storage_unavailable", 503)
			}
			return
		}
		if run.State == "unknown" || run.State == "dispatching" {
			audit.MarkRemoteUnknown(r.Context())
		}
		writeJSON(w, map[string]any{"run": run, "automaticRetryAllowed": false}, 202)
	}
}
func (h *OperationsHandler) List(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	runs, err := h.service.List(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, "Could not load operation history.", "storage_unavailable", 503)
		return
	}
	writeJSON(w, runs, 200)
}
func (h *OperationsHandler) Read(w http.ResponseWriter, r *http.Request) { h.observe(w, r, "cached") }
func (h *OperationsHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	h.observe(w, r, "inspect")
}
func (h *OperationsHandler) Cancel(w http.ResponseWriter, r *http.Request) { h.observe(w, r, "cancel") }
func (h *OperationsHandler) Release(w http.ResponseWriter, r *http.Request) {
	h.observe(w, r, "release")
}
func (h *OperationsHandler) observe(w http.ResponseWriter, r *http.Request, action string) {
	w.Header().Set("Cache-Control", "no-store")
	run, err := h.service.Get(chi.URLParam(r, "id"), chi.URLParam(r, "rid"))
	if err != nil {
		writeErr(w, "Run not found.", "not_found", 404)
		return
	}
	spec, ok := remoteaction.Find(run.Action)
	if !ok {
		writeErr(w, "Unknown run action.", "unsupported_action", 409)
		return
	}
	permissions := []string{spec.ReadPermission}
	if action == "cancel" {
		permissions = spec.Permissions
	}
	access, ok := auth.FromContext(r.Context())
	if !ok {
		writeErr(w, "Operation denied.", "forbidden", 403)
		return
	}
	bound := access.CheckAuthorization
	access.CheckAuthorization = func() bool {
		return bound != nil && bound() && authorization.New(h.service.DB).All(access.User.ID, run.ServerID, permissions...)
	}
	if !access.AuthorizedNow() {
		writeErr(w, "Operation denied.", "forbidden", 403)
		return
	}
	audit.MarkResource(r.Context(), "job_run", run.ID)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	defer auth.WatchAccess(r, cancel)()
	result, err := h.service.Observe(ctx, run, action)
	if err != nil {
		audit.MarkRemoteUnknown(r.Context())
		writeErr(w, "Run state could not be verified. The run ID is retained; do not replay the command.", "remote_unknown", 502)
		return
	}
	if !access.AuthorizedNow() {
		if action == "cancel" || action == "release" {
			audit.MarkRemoteUnknown(r.Context())
			writeErr(w, "Access changed during this control request. Inspect the run state.", "remote_unknown", 502)
		} else {
			writeErr(w, "Operation access revoked.", "forbidden", 403)
		}
		return
	}
	if result.State == "unknown" {
		audit.MarkRemoteUnknown(r.Context())
	}
	if action == "cancel" {
		result.Output = ""
	}
	latest, err := h.service.Get(run.ServerID, run.ID)
	if err != nil {
		writeErr(w, "Could not load run metadata.", "storage_unavailable", 503)
		return
	}
	writeJSON(w, map[string]any{"run": latest, "observation": result, "automaticRetryAllowed": false}, 200)
}
