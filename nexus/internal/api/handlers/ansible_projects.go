package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/ansible"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"gorm.io/gorm"
)

type AnsibleProjectsHandler struct{ Service *ansible.Service }

func ansibleBody(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		writeErr(w, "Valid Ansible fields required.", "bad_request", 400)
		return false
	}
	return true
}

// Serve binds every operation to a closed policy entry and a registered server.
// Content reveals are explicit POSTs; list responses never contain ciphertext,
// session authority, project files or variable values.
func (h *AnsibleProjectsHandler) Serve(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		a, ok := auth.FromContext(r.Context())
		if !ok || !a.AuthorizedNow() {
			h.fail(w, ansible.ErrDenied)
			return
		}
		server, project, revision, plan := chi.URLParam(r, "id"), chi.URLParam(r, "projectId"), chi.URLParam(r, "revisionId"), chi.URLParam(r, "planId")
		var result any
		var err error
		status := 200
		switch action {
		case "schedules":
			result, err = h.Service.Schedules(a, server)
		case "create-schedule":
			var input struct {
				Name            string    `json:"name"`
				PlanID          string    `json:"planId"`
				IntervalMinutes int       `json:"intervalMinutes"`
				FirstAt         time.Time `json:"firstAt"`
			}
			if !ansibleBody(w, r, &input) {
				return
			}
			var row ansible.Schedule
			row, err = h.Service.CreateSchedule(a, server, input.Name, input.PlanID, input.IntervalMinutes, input.FirstAt)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_schedule", row.ID)
			}
		case "set-schedule":
			var input struct {
				Enabled *bool `json:"enabled"`
			}
			if !ansibleBody(w, r, &input) {
				return
			}
			if input.Enabled == nil {
				h.fail(w, ansible.ErrInput)
				return
			}
			err = h.Service.SetSchedule(a, server, chi.URLParam(r, "scheduleId"), *input.Enabled)
			status = 204
		case "presets":
			result, err = h.Service.Presets(a, server)
		case "create-preset":
			var input struct {
				Name   string `json:"name"`
				PlanID string `json:"planId"`
			}
			if !ansibleBody(w, r, &input) {
				return
			}
			var row ansible.Preset
			row, err = h.Service.CreatePreset(a, server, input.Name, input.PlanID)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_preset", row.ID)
			}
		case "preset-content":
			result, err = h.Service.PresetContent(a, server, chi.URLParam(r, "presetId"))
		case "prepare-preset":
			var input struct {
				Variables     map[string]any          `json:"variables"`
				VaultPassword *ansible.VaultReference `json:"vaultPassword,omitempty"`
			}
			if !ansibleBody(w, r, &input) {
				return
			}
			var row ansible.PlanView
			row, err = h.Service.PreparePreset(a, server, chi.URLParam(r, "presetId"), input.Variables, input.VaultPassword)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_plan", row.ID)
			}
		case "archive-preset":
			err = h.Service.ArchivePreset(a, server, chi.URLParam(r, "presetId"))
			status = 204
		case "templates":
			result, err = h.Service.Templates(a, server)
		case "create-template":
			var input struct {
				Name   string         `json:"name"`
				Bundle ansible.Bundle `json:"bundle"`
			}
			if !ansibleBody(w, r, &input) {
				return
			}
			var row ansible.ProjectTemplate
			row, err = h.Service.CreateTemplate(a, server, input.Name, input.Bundle)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_template", row.ID)
			}
		case "template-content":
			result, err = h.Service.TemplateContent(a, server, chi.URLParam(r, "templateId"))
		case "archive-template":
			err = h.Service.ArchiveTemplate(a, server, chi.URLParam(r, "templateId"))
			status = 204
		case "import-revision":
			var input ansible.RepositoryImport
			if !ansibleBody(w, r, &input) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()
			defer auth.WatchAccess(r, cancel)()
			var row ansible.Revision
			row, err = h.Service.ImportRevision(ctx, a, server, project, input)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_revision", row.ID)
			}
		case "projects":
			result, err = h.Service.Projects(a, server)
		case "create-project":
			var body struct {
				Name string `json:"name"`
			}
			if !ansibleBody(w, r, &body) {
				return
			}
			var row ansible.Project
			row, err = h.Service.CreateProject(a, server, body.Name)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_project", row.ID)
			}
		case "archive":
			err = h.Service.Archive(a, server, project)
			status = 204
		case "revisions":
			result, err = h.Service.Revisions(a, server, project)
		case "create-revision":
			var body ansible.Bundle
			if !ansibleBody(w, r, &body) {
				return
			}
			var row ansible.Revision
			row, err = h.Service.CreateRevision(a, server, project, body)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_revision", row.ID)
			}
		case "revision-content":
			result, err = h.Service.Content(a, server, project, revision)
		case "prepare":
			var body ansible.PlanRequest
			if !ansibleBody(w, r, &body) {
				return
			}
			var row ansible.PlanView
			row, err = h.Service.Prepare(a, server, project, body)
			result = row
			status = 201
			if err == nil {
				audit.MarkResource(r.Context(), "ansible_plan", row.ID)
			}
		case "plans":
			result, err = h.Service.Plans(a, server)
		case "plan", "plan-content":
			result, err = h.Service.Plan(a, server, plan, action == "plan-content")
		case "approve":
			var body struct {
				PlanDigest     string `json:"planDigest"`
				RevisionDigest string `json:"revisionDigest"`
			}
			if !ansibleBody(w, r, &body) {
				return
			}
			result, err = h.Service.Approve(a, server, plan, body.PlanDigest, body.RevisionDigest)
		case "cancel":
			err = h.Service.CancelPlan(a, server, plan)
			status = 204
		default:
			h.fail(w, ansible.ErrInput)
			return
		}
		if err != nil {
			h.fail(w, err)
			return
		}
		if !a.AuthorizedNow() {
			h.fail(w, ansible.ErrDenied)
			return
		}
		if status == 204 {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, result, status)
	}
}
func (h *AnsibleProjectsHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ansible.ErrDisabled):
		writeErr(w, "Automation is disabled.", "feature_disabled", 409)
	case errors.Is(err, ansible.ErrDenied):
		writeErr(w, "Ansible authority unavailable or revoked.", "forbidden", 403)
	case errors.Is(err, gorm.ErrRecordNotFound):
		writeErr(w, "Ansible resource not found.", "not_found", 404)
	case errors.Is(err, ansible.ErrInput):
		writeErr(w, "Check bundle paths, declared variable types, options, distinct controller/targets, verified host keys and group selection.", "invalid_ansible_input", 400)
	case errors.Is(err, ansible.ErrBusy):
		writeErr(w, "The queue is full or a selected host is busy.", "ansible_busy", 409)
	case errors.Is(err, ansible.ErrConflict):
		writeErr(w, "Ansible content, target identity or approval changed. Prepare a new plan; a different person must approve it.", "ansible_conflict", 409)
	default:
		writeErr(w, "Protected Ansible data or storage unavailable.", "unavailable", 503)
	}
}
