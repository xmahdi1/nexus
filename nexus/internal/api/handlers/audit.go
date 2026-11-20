package handlers

import (
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strconv"

	"github.com/xmahdi1/nexus/internal/audit"
	"gorm.io/gorm"
)

type AuditHandler struct{ db *gorm.DB }

func NewAuditHandler(db *gorm.DB) *AuditHandler { return &AuditHandler{db} }
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, err := strconv.ParseUint(q.Get("before"), 10, 64)
	if q.Get("before") != "" && err != nil {
		writeErr(w, "Invalid cursor.", "bad_request", 400)
		return
	}
	limit := 50
	if q.Get("limit") != "" {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 200 {
			writeErr(w, "Limit must be 1 to 200.", "bad_request", 400)
			return
		}
	}
	page, err := audit.Query(h.db, audit.Filter{Before: before, Limit: limit, Actor: q.Get("actor"), Server: q.Get("server"), Outcome: q.Get("outcome"), Action: q.Get("action"), Operation: q.Get("operation"), Request: q.Get("request")})
	if err != nil {
		writeErr(w, "Could not read audit events.", "audit_unavailable", 503)
		return
	}
	if q.Get("format") == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="nexus-audit.jsonl"`)
		w.Header().Set("X-Next-Cursor", page.Next)
		for _, event := range page.Items {
			if json.NewEncoder(w).Encode(event) != nil {
				return
			}
		}
		return
	}
	writeJSON(w, page, 200)
}

func (h *AuditHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	operation, err := audit.Inspect(h.db, chi.URLParam(r, "operationId"))
	if errors.Is(err, audit.ErrOperationID) {
		writeErr(w, "Invalid operation ID.", "bad_request", 400)
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeErr(w, "Operation not found.", "not_found", 404)
		return
	}
	if err != nil {
		writeErr(w, "Operation inspection unavailable.", "audit_unavailable", 503)
		return
	}
	writeJSON(w, operation, 200)
}
