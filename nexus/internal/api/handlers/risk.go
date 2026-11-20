package handlers

import (
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
	"net/http"
)

func (h *AuthorizationHandler) StepUp(w http.ResponseWriter, r *http.Request) {
	var input struct{ CurrentPassword, Code string }
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		writeErr(w, "Password and factor required.", "bad_request", 400)
		return
	}
	a, _ := auth.FromContext(r.Context())
	if err := h.sessions.StepUp(a, input.CurrentPassword, input.Code); err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
func (h *AuthorizationHandler) SetGroupPolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string
		RequireMFA      *bool
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || input.RequireMFA == nil {
		writeErr(w, "An explicit MFA policy value is required.", "bad_request", 400)
		return
	}
	a, _ := auth.FromContext(r.Context())
	if err := h.sessions.RequirePassword(a, input.CurrentPassword); err != nil {
		if errors.Is(err, auth.ErrCredentials) || errors.Is(err, auth.ErrStepUp) {
			writeErr(w, "Confirm the current password and recent MFA.", "step_up_required", 403)
			return
		}
		h.failure(w, err)
		return
	}
	if !a.RecentMFA() {
		writeErr(w, "Enroll MFA and verify it before changing protected-group policy.", "step_up_required", 403)
		return
	}
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if !authorization.New(tx).All(a.User.ID, "", "roles.manage", "groups.manage") {
			return authorization.ErrDenied
		}
		row := tx.Model(&authorization.Group{}).Where("id=?", chi.URLParam(r, "gid")).Update("require_mfa", *input.RequireMFA)
		if row.Error != nil {
			return row.Error
		}
		if row.RowsAffected != 1 {
			return authorization.ErrInvalid
		}
		return authorization.New(tx).Record(a.User.ID, "groups.risk_policy", chi.URLParam(r, "gid"), "succeeded", w.Header().Get("X-Request-ID"))
	})
	if err != nil {
		h.failure(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, 200)
}
