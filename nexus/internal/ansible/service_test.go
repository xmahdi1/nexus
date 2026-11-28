package ansible

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"strings"
	"testing"
	"time"
)

func planInput(revision Revision) PlanRequest {
	return PlanRequest{RevisionID: revision.ID, RevisionDigest: revision.Digest, GroupID: "managed", ServerIDs: []string{"dev"}, Variables: map[string]any{"message": "fixture-private-variable"}, Options: Options{Mode: "check", TimeoutSeconds: 60}}
}
func TestFrozenPlanApprovalAndLiveAuthority(t *testing.T) {
	s, actor, approver, p, r := fixture(t)
	view, err := s.Prepare(actor, "controller", p.ID, planInput(r))
	if err != nil {
		t.Fatal(err)
	}
	if view.State != "prepared" || len(view.Targets) != 1 || view.Targets[0].ServerID != "dev" || len(view.Variables) != 0 {
		t.Fatal("invalid public snapshot")
	}
	if _, err := s.AuthorizedPlan(view.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("unapproved plan admitted", err)
	}
	if _, err := s.Approve(actor, "controller", view.ID, view.Digest, r.Digest); !errors.Is(err, ErrConflict) {
		t.Fatal("self approval admitted", err)
	}
	if _, err := s.Approve(approver, "controller", view.ID, strings.Repeat("0", 64), r.Digest); !errors.Is(err, ErrConflict) {
		t.Fatal("changed digest approved", err)
	}
	approved, err := s.Approve(approver, "controller", view.ID, view.Digest, r.Digest)
	if err != nil || approved.ApprovedBy != approver.User.ID {
		t.Fatal("approval failed", err)
	}
	if _, err := s.AuthorizedPlan(view.ID); err != nil {
		t.Fatal("approved plan unavailable", err)
	}
	// A newly selected group member cannot join the frozen plan implicitly.
	if err := s.DB.Exec("INSERT INTO server_group_members(group_id,server_id) VALUES('managed','controller')").Error; err != nil {
		t.Fatal(err)
	}
	read, err := s.Plan(actor, "controller", view.ID, false)
	if err != nil || len(read.Targets) != 1 || read.Targets[0].ServerID != "dev" {
		t.Fatal("targets changed", err)
	}
	if _, err := s.AuthorizedPlan(view.ID); err != nil {
		t.Fatal("unselected group additions invalidated or expanded plan", err)
	}
	if err := s.DB.Model(&models.Server{}).Where("id='dev'").Update("host", "192.0.2.99").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizedPlan(view.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("changed target address admitted", err)
	}
	if err := s.DB.Model(&models.Server{}).Where("id='dev'").Update("host", "192.0.2.2").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizedPlan(view.ID); err != nil {
		t.Fatal("restored frozen target identity rejected", err)
	}
	if err := s.DB.Where("principal_id=? AND role_id='ansible-approver' AND scope_type='server_group'", approver.User.ID).Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizedPlan(view.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("removed approval authority retained", err)
	}
}
func TestProjectAndPlanCiphertextBindingAndRedaction(t *testing.T) {
	s, a, _, p, r := fixture(t)
	v, err := s.Prepare(a, "controller", p.ID, planInput(r))
	if err != nil {
		t.Fatal(err)
	}
	var row Plan
	if err := s.DB.First(&row, "id=?", v.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{r.BundleEnc, row.ConfigEnc} {
		if strings.Contains(data, "fixture-private") {
			t.Fatal("plaintext persisted")
		}
	}
	for _, scope := range []struct{ kind, id, server, value string }{{"revision", r.ID, "prod", r.BundleEnc}, {"revision", row.ID, "controller", r.BundleEnc}, {"plan", r.ID, "controller", r.BundleEnc}, {"plan", row.ID, "prod", row.ConfigEnc}} {
		if _, err := nexuscrypto.DecryptAnsiblePayload(s.Key, scope.kind, scope.id, scope.server, scope.value); err == nil {
			t.Fatal("cross-purpose or identity ciphertext accepted")
		}
	}
	plain, err := s.Plan(a, "controller", v.ID, true)
	if err != nil || plain.Variables["message"] != "fixture-private-variable" {
		t.Fatal("authorized content unavailable", err)
	}
	if err := s.DB.Where("principal_id=? AND role_id='secret-reader'", a.User.ID).Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.Plan(a, "controller", v.ID, true); !errors.Is(err, ErrDenied) {
		t.Fatal("secret reveal removal ignored", err)
	}
	if _, err := s.Content(a, "controller", p.ID, r.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("code reveal removal ignored", err)
	}
	meta, err := s.Plan(a, "controller", v.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(meta)
	if bytes.Contains(encoded, []byte("fixture-private-variable")) || bytes.Contains(encoded, []byte("configEnc")) || bytes.Contains(encoded, []byte("sourceSession")) || bytes.Contains(encoded, []byte("fingerprint")) {
		t.Fatal("private plan content leaked")
	}
	var events []audit.Event
	s.DB.Find(&events)
	encoded, _ = json.Marshal(events)
	if bytes.Contains(encoded, []byte("fixture-private")) {
		t.Fatal("private automation data entered audit")
	}
}
func TestPlanExpiryMembershipAndSessionLoss(t *testing.T) {
	for _, reason := range []string{"expiry", "membership", "source-session", "approver-session", "archive"} {
		t.Run(reason, func(t *testing.T) {
			s, a, b, p, r := fixture(t)
			v, err := s.Prepare(a, "controller", p.ID, planInput(r))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Approve(b, "controller", v.ID, v.Digest, r.Digest); err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "expiry":
				if err := s.DB.Model(&Plan{}).Where("id=?", v.ID).Update("expires_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
					t.Fatal(err)
				}
			case "membership":
				if err := s.DB.Exec("DELETE FROM server_group_members WHERE group_id='managed' AND server_id='dev'").Error; err != nil {
					t.Fatal(err)
				}
			case "source-session":
				if err := s.Sessions.Revoke(a, a.Session.ID, false); err != nil {
					t.Fatal(err)
				}
			case "approver-session":
				if err := s.Sessions.Revoke(b, b.Session.ID, false); err != nil {
					t.Fatal(err)
				}
			case "archive":
				if err := s.Archive(a, "controller", p.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.AuthorizedPlan(v.ID); err == nil {
				t.Fatal("lost authority admitted", reason)
			}
		})
	}
}
