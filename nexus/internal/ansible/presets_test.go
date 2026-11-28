package ansible

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func TestPresetsCreateFreshPlansWithoutValuesOrApproval(t *testing.T) {
	s, a, b, p, r := fixture(t)
	original, err := s.Prepare(a, "controller", p.ID, planInput(r))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Approve(b, "controller", original.ID, original.Digest, r.Digest); err != nil {
		t.Fatal(err)
	}
	preset, err := s.CreatePreset(a, "controller", "Check selected targets", original.ID)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(preset)
	if strings.Contains(string(public), "fixture-private-variable") || strings.Contains(string(public), "configEnc") {
		t.Fatal("preset metadata leaked content")
	}
	var selection PresetSelection
	if err = s.open("preset", preset.ID, "controller", preset.ConfigEnc, preset.Digest, &selection); err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(selection)
	if strings.Contains(string(plain), "fixture-private-variable") || strings.Contains(string(plain), "approvedBy") || selection.Options.VaultPassword != nil {
		t.Fatal("preset copied values or authority")
	}
	if _, err = s.PreparePreset(a, "controller", preset.ID, nil, nil); !errors.Is(err, ErrInput) {
		t.Fatal("required input reused", err)
	}
	next, err := s.PreparePreset(a, "controller", preset.ID, map[string]any{"message": "fresh-value"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if next.ID == original.ID || next.State != "prepared" || next.ApprovedBy != "" || next.PresetID != preset.ID || len(next.Targets) != 1 || next.Targets[0].ServerID != "dev" {
		t.Fatal("selection or independent authority lost", next)
	}
	revealed, err := s.Plan(a, "controller", next.ID, true)
	if err != nil || revealed.Variables["message"] != "fresh-value" {
		t.Fatal("fresh input lost", err)
	}
	if _, err = s.AuthorizedPlan(next.ID); err == nil {
		t.Fatal("preset inherited approval")
	}
	if _, err = s.Approve(a, "controller", next.ID, next.Digest, r.Digest); !errors.Is(err, ErrConflict) {
		t.Fatal("self approval admitted", err)
	}
	if _, err = s.Approve(b, "controller", next.ID, next.Digest, r.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizedPlan(next.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.ArchivePreset(a, "controller", preset.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreparePreset(a, "controller", preset.ID, map[string]any{"message": "other"}, nil); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatal("archived preset reused", err)
	}
	if _, err = s.AuthorizedPlan(next.ID); err != nil {
		t.Fatal("archiving selection changed frozen approval", err)
	}
}

func TestPresetUseRechecksScopeMembershipAndContentBinding(t *testing.T) {
	s, a, b, p, r := fixture(t)
	plan, err := s.Prepare(a, "controller", p.ID, planInput(r))
	if err != nil {
		t.Fatal(err)
	}
	preset, err := s.CreatePreset(a, "controller", "Scoped selection", plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreatePreset(b, "controller", "Other actor", plan.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("another actor copied plan", err)
	}
	if _, err = s.PresetContent(a, "dev", preset.ID); err == nil {
		t.Fatal("controller substitution admitted")
	}
	s.DB.Model(&Preset{}).Where("id=?", preset.ID).Update("name", "Changed metadata")
	if _, err = s.PresetContent(a, "controller", preset.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("metadata substitution admitted", err)
	}
	s.DB.Model(&Preset{}).Where("id=?", preset.ID).Update("name", preset.Name)
	s.DB.Exec("DELETE FROM server_group_members WHERE server_id='dev' AND group_id='managed'")
	if _, err = s.PreparePreset(a, "controller", preset.ID, map[string]any{"message": "new"}, nil); err == nil {
		t.Fatal("removed target remained eligible")
	}
	s.DB.Exec("INSERT INTO server_group_members(group_id,server_id)VALUES('managed','dev')")
	s.DB.Exec("DELETE FROM role_permissions WHERE role_id='ansible-executor' AND permission_key='ansible.playbooks.execute'")
	if _, err = s.PreparePreset(a, "controller", preset.ID, map[string]any{"message": "new"}, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked execution still prepared", err)
	}
}
