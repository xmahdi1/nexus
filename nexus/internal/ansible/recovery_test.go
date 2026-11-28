package ansible

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"time"
)

func TestRecoveryRotationPreservesProjectsAndRevokesApprovalAuthority(t *testing.T) {
	s, a, b, p, r := fixture(t)
	plan, err := s.Prepare(a, "controller", p.ID, planInput(r))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b, "controller", plan.ID, plan.Digest, r.Digest); err != nil {
		t.Fatal(err)
	}
	preset, err := s.CreatePreset(a, "controller", "Recovery selection", plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&authorization.Grant{ID: "recovery-scheduler", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "ansible-scheduler", ScopeType: "server", ScopeID: "controller", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	selected, err := s.PreparePreset(a, "controller", preset.ID, map[string]any{"message": "scheduled-private-value"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := s.CreateSchedule(a, "controller", "Recovery review", selected.ID, 60, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := NewRuntime(s, nil, true).Enqueue(a, "controller", plan.ID, strings.Repeat("e", 32), "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var databases []struct{ Name, File string }
	if err := s.DB.Raw("PRAGMA database_list").Scan(&databases).Error; err != nil {
		t.Fatal(err)
	}
	var source string
	for _, database := range databases {
		if database.Name == "main" {
			source = database.File
		}
	}
	if source == "" {
		t.Fatal("fixture database missing")
	}
	destination := filepath.Join(t.TempDir(), "rotated")
	if err := db.RotateRecoverySet(source, destination, s.Key); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := db.Init(filepath.Join(destination, "nexus.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := rotated.DB()
	defer connection.Close()
	next := &Service{DB: rotated, Key: key, Sessions: auth.NewService(rotated, &config.Config{EncryptionKey: key}), Enabled: true}
	login, err := next.Sessions.Login("owner", "Ansible fixture password", "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := next.Sessions.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := next.Content(reader, "controller", p.ID, r.ID)
	if err != nil || !strings.Contains(bundle.Files[bundle.Main], "fixture-private-playbook") {
		t.Fatal("revision lost", err)
	}
	view, err := next.Plan(reader, "controller", plan.ID, true)
	if err != nil || view.Digest != plan.Digest || view.Variables["message"] != "fixture-private-variable" {
		t.Fatal("plan lost or approval digest changed", err)
	}
	selection, err := next.PresetContent(reader, "controller", preset.ID)
	if err != nil || selection.RevisionID != r.ID {
		t.Fatal("preset lost", err)
	}
	fresh, err := next.PreparePreset(reader, "controller", preset.ID, map[string]any{"message": "fresh after recovery"}, nil)
	if err != nil || fresh.ApprovedBy != "" || fresh.State != "prepared" {
		t.Fatal("recovered preset carried authority", err)
	}
	var paused Schedule
	if err := rotated.First(&paused, "id=?", schedule.ID).Error; err != nil {
		t.Fatal(err)
	}
	if paused.Enabled || paused.LastState != "recovery_copy" {
		t.Fatal("copied schedule retained authority")
	}
	if data, err := next.scheduleConfig(paused); err != nil || data.Variables["message"] != "scheduled-private-value" {
		t.Fatal("schedule configuration lost", err)
	}
	var cancelled QueueEntry
	rotated.First(&cancelled, "id=?", queued.ID)
	if cancelled.State != "cancelled" || cancelled.Detail != "recovery_copy" {
		t.Fatal("copied queue retained authority")
	}
	var original Schedule
	s.DB.First(&original, "id=?", schedule.ID)
	if !original.Enabled {
		t.Fatal("original schedule changed")
	}
	if _, err := next.AuthorizedPlan(plan.ID); err == nil {
		t.Fatal("copied approval retained live session authority")
	}
	if _, err := s.AuthorizedPlan(plan.ID); err != nil {
		t.Fatal("source authority changed", err)
	}
}
