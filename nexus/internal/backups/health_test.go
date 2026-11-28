package backups

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/models"
)

func TestHealthAlertsDeduplicateResolveAndRespectScope(t *testing.T) {
	r, a, definition := fixture(t, false)
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SaveSettings(a, "server", policy.ID, PolicySettings{KeepLast: 7, MaxAgeMinutes: 60, VerifyAfterDays: 1}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	past := now.Add(-48 * time.Hour)
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("created_at", past)
	failed := models.SupervisedRun{ID: strings.Repeat("b", 32), TaskID: policy.ID, ServerID: "server", Kind: "scheduled", Action: "backup:backup", State: "failed", CreatedAt: past, FinishedAt: &past}
	if err := r.DB.Create(&failed).Error; err != nil {
		t.Fatal(err)
	}
	r.SweepHealth(now)
	r.SweepHealth(now.Add(time.Minute))
	report, err := r.Health(a, "server")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Alerts) != 2 {
		t.Fatal("expected distinct failure and overdue alerts", len(report.Alerts))
	}
	for _, alert := range report.Alerts {
		if alert.State != "open" || !alert.FirstSeenAt.Equal(now) || !alert.LastSeenAt.Equal(now.Add(time.Minute)) {
			t.Fatal("alert duplicated or first observation lost")
		}
	}
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Updates(map[string]any{"last_success_at": now.Add(2 * time.Minute), "last_restore_at": now.Add(2 * time.Minute)})
	r.SweepHealth(now.Add(3 * time.Minute))
	report, err = r.Health(a, "server")
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range report.Alerts {
		if alert.State != "resolved" || alert.ResolvedAt == nil {
			t.Fatal("successful backup did not resolve previous issue")
		}
	}
	if other, err := r.Health(a, "other"); (err != nil && !errors.Is(err, ErrDenied)) || len(other.Policies) != 0 || len(other.Alerts) != 0 {
		t.Fatal("other scope leaked alerts", err)
	}
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("last_restore_at", past)
	r.SweepHealth(now.Add(4 * time.Minute))
	report, err = r.Health(a, "server")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, alert := range report.Alerts {
		if alert.Code == "restore_overdue" && alert.State == "open" {
			found = true
		}
	}
	if !found {
		t.Fatal("stale restore check not reported")
	}
	if err := r.Archive(a, "server", policy.ID); err != nil {
		t.Fatal(err)
	}
	r.SweepHealth(now.Add(5 * time.Minute))
	report, err = r.Health(a, "server")
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range report.Alerts {
		if alert.State == "open" {
			t.Fatal("archived policy retained active alert")
		}
	}
}

func TestCoverageDoesNotTreatLiveDatabaseFilesAsDatabaseExports(t *testing.T) {
	r, a, definition := fixture(t, false)
	definition.Sources = []Source{{Kind: "files", Label: "Application", Path: "/srv/app"}}
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	discovery := Discovery{Sources: []Candidate{
		{ID: "files", Source: Source{Kind: "files", Label: "Uploads", Path: "/srv/app/uploads"}, State: "ready"},
		{ID: "db", Source: Source{Kind: "postgres", Label: "Database", ContainerID: strings.Repeat("b", 64), Database: Database{Password: "must-not-persist"}}, State: "needs_setup"},
		{ID: "plugin", Source: Source{Kind: "docker-volume", Volume: "plugin", Label: "Plugin"}, State: "unsupported"},
	}}
	coverage, err := r.coverageFrom("server", discovery, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Items[0].State != "configured" || coverage.Items[1].State != "unprotected" || coverage.Items[2].State != "unsupported" {
		t.Fatal("incorrect source coverage", coverage.Items)
	}
	encoded, _ := json.Marshal(coverage)
	if strings.Contains(string(encoded), "must-not-persist") {
		t.Fatal("coverage persisted credentials")
	}
	scan := coverageScan{ScopeID: "server", ScannedAt: now, WatchGaps: true, ReportJSON: string(encoded)}
	if err := r.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("last_success_at", now)
	report, err := r.Health(a, "server")
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.Items[0].State != "backed_up" {
		t.Fatal("coverage did not use latest successful backup")
	}
	issues, err := coverageIssues(scan, now.Add(25*time.Hour))
	if err != nil || len(issues) != 1 || issues[0].Code != "coverage_stale" {
		t.Fatal("stale scan treated as current coverage", issues, err)
	}
	if err := r.Archive(a, "server", policy.ID); err != nil {
		t.Fatal(err)
	}
	report, err = r.Health(a, "server")
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.Items[0].State != "unprotected" {
		t.Fatal("archived policy still protected discovered source")
	}
}

func TestFutureOneTimeBackupIsNotOverdueOrPausedAfterAdmission(t *testing.T) {
	r, a, definition := fixture(t, false)
	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	definition.Timing = Timing{Mode: "once", At: &future}
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("created_at", now.Add(-48*time.Hour))
	var row Policy
	r.DB.First(&row, "id=?", policy.ID)
	health, err := r.policyHealth(row, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range health.Issues {
		if issue.Code == "backup_overdue" {
			t.Fatal("future first backup reported overdue")
		}
	}
	row.Enabled = false
	row.NextAt = nil
	row.LastState = "prepared"
	health, err = r.policyHealth(row, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range health.Issues {
		if issue.Code == "schedule_paused" {
			t.Fatal("admitted one-time backup reported paused")
		}
	}
}
