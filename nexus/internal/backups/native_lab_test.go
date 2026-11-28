package backups

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestNativeNexusBackupRestoreAndMatchingRecoveryKey(t *testing.T) {
	binary := os.Getenv("NEXUS_BACKUP_LAB_RESTIC")
	if binary == "" {
		t.Skip("set NEXUS_BACKUP_LAB_RESTIC to the pinned local fixture binary")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute fixture path required")
	}
	r, a, definition := fixture(t, true)
	if err := privateDirectory(r.WorkRoot); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(r.WorkRoot, "tools")
	if err := privateDirectory(tools); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "restic-0.20.0"), content, 0500); err != nil {
		t.Fatal(err)
	}
	policy, err := r.Create(a, "", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot string
	for index, action := range []string{"install", "init", "backup", "snapshots", "check", "restore", "verify"} {
		id := strings.Repeat(string(rune('b'+index)), 32)
		// IDs remain hexadecimal for every operation.
		if index >= 5 {
			id = strings.Repeat(string(rune('1'+index-5)), 32)
		}
		run, err := r.Start(a, "", policy.ID, id, action, snapshot)
		if err != nil {
			t.Fatal(action, err)
		}
		waitNative(t, func() bool {
			current, e := r.Get("", run.ID)
			_, active := activeRuns.Load(localKey{r.DB, run.ID})
			return e == nil && current.FinishedAt != nil && !active
		})
		current, err := r.Get("", run.ID)
		if err != nil || current.State != "exited" {
			t.Fatal(action, "did not finish", err, current.State, current.Detail)
		}
		observation, err := r.controller(func() bool { return false }).Cached(current)
		if err != nil {
			t.Fatal(err)
		}
		result := parseResult(observation.Output, r.WorkRoot, policy.ID, id)
		if result == nil {
			t.Fatal("structured result unavailable", action)
		}
		if action == "backup" {
			snapshot = result.SnapshotID
			if !snapshotPattern.MatchString(snapshot) {
				t.Fatal("backup missing snapshot")
			}
		}
		if action == "restore" {
			if !result.Verified || result.RestorePath == "" {
				t.Fatal("restore not verified")
			}
			var recoveredDB, keyFile string
			err = filepath.WalkDir(result.RestorePath, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.Name() == "nexus.db" {
					recoveredDB = path
				}
				if entry.Name() == "encryption-key.base64" {
					keyFile = path
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if recoveredDB == "" || keyFile == "" {
				t.Fatal("recovery pair missing")
			}
			encoded, err := os.ReadFile(keyFile)
			if err != nil {
				t.Fatal(err)
			}
			key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := db.Init(recoveredDB, key)
			if err != nil {
				t.Fatal("matching key failed", err)
			}
			var sessions, enabled int64
			recovered.Table("auth_sessions").Count(&sessions)
			recovered.Table("backup_policies").Where("enabled=1").Count(&enabled)
			sql, _ := recovered.DB()
			sql.Close()
			if sessions != 0 || enabled != 0 {
				t.Fatal("recovery copy kept runtime authority")
			}
		}
	}
	if err := r.SaveSettings(a, "", policy.ID, PolicySettings{KeepLast: 1, VerifyAfterDays: 30}); err != nil {
		t.Fatal(err)
	}
	if err := r.DB.Create(&authorization.Grant{ID: "native-retention-role", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "backup-retention-manager", ScopeType: "global", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	awaitResult := func(run models.SupervisedRun) *Result {
		t.Helper()
		waitNative(t, func() bool {
			row, err := r.Get("", run.ID)
			_, active := activeRuns.Load(localKey{r.DB, run.ID})
			return err == nil && row.FinishedAt != nil && !active
		})
		row, err := r.Get("", run.ID)
		if err != nil || row.State != "exited" {
			t.Fatal("native retention operation failed", row.State, err)
		}
		observation, err := r.controller(func() bool { return false }).Cached(row)
		if err != nil {
			t.Fatal(err)
		}
		parsed := parseResult(observation.Output, r.WorkRoot, policy.ID, run.ID)
		if parsed == nil {
			t.Fatal("native retention result missing")
		}
		return parsed
	}
	second, err := r.Start(a, "", policy.ID, strings.Repeat("4", 32), "backup", "")
	if err != nil {
		t.Fatal(err)
	}
	awaitResult(second)
	preview, err := r.StartRetention(a, "", policy.ID, strings.Repeat("5", 32), "retention-preview", "")
	if err != nil {
		t.Fatal(err)
	}
	plan := awaitResult(preview)
	if plan.Retention == nil || len(plan.Retention.RemoveIDs) != 1 {
		t.Fatal("native retention preview did not select one old successful snapshot", plan)
	}
	apply, err := r.StartRetention(a, "", policy.ID, strings.Repeat("6", 32), "retention-apply", preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result := awaitResult(apply); result.State != "retention_applied" {
		t.Fatal("native retention did not apply", result)
	}
	list, err := r.Start(a, "", policy.ID, strings.Repeat("7", 32), "snapshots", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(awaitResult(list).Snapshots) != 1 {
		t.Fatal("native retention did not preserve exactly one snapshot")
	}
	rows, err := r.Policies(a, "")
	if err != nil || len(rows) != 1 || rows[0].LastSuccessAt == nil || rows[0].LastCheckAt == nil || rows[0].LastRestoreAt == nil {
		t.Fatal("backup/check/restore timestamps missing", err)
	}
	bytes, _ := json.Marshal(rows)
	if strings.Contains(string(bytes), definition.Repository.Password) {
		t.Fatal("repository password leaked")
	}
	var count int64
	r.DB.Model(&models.SupervisedRun{}).Where("server_id=? AND finished_at IS NULL", LocalHost).Count(&count)
	if count != 0 {
		t.Fatal("completed local job retained reservation")
	}
	if !a.AuthorizedNow() {
		t.Fatal("backup revoked the original login")
	}
}
func waitNative(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(40 * time.Second)
	for time.Now().Before(until) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("native backup did not settle")
}
