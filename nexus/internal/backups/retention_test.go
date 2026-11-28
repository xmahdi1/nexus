package backups

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestRetentionRequiresSeparateGrantAndSingleUseCurrentPreview(t *testing.T) {
	r, a, definition := fixture(t, false)
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SaveSettings(a, "server", policy.ID, PolicySettings{KeepLast: 1, VerifyAfterDays: 30}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	code := 0
	preview := models.SupervisedRun{ID: strings.Repeat("b", 32), TaskID: policy.ID, ServerID: "server", ActorID: a.User.ID, SourceSessionID: a.Session.ID, Kind: "scheduled", Action: "backup:retention-preview", OperationContext: policy.Digest, CommandHash: strings.Repeat("e", 64), State: "running", CreatedAt: now.Add(-time.Minute)}
	if err := r.DB.Create(&preview).Error; err != nil {
		t.Fatal(err)
	}
	value := RetentionResult{KeepLast: 1, InventoryDigest: strings.Repeat("d", 64), RemoveIDs: []string{strings.Repeat("c", 64)}, KeptCount: 1}
	encoded, _ := json.Marshal(Result{State: "retention_preview", Verified: true, Retention: &value})
	job := jobsupervisor.NewService(r.DB, r.Key, nil)
	if err := job.Save(preview, jobsupervisor.Snapshot{State: "exited", Verified: true, Empty: true, ExitCode: &code, Output: string(encoded)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StartRetention(a, "server", policy.ID, strings.Repeat("f", 32), "retention-apply", preview.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("ordinary backup grant deleted snapshots", err)
	}
	if err := r.DB.Create(&authorization.Grant{ID: "retention-fixture", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "backup-retention-manager", ScopeType: "server", ScopeID: "server", CreatedBy: a.User.ID, CreatedAt: now}).Error; err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{Service: job}
	r.controller = func(guard func() bool) jobController { controller.Guard = guard; return controller }
	run, err := r.StartRetention(a, "server", policy.ID, strings.Repeat("f", 32), "retention-apply", preview.ID)
	if err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { _, active := activeRuns.Load(localKey{r.DB, run.ID}); return !active })
	if controller.calls.Load() != 1 {
		t.Fatal("cleanup was not admitted once")
	}
	if _, err := r.StartRetention(a, "server", policy.ID, strings.Repeat("f", 32), "retention-apply", preview.ID); err != nil {
		t.Fatal("same request identity lost", err)
	}
	if _, err := r.StartRetention(a, "server", policy.ID, strings.Repeat("1", 32), "retention-apply", preview.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("preview reused with new run", err)
	}
	if err := r.SaveSettings(a, "server", policy.ID, PolicySettings{KeepLast: 2}); err != nil {
		t.Fatal(err)
	}
	if r.Allowed(run) {
		t.Fatal("changed retention rule retained cleanup authority")
	}
	if _, err := r.StartRetention(a, "server", policy.ID, strings.Repeat("2", 32), "retention-apply", preview.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("changed rule accepted old preview", err)
	}
	r.DB.Model(&models.SupervisedRun{}).Where("id=?", preview.ID).Update("finished_at", now.Add(-31*time.Minute))
	if _, err := r.StartRetention(a, "server", policy.ID, strings.Repeat("3", 32), "retention-apply", preview.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("expired preview accepted", err)
	}
}
