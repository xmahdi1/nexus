package backups

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestOneTimeBackupSurvivesSignOutWithoutDuplicateAdmission(t *testing.T) {
	r, a, definition := fixture(t, false)
	at := time.Now().UTC().Add(time.Minute)
	definition.Timing = Timing{Mode: "once", At: &at}
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("last_check_at", time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(a, "server", policy.ID, true); err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{Service: jobsupervisor.NewService(r.DB, r.Key, nil)}
	r.controller = func(guard func() bool) jobController { controller.Guard = guard; return controller }
	if err := r.DB.Exec("DELETE FROM auth_sessions").Error; err != nil {
		t.Fatal(err)
	}
	if a.AuthorizedNow() {
		t.Fatal("fixture did not sign out")
	}
	if err := r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("next_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	r.Tick(context.Background())
	wait(t, func() bool { return controller.calls.Load() == 1 })
	var run models.SupervisedRun
	if err := r.DB.First(&run, "task_id=?", policy.ID).Error; err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { _, active := activeRuns.Load(localKey{r.DB, run.ID}); return !active })
	for range 3 {
		r.Tick(context.Background())
	}
	var count int64
	r.DB.Model(&models.SupervisedRun{}).Where("task_id=?", policy.ID).Count(&count)
	var current Policy
	r.DB.First(&current, "id=?", policy.ID)
	if count != 1 || current.Enabled || current.NextAt != nil || run.SourceSessionID != "" || !r.Allowed(run) {
		t.Fatal("one-time durable authority or single admission lost", count, current.Enabled)
	}
	login, err := r.Sessions.Login("owner", "Backup fixture password only", "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err = r.Sessions.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(a, "server", policy.ID, false); err != nil || r.Allowed(run) {
		t.Fatal("pause retained scheduled authority", err)
	}
}

func TestChangedHostCannotReceiveBackupControls(t *testing.T) {
	r, a, definition := fixture(t, false)
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{Service: jobsupervisor.NewService(r.DB, r.Key, nil)}
	r.controller = func(guard func() bool) jobController { controller.Guard = guard; return controller }
	run, err := r.Start(a, "server", policy.ID, strings.Repeat("b", 32), "backup", "")
	if err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { _, active := activeRuns.Load(localKey{r.DB, run.ID}); return !active })
	if err := r.DB.Model(&models.Server{}).Where("id='server'").Update("host", "192.0.2.2").Error; err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"inspect", "cancel", "release"} {
		if _, _, err := r.Observe(context.Background(), a, "server", run.ID, action); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s followed substituted host: %v", action, err)
		}
	}
}

func TestLocalOrphanRequiresOwnerAndProcessGroupProof(t *testing.T) {
	r, _, _ := fixture(t, true)
	run := models.SupervisedRun{ID: strings.Repeat("a", 32), CommandHash: strings.Repeat("b", 64)}
	receipt := localReceipt{RunID: run.ID, Hash: run.CommandHash, OwnerPID: os.Getpid(), OwnerStart: processStart(os.Getpid()), Namespace: processNamespace()}
	check := func(wantOwner, wantEmpty, wantNoDispatch bool) {
		t.Helper()
		if err := r.writeReceipt(run, receipt); err != nil {
			t.Fatal(err)
		}
		owner, empty, noDispatch := r.localOrphan(run)
		if owner != wantOwner || empty != wantEmpty || noDispatch != wantNoDispatch {
			t.Fatal("incorrect orphan proof", owner, empty, noDispatch)
		}
	}
	check(true, false, false)
	receipt.OwnerStart = "different-process-instance"
	check(false, true, true)
	child := exec.Command("sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	receipt.PID = child.Process.Pid
	check(false, false, false)
	_ = child.Process.Kill()
	_ = child.Wait()
	check(false, true, false)
	receipt.Namespace = "other-namespace"
	check(false, false, false)
	receipt.Namespace = processNamespace()
	receipt.OwnerStart = ""
	check(false, false, false)
}

func TestInspectingOldFailureCannotPauseResumedSchedule(t *testing.T) {
	r, a, definition := fixture(t, false)
	definition.Timing = Timing{Mode: "interval", IntervalMinutes: 60}
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	run := models.SupervisedRun{ID: strings.Repeat("b", 32), TaskID: policy.ID, ServerID: "server", ActorID: a.User.ID, Kind: "scheduled", Action: "backup:backup", CommandHash: strings.Repeat("c", 64), State: "running", CreatedAt: time.Now().UTC()}
	if err := r.DB.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	r.DB.Exec("INSERT INTO backup_run_cleanup(run_id)VALUES(?)", run.ID)
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Updates(map[string]any{"last_run_id": run.ID, "last_check_at": time.Now().UTC()})
	code := 1
	if err := r.controller(func() bool { return false }).Save(run, jobsupervisor.Snapshot{State: "failed", Verified: true, Empty: true, ExitCode: &code}); err != nil {
		t.Fatal(err)
	}
	if err := r.finish(run.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(a, "server", policy.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := r.finish(run.ID); err != nil {
		t.Fatal(err)
	}
	var current Policy
	r.DB.First(&current, "id=?", policy.ID)
	if !current.Enabled || current.LastState != "scheduled" {
		t.Fatal("old failure changed resumed schedule")
	}
}
