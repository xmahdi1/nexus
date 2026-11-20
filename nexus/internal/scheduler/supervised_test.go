package scheduler

import (
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestPreparedSupervisedOrphanNeverDispatches(t *testing.T) {
	s, task := schedulerFixture(t)
	task.Supervised = true
	task.RunID = strings.Repeat("a", 32)
	task.LastStatus = "running"
	if err := s.db.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	run := models.SupervisedRun{ID: task.RunID, TaskID: task.ID, ServerID: task.ServerID, ActorID: task.ActorID, CommandHash: jobsupervisor.Digest(task.Command), State: "prepared", CreatedAt: time.Now().Add(-2 * time.Minute)}
	if err := s.db.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	// No SSH pool is supplied: recovery must resolve the reserved-but-unsubmitted
	// run locally, without contacting a host or replaying its command.
	if s.observeSupervised(task) {
		t.Fatal("orphan remained active")
	}
	if err := s.db.First(&run, "id=?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if run.State != "not_started" || run.FinishedAt == nil || run.DispatchStartedAt != nil || run.InvocationID != "" {
		t.Fatalf("invalid orphan outcome: %+v", run)
	}
	if err := s.db.First(&task, "id=?", task.ID).Error; err != nil {
		t.Fatal(err)
	}
	if task.Enabled || task.RunID != "" || task.LastStatus != "not_started" {
		t.Fatal("orphan schedule was not paused and released")
	}
}

func TestFailedNoDispatchPersistenceRetainsReconciliationIdentity(t *testing.T) {
	s, task := schedulerFixture(t)
	task.Supervised = true
	task.RunID = strings.Repeat("c", 32)
	task.LastStatus = "running"
	if err := s.db.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	// A changed command is a local no-dispatch outcome. Inject a disk-write-like
	// failure while persisting that outcome, after the durable dispatch claim.
	run := models.SupervisedRun{ID: task.RunID, TaskID: task.ID, ServerID: task.ServerID, ActorID: task.ActorID, CommandHash: jobsupervisor.Digest("original command"), State: "prepared", CreatedAt: time.Now().UTC()}
	if err := s.db.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec(`CREATE TRIGGER fail_terminal BEFORE UPDATE ON supervised_runs WHEN NEW.finished_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	s.runSupervised(task, true)
	var stored models.ScheduledTask
	if err := s.db.First(&stored, "id=?", task.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.RunID != run.ID || stored.Enabled || stored.LastStatus != "remote_unknown" {
		t.Fatal("failed result write detached the unresolved run", stored)
	}
	if err := s.db.First(&run, "id=?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if run.FinishedAt != nil || run.DispatchStartedAt == nil {
		t.Fatal("failed terminal write invented completion", run)
	}
}
