package ansible

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

type queuedFixtureJob struct {
	*jobsupervisor.Service
	calls atomic.Int32
}

func (j *queuedFixtureJob) DispatchAnsible(_ context.Context, run models.SupervisedRun, _ string, _ []byte, _ int) (jobsupervisor.Snapshot, error) {
	now := time.Now().UTC()
	if err := j.DB.Model(&run).Update("dispatch_started_at", now).Error; err != nil {
		return jobsupervisor.Snapshot{}, err
	}
	snapshot := jobsupervisor.Snapshot{State: "unknown"}
	err := j.Save(run, snapshot)
	j.calls.Add(1)
	if err != nil {
		return snapshot, err
	}
	return snapshot, errors.New("lost acknowledgement")
}
func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(4 * time.Second)
	for time.Now().Before(until) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("queue condition did not settle")
}

func TestQueueWaitsForHostsAndNeverReplaysAnAdmittedCommand(t *testing.T) {
	s, a, b, p, rev := fixture(t)
	plan, err := s.Prepare(a, "controller", p.ID, planInput(rev))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Approve(b, "controller", plan.ID, plan.Digest, rev.Digest); err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(s, nil, true)
	job := &queuedFixtureJob{Service: jobsupervisor.NewService(s.DB, s.Key, nil)}
	runtime.controller = func(guard func() bool) jobController { job.Guard = guard; return job }
	runtime.input = func(context.Context, Plan, string, map[string]string) ([]byte, error) {
		return []byte("fixture-only"), nil
	}
	busy := models.SupervisedRun{ID: strings.Repeat("b", 32), Kind: "operation", ServerID: "controller", ActorID: a.User.ID, State: "running", CreatedAt: time.Now().UTC()}
	if err = s.DB.Create(&busy).Error; err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	entry, err := runtime.Enqueue(a, "controller", plan.ID, id, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if same, err := runtime.Enqueue(a, "controller", plan.ID, id, "", time.Time{}); err != nil || same.ID != entry.ID {
		t.Fatal("identical enqueue lost identity", err)
	}
	if _, err = runtime.Start(context.Background(), a, "controller", plan.ID, strings.Repeat("c", 32), nil); !errors.Is(err, ErrConflict) {
		t.Fatal("direct execution bypassed queue", err)
	}
	runtime.DrainQueue(context.Background())
	waitUntil(t, func() bool { _, active := runtime.queueActive.Load(id); return !active })
	if job.calls.Load() != 0 {
		t.Fatal("busy host dispatched")
	}
	now := time.Now().UTC()
	s.DB.Model(&busy).Update("finished_at", now)
	waitUntil(t, func() bool { runtime.DrainQueue(context.Background()); return job.calls.Load() == 1 })
	waitUntil(t, func() bool { _, active := runtime.queueActive.Load(id); return !active })
	var current QueueEntry
	if err = s.DB.First(&current, "id=?", id).Error; err != nil || current.State != "admitted" {
		t.Fatal("admission not durable", err, current.State)
	}
	runtime.DrainQueue(context.Background())
	runtime.DrainQueue(context.Background())
	if job.calls.Load() != 1 {
		t.Fatal("unknown submission replayed")
	}
	if err = runtime.CancelQueue(a, "controller", id); !errors.Is(err, ErrConflict) {
		t.Fatal("admitted command silently requeued/cancelled", err)
	}
}

func TestQueueRechecksDelayExpiryAuthorityAndDependency(t *testing.T) {
	for _, reason := range []string{"delay", "expiry", "authority", "dependency"} {
		t.Run(reason, func(t *testing.T) {
			s, a, b, p, rev := fixture(t)
			plan, err := s.Prepare(a, "controller", p.ID, planInput(rev))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Approve(b, "controller", plan.ID, plan.Digest, rev.Digest); err != nil {
				t.Fatal(err)
			}
			runtime := NewRuntime(s, nil, true)
			job := &queuedFixtureJob{Service: jobsupervisor.NewService(s.DB, s.Key, nil)}
			runtime.controller = func(guard func() bool) jobController { job.Guard = guard; return job }
			runtime.input = func(context.Context, Plan, string, map[string]string) ([]byte, error) { return []byte("unused"), nil }
			due := time.Time{}
			after := ""
			if reason == "delay" {
				due = time.Now().Add(5 * time.Minute)
			}
			if reason == "dependency" {
				after = strings.Repeat("d", 32)
				now := time.Now().UTC()
				code := 1
				if err := s.DB.Create(&models.SupervisedRun{ID: after, Kind: "ansible", ServerID: "controller", ActorID: a.User.ID, State: "failed", ExitCode: &code, FinishedAt: &now, VerifiedAt: &now, CreatedAt: now}).Error; err != nil {
					t.Fatal(err)
				}
			}
			entry, err := runtime.Enqueue(a, "controller", plan.ID, strings.Repeat("e", 32), after, due)
			if err != nil {
				t.Fatal(err)
			}
			if reason == "expiry" {
				s.DB.Model(&entry).Update("expires_at", time.Now().Add(-time.Second))
			}
			if reason == "authority" {
				s.DB.Where("principal_id=? AND role_id='ansible-approver'", b.User.ID).Delete(&authorization.Grant{})
			}
			runtime.DrainQueue(context.Background())
			if reason == "delay" {
				time.Sleep(60 * time.Millisecond)
			} else {
				waitUntil(t, func() bool {
					var row QueueEntry
					s.DB.First(&row, "id=?", entry.ID)
					return row.State == "blocked" || row.State == "expired"
				})
			}
			if job.calls.Load() != 0 {
				t.Fatal("ineligible command dispatched")
			}
		})
	}
}

func TestRecurringSchedulesCreateFreshReviewPlansAndPauseOnRevocation(t *testing.T) {
	s, a, _, p, rev := fixture(t)
	base, err := s.Prepare(a, "controller", p.ID, planInput(rev))
	if err != nil {
		t.Fatal(err)
	}
	preset, err := s.CreatePreset(a, "controller", "Checks", base.ID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := s.PreparePreset(a, "controller", preset.ID, map[string]any{"message": "private-scheduled-value"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSchedule(a, "controller", "Daily checks", seed.ID, 1440, time.Time{}); !errors.Is(err, ErrDenied) {
		t.Fatal("implicit recurring authority", err)
	}
	if err = s.DB.Create(&authorization.Grant{ID: "scheduler-fixture", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "ansible-scheduler", ScopeType: "server", ScopeID: "controller", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	schedule, err := s.CreateSchedule(a, "controller", "Daily checks", seed.ID, 1440, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(schedule)
	if strings.Contains(string(public), "private-scheduled-value") || strings.Contains(string(public), "configEnc") {
		t.Fatal("scheduled values leaked")
	}
	runtime := NewRuntime(s, nil, true)
	runtime.TickSchedules(context.Background())
	var first Schedule
	s.DB.First(&first, "id=?", schedule.ID)
	if first.PendingPlanID == "" || first.PendingPlanID == seed.ID || first.LastState != "awaiting_review" {
		t.Fatal("schedule did not create a fresh plan", first)
	}
	view, err := s.Plan(a, "controller", first.PendingPlanID, true)
	if err != nil || view.State != "prepared" || view.ApprovedBy != "" || view.Variables["message"] != "private-scheduled-value" {
		t.Fatal("new review lost input or inherited approval", err)
	}
	s.DB.Model(&first).Update("next_at", time.Now().Add(-time.Second))
	runtime.TickSchedules(context.Background())
	var held Schedule
	s.DB.First(&held, "id=?", schedule.ID)
	if held.PendingPlanID != first.PendingPlanID {
		t.Fatal("duplicate pending plans generated")
	}
	s.DB.Where("id=?", "scheduler-fixture").Delete(&authorization.Grant{})
	s.DB.Model(&first).Update("next_at", time.Now().Add(-time.Second))
	runtime.TickSchedules(context.Background())
	s.DB.First(&held, "id=?", schedule.ID)
	if held.Enabled || held.LastState != "authority_changed" {
		t.Fatal("revoked schedule stayed active", held)
	}
}
