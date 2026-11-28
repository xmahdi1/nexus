package scheduler

import (
	"context"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func (s *Scheduler) prepareSupervised(tx *gorm.DB, task models.ScheduledTask) error {
	return tx.Create(&models.SupervisedRun{ID: task.RunID, TaskID: task.ID, ServerID: task.ServerID, ActorID: task.ActorID, CommandHash: jobsupervisor.Digest(task.Command), State: "prepared", CreatedAt: time.Now().UTC()}).Error
}
func (s *Scheduler) reconcileSupervised() {
	var tasks []models.ScheduledTask
	if s.db.Table("scheduled_tasks AS t").Select("t.*").Joins("JOIN supervised_runs r ON r.id=t.run_id").Where("t.supervised=1 AND t.run_id<>''").Order("COALESCE(r.last_checked_at,r.created_at),t.created_at").Limit(128).Find(&tasks).Error != nil {
		return
	}
	for _, task := range tasks {
		var run models.SupervisedRun
		if s.db.First(&run, "id=?", task.RunID).Error != nil {
			continue
		}
		if run.DispatchStartedAt == nil && time.Since(run.CreatedAt) < time.Minute {
			continue
		}
		if _, loaded := s.activeSupervised.LoadOrStore(task.RunID, true); loaded {
			continue
		}
		select {
		case s.reconcileSlots <- struct{}{}:
			go func(task models.ScheduledTask) {
				defer func() { <-s.reconcileSlots; s.activeSupervised.Delete(task.RunID) }()
				s.observeSupervised(task)
			}(task)
		default:
			s.activeSupervised.Delete(task.RunID)
			return
		}
	}
}
func (s *Scheduler) runSupervised(task models.ScheduledTask, start bool) {
	if _, loaded := s.activeSupervised.LoadOrStore(task.RunID, true); loaded {
		return
	}
	defer s.activeSupervised.Delete(task.RunID)
	service := jobsupervisor.NewService(s.db, s.encKey, s.pool)
	service.Guard = func() bool { return permitted(s.db, task) }
	var run models.SupervisedRun
	if s.db.First(&run, "id=? AND task_id=? AND server_id=?", task.RunID, task.ID, task.ServerID).Error != nil {
		return
	}
	if start {
		if !permitted(s.db, task) {
			result := jobsupervisor.Snapshot{State: "not_started", NoDispatch: true, Detail: "execution_authority_changed"}
			if service.Save(run, result) == nil {
				s.finishSupervised(task, result)
			} else {
				s.markSupervisedUnknown(task, "Could not record pre-dispatch denial.")
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result, err := service.Dispatch(ctx, run, task.Command)
		cancel()
		// A no-dispatch observation is actionable only after its durable save
		// succeeds. Otherwise retain the run ID for reconciliation/manual review.
		unconfirmed := result.State == "unknown" || ((result.State == "unsupported" || result.State == "capacity_exceeded") && !result.NoDispatch)
		if err != nil || unconfirmed {
			s.markSupervisedUnknown(task, "Supervisor dispatch is unconfirmed or unsupported; inspect this run before retrying.")
			return
		}
		if result.NoDispatch {
			s.finishSupervised(task, result)
			return
		}
	}
	s.monitorSupervised(task)
}
func (s *Scheduler) monitorSupervised(task models.ScheduledTask) {
	for s.observeSupervised(task) {
		time.Sleep(time.Second)
	}
}
func (s *Scheduler) observeSupervised(task models.ScheduledTask) bool {
	service := jobsupervisor.NewService(s.db, s.encKey, s.pool)
	var run models.SupervisedRun
	if s.db.First(&run, "id=? AND task_id=? AND server_id=?", task.RunID, task.ID, task.ServerID).Error != nil {
		return false
	}
	if s.db.Model(&run).Update("last_checked_at", time.Now().UTC()).Error != nil {
		return false
	}
	if run.DispatchStartedAt == nil && run.State == "prepared" {
		now := time.Now().UTC()
		changed := s.db.Model(&models.SupervisedRun{}).Where("id=? AND dispatch_started_at IS NULL AND state='prepared'", run.ID).Updates(map[string]any{"state": "not_started", "detail": "dispatcher_interrupted_before_submission", "finished_at": now})
		if changed.Error != nil {
			return false
		}
		if changed.RowsAffected == 1 {
			s.finishSupervised(task, jobsupervisor.Snapshot{State: "not_started", NoDispatch: true})
			return false
		}
		return true
	}
	action := "inspect"
	if run.CancelRequestedAt != nil || !permitted(s.db, task) {
		action = "cancel"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result, err := service.Inspect(ctx, run, action)
	cancel()
	if err != nil || result.State == "unknown" {
		s.markSupervisedUnknown(task, "Remote outcome is unknown. The run ID is retained; automatic retry is disabled.")
		return false
	}
	if result.Terminal() {
		s.finishSupervised(task, result)
		return false
	}
	if result.NoDispatch {
		s.finishSupervised(task, result)
		return false
	}
	// Keep monitoring through normal transport reconnects; a failed observation
	// returns to the bounded durable reconciliation loop instead of redispatching.
	return true
}
func (s *Scheduler) markSupervisedUnknown(task models.ScheduledTask, message string) {
	_ = s.db.Transaction(func(tx *gorm.DB) error {
		changed := tx.Model(&models.ScheduledTask{}).Where("id=? AND run_id=? AND (last_status<>'remote_unknown' OR enabled=1)", task.ID, task.RunID).Updates(map[string]any{"last_status": "remote_unknown", "enabled": false, "last_output": message, "lease_until": nil})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected == 0 {
			return nil
		}
		return authorization.New(tx).Record(task.ActorID, "tasks.execute", task.ID, "remote_unknown", task.RunID)
	})
}
func (s *Scheduler) finishSupervised(task models.ScheduledTask, result jobsupervisor.Snapshot) {
	now := time.Now().UTC()
	next := now.Add(time.Duration(max(task.IntervalMinutes, 1)) * time.Minute)
	status := result.State
	if status == "exited" {
		status = "ok"
	}
	output := "Supervised run completed. Open run history for protected output."
	if result.NoDispatch {
		output = "The command was not dispatched. Review run history before enabling this task."
	}
	if result.State == "interrupted" {
		output = "Managed processes stopped without a complete command result. Inspect side effects before enabling this task."
	}
	_ = s.db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{"last_run_at": now, "next_run_at": next, "last_status": status, "last_output": output, "run_id": "", "lease_until": nil}
		var run models.SupervisedRun
		if err := tx.First(&run, "id=?", task.RunID).Error; err != nil {
			return err
		}
		if run.CancelRequestedAt != nil {
			updates["enabled"] = false
		}
		if result.State == "cancelled" || result.State == "timed_out" || result.State == "interrupted" || result.NoDispatch || result.State == "unsupported" || result.State == "capacity_exceeded" || !permitted(tx, task) {
			updates["enabled"] = false
		}
		changed := tx.Model(&models.ScheduledTask{}).Where("id=? AND run_id=?", task.ID, task.RunID).Updates(updates)
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected == 0 {
			return nil
		}
		return authorization.New(tx).Record(task.ActorID, "tasks.execute", task.ID, status, task.RunID)
	})
	// Persisted encrypted output/terminal identity precede best-effort release.
	var run models.SupervisedRun
	if result.Terminal() && s.db.First(&run, "id=?", task.RunID).Error == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = jobsupervisor.NewService(s.db, s.encKey, s.pool).Inspect(ctx, run, "release")
	}
}
