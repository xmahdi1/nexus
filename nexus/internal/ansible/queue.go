package ansible

import (
	"context"
	"errors"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type QueueEntry struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	ServerID        string     `json:"serverId"`
	PlanID          string     `json:"planId"`
	ActorID         string     `json:"actorId"`
	SourceSessionID string     `json:"-"`
	State           string     `json:"state"`
	Detail          string     `json:"detail"`
	AfterRunID      string     `json:"afterRunId,omitempty"`
	NotBefore       time.Time  `json:"notBefore"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	CreatedAt       time.Time  `json:"createdAt"`
	AdmittedAt      *time.Time `json:"admittedAt,omitempty"`
}

func (QueueEntry) TableName() string { return "ansible_queue" }

func (r *Runtime) Queue(a *auth.Access, server string) ([]QueueEntry, error) {
	if err := r.require(a, server, false, "ansible.projects.read", "jobs.read"); err != nil {
		return nil, err
	}
	rows := []QueueEntry{}
	err := r.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	if err == nil {
		err = r.require(a, server, false, "ansible.projects.read", "jobs.read")
	}
	return rows, err
}
func (r *Runtime) Enqueue(a *auth.Access, server, planID, id, after string, notBefore time.Time) (QueueEntry, error) {
	var row QueueEntry
	if !r.Enabled || !r.Supervised {
		return row, ErrDisabled
	}
	if !ValidExecutionID(id) || !idPattern.MatchString(planID) || (after != "" && !ValidExecutionID(after)) {
		return row, ErrInput
	}
	immediate := notBefore.IsZero()
	if immediate {
		notBefore = time.Now().UTC()
	}
	notBefore = notBefore.UTC()
	if err := r.require(a, server, true, "ansible.projects.read", "ansible.playbooks.execute", "jobs.execute", "jobs.read"); err != nil {
		return row, err
	}
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		var existing QueueEntry
		if err := tx.First(&existing, "id=?", id).Error; err == nil {
			if existing.ServerID != server || existing.PlanID != planID || existing.ActorID != a.User.ID || existing.SourceSessionID != a.Session.ID || existing.AfterRunID != after || (!immediate && !existing.NotBefore.Equal(notBefore)) {
				return ErrConflict
			}
			row = existing
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		inside := *r.Service
		inside.DB = tx
		plan, err := inside.AuthorizedPlan(planID)
		if err != nil {
			return err
		}
		if plan.ServerID != server || plan.ActorID != a.User.ID || plan.SourceSessionID != a.Session.ID {
			return ErrDenied
		}
		if notBefore.Before(time.Now().Add(-time.Minute)) || !notBefore.Before(plan.ExpiresAt) {
			return ErrInput
		}
		cfg, err := inside.config(plan)
		if err != nil {
			return err
		}
		if len(cfg.VaultBindings) != 0 {
			return ErrInput
		}
		if after != "" {
			var dependency models.SupervisedRun
			if err := tx.First(&dependency, "id=? AND server_id=? AND kind='ansible'", after, server).Error; err != nil {
				return err
			}
		}
		var count int64
		if err := tx.Table("ansible_run_plans").Where("plan_id=? OR run_id=?", planID, id).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		if err := tx.Model(&QueueEntry{}).Where("plan_id=?", planID).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		if err := tx.Model(&QueueEntry{}).Where("server_id=? AND state='waiting'", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrBusy
		}
		row = QueueEntry{ID: id, ServerID: server, PlanID: planID, ActorID: a.User.ID, SourceSessionID: a.Session.ID, State: "waiting", AfterRunID: after, NotBefore: notBefore, ExpiresAt: plan.ExpiresAt, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.queue.create", id, "waiting", "", a.Session.ID)
	})
	return row, err
}

func queueAdmission(tx *gorm.DB, server, plan, identity, queueID string, a *auth.Access) error {
	var rows []QueueEntry
	if err := tx.Where("plan_id=? OR id=?", plan, identity).Find(&rows).Error; err != nil {
		return err
	}
	if queueID == "" {
		if len(rows) != 0 {
			return ErrConflict
		}
		return nil
	}
	if len(rows) != 1 {
		return ErrConflict
	}
	row := rows[0]
	if row.ID != queueID || identity != queueID || row.PlanID != plan || row.ServerID != server || row.ActorID != a.User.ID || row.SourceSessionID != a.Session.ID || row.State != "waiting" || row.NotBefore.After(time.Now().UTC()) || !row.ExpiresAt.After(time.Now().UTC()) {
		return ErrConflict
	}
	if row.AfterRunID != "" {
		var dependency models.SupervisedRun
		if err := tx.First(&dependency, "id=? AND server_id=? AND kind='ansible'", row.AfterRunID, server).Error; err != nil {
			return err
		}
		if dependency.FinishedAt == nil {
			return ErrBusy
		}
		if dependency.State != "exited" || dependency.ExitCode == nil || *dependency.ExitCode != 0 || dependency.VerifiedAt == nil {
			return ErrDenied
		}
	}
	return nil
}

func (r *Runtime) CancelQueue(a *auth.Access, server, id string) error {
	if !ValidExecutionID(id) {
		return ErrInput
	}
	if err := r.require(a, server, true, "ansible.projects.read", "jobs.cancel"); err != nil {
		return err
	}
	return r.DB.Transaction(func(tx *gorm.DB) error {
		if err := r.require(a, server, true, "ansible.projects.read", "jobs.cancel"); err != nil {
			return err
		}
		result := tx.Model(&QueueEntry{}).Where("id=? AND server_id=? AND state='waiting'", id, server).Updates(map[string]any{"state": "cancelled", "detail": "cancelled_by_user"})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.queue.cancel", id, "cancelled", "", a.Session.ID)
	})
}
func (r *Runtime) blockQueued(row QueueEntry, state, detail string) {
	_ = r.DB.Transaction(func(tx *gorm.DB) error {
		changed := tx.Model(&QueueEntry{}).Where("id=? AND state='waiting'", row.ID).Updates(map[string]any{"state": state, "detail": detail})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected == 0 {
			return nil
		}
		return authorization.New(tx).Record(row.ActorID, "ansible.queue.close", row.ID, state, "", row.SourceSessionID)
	})
}
func (r *Runtime) DrainQueue(ctx context.Context) {
	if !r.Enabled || !r.Supervised || r.Sessions == nil {
		return
	}
	var rows []QueueEntry
	if r.DB.Where("state='waiting'").Order("not_before,created_at,id").Limit(128).Find(&rows).Error != nil {
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		if !row.ExpiresAt.After(time.Now().UTC()) {
			r.blockQueued(row, "expired", "approval_expired")
			continue
		}
		if row.NotBefore.After(time.Now().UTC()) {
			continue
		}
		if _, loaded := r.queueActive.LoadOrStore(row.ID, true); loaded {
			continue
		}
		select {
		case r.queueSlots <- struct{}{}:
			go func(row QueueEntry) {
				defer func() { <-r.queueSlots; r.queueActive.Delete(row.ID) }()
				a, err := r.Sessions.AccessForSession(row.SourceSessionID, row.ActorID)
				if err != nil {
					r.blockQueued(row, "blocked", "source_session_unavailable")
					return
				}
				bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
				defer cancel()
				_, err = r.start(bounded, a, row.ServerID, row.PlanID, row.ID, nil, row.ID)
				if errors.Is(err, ErrDenied) || errors.Is(err, ErrConflict) || errors.Is(err, ErrInput) {
					r.blockQueued(row, "blocked", "approval_or_dependency_changed")
				}
				// Busy and storage failures remain waiting. A created run is already
				// atomically admitted, so no transport outcome can requeue its command.
			}(row)
		default:
			r.queueActive.Delete(row.ID)
			return
		}
	}
}
