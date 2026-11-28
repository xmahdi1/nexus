package ansible

import (
	"context"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type Schedule struct {
	ID              string    `gorm:"primaryKey" json:"id"`
	ServerID        string    `json:"serverId"`
	Name            string    `json:"name"`
	PresetID        string    `json:"presetId"`
	ActorID         string    `json:"actorId"`
	SourceSessionID string    `json:"-"`
	ConfigEnc       string    `json:"-"`
	Digest          string    `json:"-"`
	IntervalMinutes int       `json:"intervalMinutes"`
	NextAt          time.Time `json:"nextAt"`
	Enabled         bool      `json:"enabled"`
	PendingPlanID   string    `json:"pendingPlanId,omitempty"`
	LastState       string    `json:"lastState"`
	CreatedAt       time.Time `json:"createdAt"`
}

func (Schedule) TableName() string { return "ansible_schedules" }

type scheduleData struct {
	Name            string          `json:"name"`
	PresetID        string          `json:"presetId"`
	IntervalMinutes int             `json:"intervalMinutes"`
	Variables       map[string]any  `json:"variables"`
	VaultPassword   *VaultReference `json:"vaultPassword,omitempty"`
}

func (s *Service) Schedules(a *auth.Access, server string) ([]Schedule, error) {
	if err := s.require(a, server, false, "ansible.projects.read"); err != nil {
		return nil, err
	}
	rows := []Schedule{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	if err == nil {
		err = s.require(a, server, false, "ansible.projects.read")
	}
	return rows, err
}

// Recurrence creates plans for independent review, never reusable approval.
func (s *Service) CreateSchedule(a *auth.Access, server, name, planID string, interval int, first time.Time) (Schedule, error) {
	var row Schedule
	name = strings.TrimSpace(name)
	now := time.Now().UTC()
	if first.IsZero() {
		first = now
	}
	first = first.UTC()
	if name == "" || !safeText(name, 80) || strings.Contains(name, "\n") || !idPattern.MatchString(planID) || interval < 15 || interval > 43200 || first.Before(now.Add(-time.Minute)) || first.After(now.AddDate(1, 0, 0)) {
		return row, ErrInput
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.read", "ansible.schedules.manage", "secrets.create", "secrets.use"); err != nil {
			return err
		}
		var plan Plan
		if err := tx.First(&plan, "id=? AND server_id=?", planID, server).Error; err != nil {
			return err
		}
		cfg, err := inside.config(plan)
		if err != nil {
			return err
		}
		if err := inside.sourceAllowed(a, cfg); err != nil {
			return err
		}
		if cfg.PresetID == "" {
			return ErrInput
		}
		if _, err := inside.preset(server, cfg.PresetID); err != nil {
			return err
		}
		id, err := audit.NewID()
		if err != nil {
			return err
		}
		data := scheduleData{Name: name, PresetID: cfg.PresetID, IntervalMinutes: interval, Variables: cfg.Variables, VaultPassword: cfg.Options.VaultPassword}
		sealed, digest, err := inside.seal("schedule", id, server, data)
		if err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&Schedule{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrInput
		}
		row = Schedule{ID: id, ServerID: server, Name: name, PresetID: cfg.PresetID, ActorID: a.User.ID, SourceSessionID: a.Session.ID, ConfigEnc: sealed, Digest: digest, IntervalMinutes: interval, NextAt: first, Enabled: true, LastState: "scheduled", CreatedAt: now}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.schedule.create", id, "scheduled", "", a.Session.ID)
	})
	return row, err
}
func (s *Service) scheduleConfig(row Schedule) (scheduleData, error) {
	var data scheduleData
	if err := s.open("schedule", row.ID, row.ServerID, row.ConfigEnc, row.Digest, &data); err != nil {
		return data, err
	}
	if data.Name != row.Name || data.PresetID != row.PresetID || data.IntervalMinutes != row.IntervalMinutes || data.IntervalMinutes < 15 || data.IntervalMinutes > 43200 {
		return scheduleData{}, ErrConflict
	}
	return data, nil
}
func (s *Service) SetSchedule(a *auth.Access, server, id string, enabled bool) error {
	if !idPattern.MatchString(id) {
		return ErrInput
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.read", "ansible.schedules.manage"); err != nil {
			return err
		}
		var row Schedule
		if err := tx.First(&row, "id=? AND server_id=?", id, server).Error; err != nil {
			return err
		}
		updates := map[string]any{"enabled": false, "last_state": "paused"}
		if enabled {
			if row.ActorID != a.User.ID {
				return ErrDenied
			}
			if err := inside.require(a, server, true, "ansible.playbooks.execute", "secrets.use"); err != nil {
				return err
			}
			if _, err := inside.scheduleConfig(row); err != nil {
				return err
			}
			if _, err := inside.preset(server, row.PresetID); err != nil {
				return err
			}
			// Old plans keep their own authority/expiry and are never rebound.
			updates = map[string]any{"enabled": true, "source_session_id": a.Session.ID, "next_at": time.Now().UTC(), "last_state": "scheduled"}
		}
		if err := tx.Model(&row).Updates(updates).Error; err != nil {
			return err
		}
		state := "paused"
		if enabled {
			state = "scheduled"
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.schedule.change", id, state, "", a.Session.ID)
	})
}
func (r *Runtime) TickSchedules(ctx context.Context) {
	if !r.Enabled || r.Sessions == nil {
		return
	}
	var rows []Schedule
	if r.DB.Where("enabled=1 AND julianday(next_at)<=julianday(?)", time.Now().UTC()).Order("julianday(next_at),id").Limit(32).Find(&rows).Error != nil {
		return
	}
	for _, candidate := range rows {
		if ctx.Err() != nil {
			return
		}
		_ = r.DB.Transaction(func(tx *gorm.DB) error {
			var row Schedule
			if err := tx.First(&row, "id=? AND enabled=1 AND julianday(next_at)<=julianday(?)", candidate.ID, time.Now().UTC()).Error; err != nil {
				return err
			}
			inside := *r.Service
			inside.DB = tx
			pause := func(state string) error {
				if err := tx.Model(&row).Updates(map[string]any{"enabled": false, "last_state": state}).Error; err != nil {
					return err
				}
				return authorization.New(tx).Record(row.ActorID, "ansible.schedule.pause", row.ID, state, "", row.SourceSessionID)
			}
			a, err := r.Sessions.AccessForSession(row.SourceSessionID, row.ActorID)
			if err != nil {
				return pause("source_session_unavailable")
			}
			if inside.require(a, row.ServerID, true, "ansible.schedules.manage", "ansible.playbooks.execute", "secrets.use") != nil {
				return pause("authority_changed")
			}
			data, err := inside.scheduleConfig(row)
			if err != nil {
				return pause("configuration_unavailable")
			}
			next := time.Now().UTC().Add(time.Duration(row.IntervalMinutes) * time.Minute)
			if row.PendingPlanID != "" {
				var previous Plan
				if err := tx.First(&previous, "id=? AND server_id=? AND actor_id=?", row.PendingPlanID, row.ServerID, row.ActorID).Error; err != nil {
					return pause("previous_plan_unavailable")
				}
				var run models.SupervisedRun
				found := tx.Where("kind='ansible' AND operation_context=?", previous.ID).Find(&run)
				if found.Error != nil {
					return found.Error
				}
				state := ""
				if found.RowsAffected > 0 && run.FinishedAt == nil {
					state = "previous_run_pending"
				} else if found.RowsAffected == 0 && previous.State != "cancelled" && previous.ExpiresAt.After(time.Now().UTC()) {
					state = "awaiting_review_or_execution"
				}
				if state != "" {
					return tx.Model(&row).Updates(map[string]any{"last_state": state, "next_at": next}).Error
				}
			}
			view, err := inside.PreparePreset(a, row.ServerID, row.PresetID, data.Variables, data.VaultPassword)
			if err != nil {
				return pause("planning_denied")
			}
			if err := tx.Model(&row).Updates(map[string]any{"pending_plan_id": view.ID, "last_state": "awaiting_review", "next_at": next}).Error; err != nil {
				return err
			}
			return authorization.New(tx).Record(row.ActorID, "ansible.schedule.plan", row.ID, "awaiting_review", view.ID, row.SourceSessionID)
		})
	}
}
