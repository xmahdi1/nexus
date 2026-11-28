package inventory

import (
	"context"
	"errors"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrPolicyInput = errors.New("invalid collection policy")
var ErrPolicyConflict = errors.New("collection policy changed")
var ErrPolicyProtected = errors.New("protected hosts require interactive collection")

// Policy delegates only this registered host's fixed, read-only collectors.
// Actor grants are checked live; no browser session or credential is retained.
type Policy struct {
	ServerID         string     `gorm:"primaryKey" json:"-"`
	ActorID          string     `json:"actorId"`
	Enabled          bool       `json:"enabled"`
	IntervalMinutes  int        `json:"intervalMinutes"`
	FreshnessMinutes int        `json:"freshnessMinutes"`
	RetentionDays    int        `json:"retentionDays"`
	Revision         int        `json:"revision"`
	NextRunAt        time.Time  `json:"nextRunAt"`
	FailureCount     int        `json:"failureCount"`
	LastStatus       string     `json:"lastStatus"`
	ClaimID          string     `json:"-"`
	LeaseUntil       *time.Time `json:"-"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

func (Policy) TableName() string { return "inventory_policies" }

type PolicyInput struct {
	Enabled          bool `json:"enabled"`
	IntervalMinutes  int  `json:"intervalMinutes"`
	FreshnessMinutes int  `json:"freshnessMinutes"`
	RetentionDays    int  `json:"retentionDays"`
	Revision         int  `json:"revision"`
}

type SourceResult struct {
	RunID       string    `gorm:"primaryKey" json:"runId"`
	Source      string    `gorm:"primaryKey" json:"source"`
	ServerID    string    `json:"-"`
	Status      string    `json:"status"`
	CollectedAt time.Time `json:"collectedAt"`
}

func (SourceResult) TableName() string { return "inventory_collection_sources" }

func collectionPolicy(tx *gorm.DB, server string) (Policy, error) {
	p := Policy{ServerID: server, IntervalMinutes: 60, FreshnessMinutes: 15}
	err := tx.Take(&p, "server_id=?", server).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return p, nil
	}
	return p, err
}

func freshnessCutoff(tx *gorm.DB, server string) (time.Time, error) {
	p, err := collectionPolicy(tx, server)
	return time.Now().UTC().Add(-time.Duration(p.FreshnessMinutes) * time.Minute), err
}

func (s *Service) Policy(actor, server string) (Policy, error) {
	var p Policy
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if !authorization.New(tx).All(actor, server, "inventory.read") {
			return authorization.ErrDenied
		}
		var err error
		p, err = collectionPolicy(tx, server)
		return err
	})
	return p, err
}

func policyAuthority(tx *gorm.DB, p Policy) bool {
	return authorization.New(tx).All(p.ActorID, p.ServerID, "inventory.read", "inventory.edit", "inventory.discover", "secrets.use")
}

func scheduleAuthority(tx *gorm.DB, p Policy) bool {
	protected, err := authorization.New(tx).Protected(p.ServerID)
	return err == nil && !protected && policyAuthority(tx, p)
}

func (s *Service) SavePolicy(ctx context.Context, access *auth.Access, server string, input PolicyInput) (Policy, error) {
	var result Policy
	if input.IntervalMinutes < 5 || input.IntervalMinutes > 1440 || input.FreshnessMinutes < 5 || input.FreshnessMinutes > 10080 ||
		input.RetentionDays < 0 || input.RetentionDays > 3650 || input.Revision < 0 || input.Revision >= 1<<31-1 {
		return result, ErrPolicyInput
	}
	if server == "" || access == nil || s.Sessions == nil {
		return result, authorization.ErrDenied
	}
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		sessions := *s.Sessions
		sessions.DB = tx
		if _, err := sessions.AccessForSession(access.Session.ID, access.User.ID); err != nil {
			return authorization.ErrDenied
		}
		old, err := collectionPolicy(tx, server)
		if err != nil {
			return err
		}
		result = Policy{ServerID: server, ActorID: access.User.ID, Enabled: input.Enabled, IntervalMinutes: input.IntervalMinutes,
			FreshnessMinutes: input.FreshnessMinutes, RetentionDays: input.RetentionDays, Revision: old.Revision + 1,
			UpdatedAt: time.Now().UTC()}
		if !policyAuthority(tx, result) {
			return authorization.ErrDenied
		}
		if input.Enabled && !scheduleAuthority(tx, result) {
			return ErrPolicyProtected
		}
		if old.Revision != input.Revision {
			return ErrPolicyConflict
		}
		result.NextRunAt = result.UpdatedAt.Add(time.Duration(input.IntervalMinutes) * time.Minute)
		// Replacing the policy clears its claim, fencing an in-flight collector.
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&result).Error; err != nil {
			return err
		}
		if err := retainHistory(tx, result, result.UpdatedAt); err != nil {
			return err
		}
		return authorization.New(tx).Record(access.User.ID, "inventory.policy.save", server, "saved", "", access.Session.ID)
	})
	return result, err
}

func recordSources(tx *gorm.DB, run Run, obs Observation, now time.Time) error {
	rows := make([]SourceResult, 0, len(collectorSources))
	for _, source := range collectorSources {
		status := "unavailable"
		if run.Status == "denied" {
			status = "denied"
		} else if run.Status == "failed" {
			status = "failed"
		} else if collectorAvailable(source, obs) {
			status = "ok"
		}
		rows = append(rows, SourceResult{RunID: run.ID, ServerID: run.ServerID, Source: source, Status: status, CollectedAt: now})
	}
	return tx.Create(&rows).Error
}

// Retention is opt-in and runs on policy save and completed collections. Keep
// all assets, notes, audits and any run still proving a resource/relationship.
func retainHistory(tx *gorm.DB, p Policy, now time.Time) error {
	if p.RetentionDays == 0 || !policyAuthority(tx, p) {
		return nil
	}
	cutoff := now.Add(-time.Duration(p.RetentionDays) * 24 * time.Hour)
	if err := tx.Where("server_id=? AND at<?", p.ServerID, cutoff).Delete(&Change{}).Error; err != nil {
		return err
	}
	old := tx.Model(&Run{}).Select("id").Where(`server_id=? AND status!='running' AND finished_at<?
 AND NOT EXISTS(SELECT 1 FROM inventory_resources r WHERE r.last_run_id=discovery_runs.id)
 AND NOT EXISTS(SELECT 1 FROM inventory_relationships r WHERE r.last_run_id=discovery_runs.id)
 AND NOT EXISTS(SELECT 1 FROM inventory_changes c WHERE c.run_id=discovery_runs.id)`, p.ServerID, cutoff)
	if err := tx.Where("server_id=? AND run_id IN (?)", p.ServerID, old).Delete(&SourceResult{}).Error; err != nil {
		return err
	}
	return tx.Where("id IN (?)", old).Delete(&Run{}).Error
}
