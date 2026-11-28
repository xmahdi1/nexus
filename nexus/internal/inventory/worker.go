package inventory

import (
	"context"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
)

// Run starts only when the inventory feature is enabled by the caller. Each
// sweep has bounded admission/concurrency; missed intervals are never replayed.
func (s *Service) Run(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			s.runDue(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *Service) runDue(ctx context.Context) {
	var policies []Policy
	now := time.Now().UTC()
	if s.DB.Where("enabled=? AND next_run_at<=? AND (claim_id='' OR lease_until<?)", true, now, now).
		Order("next_run_at, server_id").Limit(32).Find(&policies).Error != nil {
		return
	}
	// Four synchronous batches prevent a second sweep adding unbounded work.
	for start := 0; start < len(policies) && ctx.Err() == nil; start += 4 {
		done := make(chan struct{}, 4)
		end := min(start+4, len(policies))
		for _, p := range policies[start:end] {
			go func(p Policy) { defer func() { done <- struct{}{} }(); s.runPolicy(ctx, p) }(p)
		}
		for i := start; i < end; i++ {
			<-done
		}
	}
}

func (s *Service) runPolicy(ctx context.Context, candidate Policy) {
	claim, err := audit.NewID()
	if err != nil || ctx.Err() != nil {
		return
	}
	var p Policy
	claimed := false
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		if err := tx.Take(&p, "server_id=? AND enabled=? AND next_run_at<=? AND (claim_id='' OR lease_until<?)", candidate.ServerID, true, now, now).Error; err != nil {
			return err
		}
		if !scheduleAuthority(tx, p) {
			if err := tx.Model(&p).Updates(map[string]any{"enabled": false, "claim_id": "", "lease_until": nil, "last_status": "denied"}).Error; err != nil {
				return err
			}
			return authorization.New(tx).Record(p.ActorID, "inventory.schedule", p.ServerID, "denied", claim)
		}
		lease := now.Add(2 * time.Minute)
		result := tx.Model(&Policy{}).Where("server_id=? AND revision=? AND enabled=? AND next_run_at<=? AND (claim_id='' OR lease_until<?)", p.ServerID, p.Revision, true, now, now).
			Updates(map[string]any{"claim_id": claim, "lease_until": lease, "next_run_at": lease, "last_status": "running"})
		claimed = result.Error == nil && result.RowsAffected == 1
		return result.Error
	})
	if err != nil || !claimed {
		return
	}
	guard := func(tx *gorm.DB) bool {
		var count int64
		return tx.Model(&Policy{}).Where("server_id=? AND revision=? AND enabled=? AND claim_id=? AND lease_until>?", p.ServerID, p.Revision, true, claim, time.Now().UTC()).Count(&count).Error == nil && count == 1 && scheduleAuthority(tx, p)
	}
	run, collectErr := s.discover(ctx, p.ActorID, p.ServerID, "scheduled", guard)
	_ = s.DB.Transaction(func(tx *gorm.DB) error {
		status := run.Status
		if collectErr != nil && status != "denied" {
			status = "failed"
			if collectErr == ErrBusy {
				status = "busy"
			}
		}
		failures := 0
		if status != "succeeded" {
			failures = min(p.FailureCount+1, 8)
		}
		minutes := min(p.IntervalMinutes*(1<<failures), 1440)
		values := map[string]any{"claim_id": "", "lease_until": nil, "last_status": status,
			"failure_count": failures, "next_run_at": time.Now().UTC().Add(time.Duration(minutes) * time.Minute)}
		if !scheduleAuthority(tx, p) || status == "denied" {
			values["enabled"], values["last_status"] = false, "denied"
		}
		return tx.Model(&Policy{}).Where("server_id=? AND claim_id=? AND revision=?", p.ServerID, claim, p.Revision).Updates(values).Error
	})
}
