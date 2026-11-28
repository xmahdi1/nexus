package backups

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func parseResult(output, root, policyID, runID string) *Result {
	if len(output) > 65536 {
		return nil
	}
	var result Result
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil
	}
	states := map[string]bool{"ready": true, "initialized": true, "completed": true, "incomplete": true, "snapshots": true, "checked": true, "restored": true, "failed": true, "retention_preview": true, "retention_applied": true}
	phases := map[string]bool{"validation": true, "tool": true, "install": true, "repository": true, "source_export": true, "backup": true, "restore": true, "check": true, "retention": true}
	if !states[result.State] || (result.Phase != "" && !phases[result.Phase]) || (result.SnapshotID != "" && !snapshotPattern.MatchString(result.SnapshotID)) || result.Files < 0 || result.Files > 1e12 || result.Bytes < 0 || result.Bytes > 1<<60 || len(result.Snapshots) > 50 {
		return nil
	}
	if result.RestorePath != "" && (result.State != "restored" || result.RestorePath != filepath.Join(root, "restores", policyID, runID)) {
		return nil
	}
	for _, snapshot := range result.Snapshots {
		if !snapshotPattern.MatchString(snapshot.ID) {
			return nil
		}
		if _, err := time.Parse(time.RFC3339Nano, snapshot.Time); err != nil {
			return nil
		}
	}
	if value := result.Retention; value != nil {
		if (result.State != "retention_preview" && result.State != "retention_applied") || !result.Verified || value.KeepLast < 1 || value.KeepLast > 500 || !snapshotPattern.MatchString(value.InventoryDigest) || value.KeptCount < 0 || (len(value.RemoveIDs) > 0 && value.KeptCount < value.KeepLast) || value.KeptCount > 500 || value.UnclassifiedCount < 0 || value.UnclassifiedCount > value.KeptCount || len(value.RemoveIDs) > 499 {
			return nil
		}
		seen := map[string]bool{}
		for _, id := range value.RemoveIDs {
			if !snapshotPattern.MatchString(id) || seen[id] {
				return nil
			}
			seen[id] = true
		}
	}
	return &result
}
func (r *Runtime) finish(id string) error {
	var run models.SupervisedRun
	if err := r.DB.First(&run, "id=? AND kind='scheduled' AND action LIKE 'backup:%'", id).Error; err != nil {
		return err
	}
	if run.FinishedAt == nil {
		if run.State == "unknown" {
			return r.DB.Model(&Policy{}).Where("id=? AND last_run_id=?", run.TaskID, id).Updates(map[string]any{"enabled": false, "last_state": "remote_unknown"}).Error
		}
		return nil
	}
	observation, err := r.controller(func() bool { return false }).Cached(run)
	if err != nil {
		return err
	}
	server := run.ServerID
	if server == LocalHost {
		server = ""
	}
	result := parseResult(observation.Output, r.workRoot(server), run.TaskID, run.ID)
	return r.DB.Transaction(func(tx *gorm.DB) error {
		claim := tx.Exec("UPDATE backup_run_cleanup SET finalized=1 WHERE run_id=? AND finalized=0", run.ID)
		if claim.Error != nil {
			return claim.Error
		}
		if claim.RowsAffected != 1 {
			return nil
		}
		var policy Policy
		if err := tx.First(&policy, "id=?", run.TaskID).Error; err != nil {
			return err
		}
		updates := map[string]any{}
		state := run.State
		completed := run.State == "exited" && run.ExitCode != nil && *run.ExitCode == 0 && run.VerifiedAt != nil
		if result != nil && (completed || (run.State == "failed" && (result.State == "failed" || result.State == "incomplete"))) {
			state = result.State
		}
		if completed && result != nil {
			var field string
			var previous *time.Time
			if run.Action == "backup:backup" && result.State == "completed" && snapshotPattern.MatchString(result.SnapshotID) {
				field = "last_success_at"
				previous = policy.LastSuccessAt
			}
			if run.Action == "backup:check" && result.State == "checked" && result.Verified {
				field = "last_check_at"
				previous = policy.LastCheckAt
			}
			if (run.Action == "backup:verify" || run.Action == "backup:restore") && result.State == "restored" && result.Verified {
				field = "last_restore_at"
				previous = policy.LastRestoreAt
			}
			if field != "" && (previous == nil || previous.Before(*run.FinishedAt)) {
				updates[field] = run.FinishedAt
			}
		}
		changed := policy.LastRunID == run.ID && policy.LastState != state
		if policy.LastRunID == run.ID {
			updates["last_state"] = state
			if !completed || result == nil || result.State == "failed" || result.State == "incomplete" {
				updates["enabled"] = false
			}
		}
		if len(updates) > 0 {
			if err := tx.Model(&policy).Updates(updates).Error; err != nil {
				return err
			}
		}
		if changed {
			return authorization.New(tx).Record(run.ActorID, "backup.run.finish", run.ID, state, policy.ID, run.SourceSessionID)
		}
		return nil
	})
}
