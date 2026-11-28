package backups

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type PolicySettings struct {
	PolicyID        string    `json:"policyId" gorm:"primaryKey"`
	KeepLast        int       `json:"keepLast"`
	MaxAgeMinutes   int       `json:"maxAgeMinutes"`
	VerifyAfterDays int       `json:"verifyAfterDays"`
	UpdatedBy       string    `json:"updatedBy"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func (PolicySettings) TableName() string { return "backup_policy_settings" }

type RetentionResult struct {
	KeepLast          int      `json:"keepLast"`
	InventoryDigest   string   `json:"inventoryDigest"`
	RemoveIDs         []string `json:"removeIds"`
	KeptCount         int      `json:"keptCount"`
	UnclassifiedCount int      `json:"unclassifiedCount"`
}
type RetentionRequest struct {
	RetentionResult
	PreviewRunID string   `json:"previewRunId,omitempty"`
	EligibleIDs  []string `json:"eligibleIds,omitempty"`
}

func (s *Service) settings(id string) (PolicySettings, error) {
	result := PolicySettings{PolicyID: id, KeepLast: 7, VerifyAfterDays: 30}
	err := s.DB.First(&result, "policy_id=?", id).Error
	if err == gorm.ErrRecordNotFound {
		err = nil
	}
	return result, err
}
func (s *Service) Settings(a *auth.Access, server, id string) (PolicySettings, error) {
	if err := s.require(a, server, false, "backups.read"); err != nil {
		return PolicySettings{}, err
	}
	if _, err := s.policy(server, id); err != nil {
		return PolicySettings{}, err
	}
	return s.settings(id)
}
func (s *Service) SaveSettings(a *auth.Access, server, id string, value PolicySettings) error {
	if value.KeepLast < 1 || value.KeepLast > 500 || value.MaxAgeMinutes < 0 || value.MaxAgeMinutes > 525600 || (value.MaxAgeMinutes > 0 && value.MaxAgeMinutes < 15) || value.VerifyAfterDays < 0 || value.VerifyAfterDays > 3650 {
		return ErrInput
	}
	if err := s.require(a, server, true, "backups.manage"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "backups.manage"); err != nil {
			return err
		}
		row, err := inside.policy(server, id)
		if err != nil {
			return err
		}
		if row.Archived {
			return ErrConflict
		}
		value.PolicyID, value.UpdatedBy, value.UpdatedAt = id, a.User.ID, time.Now().UTC()
		if err := tx.Save(&value).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "backup.settings.save", id, "saved", "", a.Session.ID)
	})
}

func retentionHash(action string, request RetentionRequest) string {
	data, _ := json.Marshal(request)
	sum := sha256.Sum256(append([]byte(action+"\x00"), data...))
	return hex.EncodeToString(sum[:])
}
func retentionBinding(run models.SupervisedRun) string {
	data, _ := json.Marshal([]string{run.ServerID, run.TaskID, run.ActorID, run.SourceSessionID, run.OperationContext, run.TargetHash, run.Action})
	return string(data)
}
func (r *Runtime) previewResult(run models.SupervisedRun, at time.Time) (*RetentionResult, error) {
	if run.Action != "backup:retention-preview" || run.State != "exited" || run.ExitCode == nil || *run.ExitCode != 0 || run.VerifiedAt == nil || run.FinishedAt == nil || run.FinishedAt.After(at) || at.Sub(*run.FinishedAt) > 30*time.Minute {
		return nil, ErrConflict
	}
	observation, err := r.controller(func() bool { return false }).Cached(run)
	if err != nil {
		return nil, err
	}
	parsed := parseResult(observation.Output, r.workRoot(scopeOf(run)), run.TaskID, run.ID)
	if parsed == nil || parsed.State != "retention_preview" || !parsed.Verified || parsed.Retention == nil {
		return nil, ErrConflict
	}
	return parsed.Retention, nil
}
func (r *Runtime) StartRetention(a *auth.Access, server, policyID, id, action, previewID string) (models.SupervisedRun, error) {
	if !idPattern.MatchString(id) || (action != "retention-preview" && action != "retention-apply") || (action == "retention-apply" && !idPattern.MatchString(previewID)) || (action == "retention-preview" && previewID != "") {
		return models.SupervisedRun{}, ErrInput
	}
	required := permissions(action)
	if server != "" {
		required = append(required, "servers.connect")
	} else {
		required = append(required, "secrets.reveal")
	}
	if err := r.require(a, server, true, required...); err != nil {
		return models.SupervisedRun{}, err
	}
	settings, err := r.Settings(a, server, policyID)
	if err != nil {
		return models.SupervisedRun{}, err
	}
	request := RetentionRequest{RetentionResult: RetentionResult{KeepLast: settings.KeepLast}}
	if action == "retention-preview" {
		// Only snapshots with successful, authenticated Nexus run evidence can be
		// removed. Imported, incomplete and unclassified snapshots remain intact.
		var runs []models.SupervisedRun
		if err := r.DB.Where("task_id=? AND server_id=? AND action='backup:backup' AND state='exited' AND exit_code=0 AND verified_at IS NOT NULL AND finished_at IS NOT NULL", policyID, hostScope(server)).Order("julianday(finished_at) DESC,id DESC").Limit(500).Find(&runs).Error; err != nil {
			return models.SupervisedRun{}, err
		}
		for _, run := range runs {
			value, err := r.controller(func() bool { return false }).Cached(run)
			if err != nil {
				return models.SupervisedRun{}, err
			}
			result := parseResult(value.Output, r.workRoot(server), policyID, run.ID)
			if result != nil && result.State == "completed" && snapshotPattern.MatchString(result.SnapshotID) {
				request.EligibleIDs = append(request.EligibleIDs, result.SnapshotID)
			}
		}
	} else {
		preview, err := r.Get(server, previewID)
		if err != nil {
			return models.SupervisedRun{}, err
		}
		if preview.TaskID != policyID || preview.ActorID != a.User.ID || preview.SourceSessionID != a.Session.ID {
			return models.SupervisedRun{}, ErrDenied
		}
		value, err := r.previewResult(preview, time.Now().UTC())
		if err != nil || value.KeepLast != settings.KeepLast || len(value.RemoveIDs) == 0 {
			return models.SupervisedRun{}, ErrConflict
		}
		request.RetentionResult, request.PreviewRunID = *value, previewID
	}
	return r.reserve(a, server, policyID, id, action, "", false, request)
}

func (r *Runtime) retentionJob(run models.SupervisedRun) (*RetentionRequest, error) {
	var saved struct {
		Binding    string
		RequestEnc string
	}
	if err := r.DB.Raw("SELECT binding,request_enc FROM backup_retention_jobs WHERE run_id=?", run.ID).Scan(&saved).Error; err != nil {
		return nil, err
	}
	if saved.Binding != retentionBinding(run) {
		return nil, ErrConflict
	}
	raw, err := nexuscrypto.DecryptBackupRetention(r.Key, run.ID, saved.Binding, saved.RequestEnc)
	if err != nil {
		return nil, ErrConflict
	}
	defer clear(raw)
	var request RetentionRequest
	action := strings.TrimPrefix(run.Action, "backup:")
	if len(raw) > 64<<10 || json.Unmarshal(raw, &request) != nil || request.KeepLast < 1 || request.KeepLast > 500 || retentionHash(action, request) != run.TargetHash {
		return nil, ErrConflict
	}
	settings, err := r.settings(run.TaskID)
	if err != nil || settings.KeepLast != request.KeepLast {
		return nil, ErrConflict
	}
	if action == "retention-apply" {
		preview, err := r.Get(scopeOf(run), request.PreviewRunID)
		if err != nil || preview.TaskID != run.TaskID || preview.ActorID != run.ActorID || preview.SourceSessionID != run.SourceSessionID || preview.OperationContext != run.OperationContext {
			return nil, ErrConflict
		}
		value, err := r.previewResult(preview, run.CreatedAt)
		if err != nil {
			return nil, err
		}
		expected, _ := json.Marshal(value)
		actual, _ := json.Marshal(request.RetentionResult)
		if string(actual) != string(expected) {
			return nil, ErrConflict
		}
		var claimed string
		if err := r.DB.Raw("SELECT run_id FROM backup_retention_claims WHERE preview_run_id=?", request.PreviewRunID).Scan(&claimed).Error; err != nil || claimed != run.ID {
			return nil, ErrConflict
		}
	}
	return &request, nil
}
