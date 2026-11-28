package backups

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type HealthIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
}
type PolicyHealth struct {
	PolicyID      string         `json:"policyId"`
	Name          string         `json:"name"`
	State         string         `json:"state"`
	Settings      PolicySettings `json:"settings"`
	Issues        []HealthIssue  `json:"issues"`
	LastSuccessAt *time.Time     `json:"lastSuccessAt,omitempty"`
	LastRestoreAt *time.Time     `json:"lastRestoreAt,omitempty"`
}
type BackupAlert struct {
	ID          string     `json:"id" gorm:"primaryKey"`
	ScopeID     string     `json:"-"`
	PolicyID    string     `json:"policyId"`
	Code        string     `json:"code"`
	Severity    string     `json:"severity"`
	State       string     `json:"state"`
	FirstSeenAt time.Time  `json:"firstSeenAt"`
	LastSeenAt  time.Time  `json:"lastSeenAt"`
	ResolvedAt  *time.Time `json:"resolvedAt,omitempty"`
}

func (BackupAlert) TableName() string { return "backup_alerts" }

type HealthReport struct {
	ObservedAt time.Time       `json:"observedAt"`
	Policies   []PolicyHealth  `json:"policies"`
	Alerts     []BackupAlert   `json:"alerts"`
	Coverage   *CoverageReport `json:"coverage,omitempty"`
}

func (r *Runtime) policyHealth(row Policy, now time.Time) (PolicyHealth, error) {
	settings, err := r.settings(row.ID)
	result := PolicyHealth{PolicyID: row.ID, Name: row.Name, State: row.LastState, Settings: settings, Issues: []HealthIssue{}, LastSuccessAt: row.LastSuccessAt, LastRestoreAt: row.LastRestoreAt}
	if err != nil || row.Archived {
		return result, err
	}
	definition, err := r.config(row)
	if err != nil {
		return result, err
	}
	add := func(code, severity string) { result.Issues = append(result.Issues, HealthIssue{code, severity}) }
	if !r.ownerAllowed(row, definition) {
		add("authority_changed", "warning")
	}
	if row.LastState == "remote_unknown" {
		add("run_unknown", "critical")
	}
	var last models.SupervisedRun
	err = r.DB.Where("task_id=? AND server_id=? AND action='backup:backup' AND finished_at IS NOT NULL", row.ID, hostScope(row.ServerID)).Order("julianday(finished_at) DESC,id DESC").First(&last).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return result, err
	}
	if err == nil && (row.LastSuccessAt == nil || last.FinishedAt.After(*row.LastSuccessAt)) {
		add("backup_failed", "critical")
	}
	maxAge := settings.MaxAgeMinutes
	if maxAge == 0 && row.Mode == "interval" {
		maxAge = row.IntervalMinutes * 2
	}
	if maxAge == 0 && row.Mode == "once" && row.NextAt != nil {
		maxAge = 15
	}
	anchor := row.CreatedAt
	if row.LastSuccessAt != nil {
		anchor = *row.LastSuccessAt
	} else if row.NextAt != nil && row.NextAt.After(anchor) {
		anchor = *row.NextAt
	}
	if maxAge > 0 && now.Sub(anchor) > time.Duration(maxAge)*time.Minute {
		add("backup_overdue", "warning")
	}
	if !row.Enabled && (row.Mode == "interval" || (row.Mode == "once" && row.NextAt != nil)) {
		add("schedule_paused", "warning")
	}
	if settings.VerifyAfterDays > 0 && row.LastSuccessAt != nil {
		verified := row.CreatedAt
		if row.LastRestoreAt != nil {
			verified = *row.LastRestoreAt
		}
		if now.Sub(verified) > time.Duration(settings.VerifyAfterDays)*24*time.Hour {
			add("restore_overdue", "warning")
		}
	}
	return result, nil
}
func (r *Runtime) syncIssues(scope, policy string, issues []HealthIssue, now time.Time) error {
	return r.DB.Transaction(func(tx *gorm.DB) error {
		ids := []string{}
		for _, issue := range issues {
			sum := sha256.Sum256([]byte(scope + "\x00" + policy + "\x00" + issue.Code))
			id := hex.EncodeToString(sum[:])
			ids = append(ids, id)
			row := BackupAlert{ID: id, ScopeID: scope, PolicyID: policy, Code: issue.Code, Severity: issue.Severity, State: "open", FirstSeenAt: now, LastSeenAt: now}
			if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoUpdates: clause.Assignments(map[string]any{"state": "open", "severity": issue.Severity, "last_seen_at": now, "resolved_at": nil, "first_seen_at": gorm.Expr("CASE WHEN backup_alerts.state='resolved' THEN ? ELSE backup_alerts.first_seen_at END", now)})}).Create(&row).Error; err != nil {
				return err
			}
		}
		query := tx.Model(&BackupAlert{}).Where("scope_id=? AND policy_id=? AND state='open'", scope, policy)
		if len(ids) > 0 {
			query = query.Where("id NOT IN ?", ids)
		}
		return query.Updates(map[string]any{"state": "resolved", "resolved_at": now, "last_seen_at": now}).Error
	})
}
func (r *Runtime) Health(a *auth.Access, server string) (HealthReport, error) {
	result := HealthReport{ObservedAt: time.Now().UTC(), Policies: []PolicyHealth{}, Alerts: []BackupAlert{}}
	if err := r.require(a, server, false, "backups.read"); err != nil {
		return result, err
	}
	var rows []Policy
	if err := r.DB.Where("server_id=? AND archived=0", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error; err != nil {
		return result, err
	}
	for _, row := range rows {
		value, err := r.policyHealth(row, result.ObservedAt)
		if err != nil {
			return result, err
		}
		result.Policies = append(result.Policies, value)
	}
	var scan coverageScan
	if err := r.DB.First(&scan, "scope_id=?", hostScope(server)).Error; err == nil {
		updated, err := r.savedCoverage(scan)
		if err != nil {
			return result, err
		}
		result.Coverage = &updated
	} else if err != gorm.ErrRecordNotFound {
		return result, err
	}
	if err := r.DB.Where("scope_id=?", hostScope(server)).Order("state,julianday(last_seen_at) DESC,id").Limit(100).Find(&result.Alerts).Error; err != nil {
		return result, err
	}
	return result, r.require(a, server, false, "backups.read")
}
func (r *Runtime) SweepHealth(now time.Time) {
	if !r.Enabled {
		return
	}
	var policies []Policy
	if r.DB.Where("id>?", r.healthAfter).Order("id").Limit(100).Find(&policies).Error == nil {
		for _, row := range policies {
			value, err := r.policyHealth(row, now)
			if err == nil {
				_ = r.syncIssues(hostScope(row.ServerID), row.ID, value.Issues, now)
			}
			r.healthAfter = row.ID
		}
		if len(policies) < 100 {
			r.healthAfter = ""
		}
	}
	var scans []coverageScan
	if r.DB.Where("scope_id>?", r.coverageAfter).Order("scope_id").Limit(100).Find(&scans).Error == nil {
		for _, scan := range scans {
			if fresh, err := r.savedCoverage(scan); err == nil {
				data, _ := json.Marshal(fresh)
				scan.ReportJSON = string(data)
				_ = r.syncCoverage(scan, now)
			}
			r.coverageAfter = scan.ScopeID
		}
		if len(scans) < 100 {
			r.coverageAfter = ""
		}
	}
}
