package backups

import (
	"context"
	"encoding/json"
	"path"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
)

type CoverageItem struct {
	Candidate     Candidate  `json:"candidate"`
	State         string     `json:"state"`
	PolicyIDs     []string   `json:"policyIds"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
}
type CoverageReport struct {
	ScannedAt time.Time      `json:"scannedAt"`
	Truncated bool           `json:"truncated"`
	WatchGaps bool           `json:"watchGaps"`
	Items     []CoverageItem `json:"items"`
}
type coverageScan struct {
	ScopeID    string `gorm:"primaryKey"`
	ScannedAt  time.Time
	WatchGaps  bool
	ReportJSON string
}

func (coverageScan) TableName() string { return "backup_coverage_scans" }

func covers(saved, discovered Source) bool {
	if saved.Kind != discovered.Kind {
		return false
	}
	switch saved.Kind {
	case "nexus":
		return true
	case "files":
		return saved.Path == discovered.Path || (path.Clean(saved.Path) == saved.Path && (saved.Path == "/" || strings.HasPrefix(discovered.Path, saved.Path+"/")))
	case "sqlite":
		return saved.Path == discovered.Path
	case "docker-volume":
		return saved.Volume == discovered.Volume
	case "docker-bind":
		return saved.Path == discovered.Path && saved.ContainerID == discovered.ContainerID
	default:
		if saved.ContainerID != "" || discovered.ContainerID != "" {
			return saved.ContainerID != "" && saved.ContainerID == discovered.ContainerID && (saved.Database.Name == "" || saved.Database.Name == discovered.Database.Name)
		}
		return saved.Database.Host == discovered.Database.Host && saved.Database.Port == discovered.Database.Port && (saved.Database.Name == "" || saved.Database.Name == discovered.Database.Name)
	}
}
func (r *Runtime) coverageFrom(server string, discovery Discovery, watch bool, now time.Time) (CoverageReport, error) {
	result := CoverageReport{ScannedAt: now, WatchGaps: watch, Truncated: discovery.Truncated, Items: []CoverageItem{}}
	var policies []Policy
	if err := r.DB.Where("server_id=? AND archived=0", server).Order("id").Limit(100).Find(&policies).Error; err != nil {
		return result, err
	}
	definitions := make(map[string]sealedDefinition, len(policies))
	for _, row := range policies {
		data, err := r.config(row)
		if err != nil {
			return result, err
		}
		definitions[row.ID] = data
	}
	for _, candidate := range discovery.Sources {
		item := CoverageItem{Candidate: candidate, State: "unprotected", PolicyIDs: []string{}}
		// Discovery must never persist credentials, even from a future adapter.
		item.Candidate.Source.Database.Password = ""
		if candidate.State == "unsupported" {
			item.State = "unsupported"
		}
		for _, row := range policies {
			for _, source := range definitions[row.ID].Sources {
				if covers(source, candidate.Source) {
					item.PolicyIDs = append(item.PolicyIDs, row.ID)
					if row.LastSuccessAt != nil && (item.LastSuccessAt == nil || row.LastSuccessAt.After(*item.LastSuccessAt)) {
						item.LastSuccessAt = row.LastSuccessAt
					}
					break
				}
			}
		}
		if len(item.PolicyIDs) > 0 {
			item.State = "configured"
			if item.LastSuccessAt != nil {
				item.State = "backed_up"
			}
		}
		result.Items = append(result.Items, item)
	}
	return result, nil
}
func (r *Runtime) RefreshCoverage(ctx context.Context, a *auth.Access, server, prefix string, watch bool) (CoverageReport, error) {
	discovery, err := r.Discover(ctx, a, server, prefix)
	if err != nil {
		return CoverageReport{}, err
	}
	report, err := r.coverageFrom(server, discovery, watch, time.Now().UTC())
	if err != nil {
		return report, err
	}
	if err = r.require(a, server, true, "backups.read", "backups.manage", "secrets.use"); err != nil {
		return CoverageReport{}, err
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > 512<<10 {
		return CoverageReport{}, ErrInput
	}
	scan := coverageScan{ScopeID: hostScope(server), ScannedAt: report.ScannedAt, WatchGaps: watch, ReportJSON: string(encoded)}
	err = r.DB.Save(&scan).Error
	if err == nil {
		err = r.syncCoverage(scan, time.Now().UTC())
	}
	return report, err
}
func coverageIssues(scan coverageScan, now time.Time) ([]HealthIssue, error) {
	issues := []HealthIssue{}
	if !scan.WatchGaps {
		return issues, nil
	}
	if now.Sub(scan.ScannedAt) > 24*time.Hour {
		return []HealthIssue{{"coverage_stale", "warning"}}, nil
	}
	var report CoverageReport
	if len(scan.ReportJSON) > 512<<10 || json.Unmarshal([]byte(scan.ReportJSON), &report) != nil {
		return nil, ErrConflict
	}
	if report.Truncated {
		issues = append(issues, HealthIssue{"coverage_incomplete", "warning"})
	}
	for _, item := range report.Items {
		if item.State == "unprotected" || item.State == "configured" {
			issues = append(issues, HealthIssue{"sources_unprotected", "warning"})
			break
		}
	}
	return issues, nil
}
func (r *Runtime) syncCoverage(scan coverageScan, now time.Time) error {
	issues, err := coverageIssues(scan, now)
	if err != nil {
		return err
	}
	return r.syncIssues(scan.ScopeID, "", issues, now)
}

func (r *Runtime) savedCoverage(scan coverageScan) (CoverageReport, error) {
	var saved CoverageReport
	if len(scan.ReportJSON) > 512<<10 || json.Unmarshal([]byte(scan.ReportJSON), &saved) != nil {
		return CoverageReport{}, ErrConflict
	}
	discovery := Discovery{Truncated: saved.Truncated}
	for _, item := range saved.Items {
		discovery.Sources = append(discovery.Sources, item.Candidate)
	}
	server := scan.ScopeID
	if server == LocalHost {
		server = ""
	}
	return r.coverageFrom(server, discovery, scan.WatchGaps, scan.ScannedAt)
}
