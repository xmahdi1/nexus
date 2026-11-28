package inventory

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
)

func duePolicy(t *testing.T, s *Service) Policy {
	t.Helper()
	p := Policy{ServerID: "dev", ActorID: authorization.LegacyPrincipal, Enabled: true, IntervalMinutes: 5, FreshnessMinutes: 15, Revision: 1, NextRunAt: time.Now().UTC().Add(-time.Minute), UpdatedAt: time.Now().UTC()}
	if err := s.DB.Create(&p).Error; err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScheduleOptInConcurrentClaimsAndSourceProvenance(t *testing.T) {
	s := fixture(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) {
		calls.Add(1)
		close(entered)
		<-release
		obs := observation()
		obs.Routes6OK = false
		return obs, nil
	})
	s.runDue(context.Background())
	if calls.Load() != 0 {
		t.Fatal("default scan")
	}
	duePolicy(t, s)
	done := make(chan struct{})
	go func() { s.runDue(context.Background()); close(done) }()
	<-entered
	// Independent sweeps and a manual request cannot overlap the host claim.
	s.runDue(context.Background())
	if _, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev"); !errors.Is(err, ErrBusy) {
		t.Fatal("overlapping manual scan", err)
	}
	close(release)
	<-done
	if calls.Load() != 1 {
		t.Fatal("duplicate transport", calls.Load())
	}
	p, err := s.Policy(authorization.LegacyPrincipal, "dev")
	if err != nil || p.ClaimID != "" || p.FailureCount != 1 || p.LastStatus != "partial" || time.Until(p.NextRunAt) < 9*time.Minute {
		t.Fatal(p, err)
	}
	snapshot, err := s.Read(authorization.LegacyPrincipal, "dev")
	if err != nil || len(snapshot.Sources) != len(collectorSources) || len(snapshot.Runs) != 1 || snapshot.Runs[0].Trigger != "scheduled" {
		t.Fatal(snapshot, err)
	}
	for _, source := range snapshot.Sources {
		want := "ok"
		if source.Source == routes6Source {
			want = "unavailable"
		}
		if source.Status != want || source.RunID != snapshot.Runs[0].ID {
			t.Fatal(source)
		}
	}
	for _, item := range snapshot.Items {
		if item.LastRunID != snapshot.Runs[0].ID {
			t.Fatal("resource provenance", item)
		}
	}
	links, err := s.Relationships(authorization.LegacyPrincipal, "dev", "", 200)
	if err != nil || len(links.Items) == 0 {
		t.Fatal(links, err)
	}
	for _, link := range links.Items {
		if link.LastRunID != snapshot.Runs[0].ID {
			t.Fatal("relationship provenance", link)
		}
	}
}

func TestScheduleRevocationProtectionAndEditingFencePublication(t *testing.T) {
	for _, change := range []string{"revocation", "protection", "edit"} {
		t.Run(change, func(t *testing.T) {
			s := fixture(t)
			duePolicy(t, s)
			entered := make(chan struct{})
			s.Adapter = adapterFunc(func(ctx context.Context, _ string) (Observation, error) {
				close(entered)
				select {
				case <-ctx.Done():
					return observation(), nil
				case <-time.After(5 * time.Second):
					return Observation{}, errors.New("cancellation did not arrive")
				}
			})
			done := make(chan struct{})
			go func() { s.runDue(context.Background()); close(done) }()
			<-entered
			switch change {
			case "revocation":
				if err := s.DB.Where("principal_id=?", authorization.LegacyPrincipal).Delete(&authorization.Grant{}).Error; err != nil {
					t.Fatal(err)
				}
			case "protection":
				if err := s.DB.Exec("INSERT INTO server_groups(id,name,require_mfa,created_at)VALUES('protected','Protected',1,CURRENT_TIMESTAMP)").Error; err != nil {
					t.Fatal(err)
				}
				if err := s.DB.Exec("INSERT INTO server_group_members(group_id,server_id)VALUES('protected','dev')").Error; err != nil {
					t.Fatal(err)
				}
			case "edit":
				if err := s.DB.Model(&Policy{}).Where("server_id='dev'").Updates(map[string]any{"revision": 2, "claim_id": "", "enabled": false, "last_status": "new-policy"}).Error; err != nil {
					t.Fatal(err)
				}
			}
			<-done
			var count int64
			s.DB.Model(&Resource{}).Count(&count)
			if count != 0 {
				t.Fatal("fenced scan published resources")
			}
			var run Run
			s.DB.Take(&run)
			if run.Status != "denied" {
				t.Fatal("did not fence collection", run)
			}
			var p Policy
			s.DB.Take(&p)
			if p.Enabled || (change == "edit" && (p.Revision != 2 || p.LastStatus != "new-policy")) {
				t.Fatal("old worker overwrote policy", p)
			}
		})
	}
}

func TestScheduleCrashRecoveryBackoffAndRevokedAdmission(t *testing.T) {
	s := fixture(t)
	p := duePolicy(t, s)
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) {
		return Observation{}, errors.New("PRIVATE remote failure")
	})
	// A dead process's read-only claim becomes eligible after its lease, while
	// the crashed discovery run is recorded as interrupted before new admission.
	expired := time.Now().UTC().Add(-3 * time.Minute)
	s.DB.Model(&p).Updates(map[string]any{"claim_id": "crashed", "lease_until": expired, "failure_count": 8})
	s.DB.Create(&Run{ID: "crashed-run", ServerID: "dev", ActorID: p.ActorID, Status: "running", Trigger: "scheduled", StartedAt: expired})
	s.runDue(context.Background())
	s.DB.Take(&p, "server_id='dev'")
	if p.LastStatus != "failed" || p.FailureCount != 8 || time.Until(p.NextRunAt) < 20*time.Hour || time.Until(p.NextRunAt) > 24*time.Hour {
		t.Fatal("backoff", p)
	}
	var old Run
	s.DB.Take(&old, "id='crashed-run'")
	if old.Status != "interrupted" {
		t.Fatal(old)
	}
	s.DB.Model(&p).Updates(map[string]any{"next_run_at": expired})
	s.DB.Where("principal_id=?", authorization.LegacyPrincipal).Delete(&authorization.Grant{})
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) {
		t.Error("revoked transport opened")
		return observation(), nil
	})
	s.runDue(context.Background())
	s.DB.Take(&p, "server_id='dev'")
	if p.Enabled || p.LastStatus != "denied" {
		t.Fatal("revoked schedule not disabled", p)
	}
}

func TestPolicyFreshnessMatchesResourcesRelationshipsAndReports(t *testing.T) {
	s := fixture(t)
	p := duePolicy(t, s)
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return observation(), nil })
	if _, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-10 * time.Minute)
	s.DB.Model(&Resource{}).Where("server_id='dev'").Update("last_verified_at", old)
	s.DB.Model(&Relationship{}).Where("server_id='dev'").Update("last_verified_at", old)
	for _, minutes := range []int{5, 60} {
		s.DB.Model(&p).Update("freshness_minutes", minutes)
		want := "fresh"
		if minutes == 5 {
			want = "stale"
		}
		snapshot, err := s.Read(authorization.LegacyPrincipal, "dev")
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range snapshot.Items {
			if item.DataState != want {
				t.Fatal(item)
			}
		}
		links, err := s.Relationships(authorization.LegacyPrincipal, "dev", "", 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, link := range links.Items {
			if link.DataState != want {
				t.Fatal(link)
			}
		}
		report, err := s.Document(context.Background(), authorization.LegacyPrincipal, "dev")
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range report.Resources {
			if item.DataState != want {
				t.Fatal(item)
			}
		}
		if len(report.Sources) != len(collectorSources) {
			t.Fatal("report omitted collector provenance")
		}
	}
}

func TestRetentionPreservesNotesAssetsAuditAndReferencedProvenance(t *testing.T) {
	s := fixture(t)
	p := duePolicy(t, s)
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return observation(), nil })
	run, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-72 * time.Hour)
	s.DB.Model(&Run{}).Where("id=?", run.ID).Updates(map[string]any{"started_at": old, "finished_at": old})
	s.DB.Model(&Change{}).Where("server_id='dev'").Update("at", old)
	s.DB.Create(&Run{ID: "unused", ServerID: "dev", ActorID: p.ActorID, Status: "failed", StartedAt: old, FinishedAt: &old})
	s.DB.Create(&SourceResult{RunID: "unused", Source: "ssh", ServerID: "dev", Status: "failed", CollectedAt: old})
	s.DB.Create(&Run{ID: "other", ServerID: "other", ActorID: p.ActorID, Status: "failed", StartedAt: old, FinishedAt: &old})
	s.DB.Create(&DocumentNotes{ServerID: "dev", Notes: "preserve", Revision: 1, UpdatedAt: old})
	var auditBefore int64
	if err := s.DB.Table("operation_events").Count(&auditBefore).Error; err != nil || auditBefore == 0 {
		t.Fatal("missing fixture audit", auditBefore, err)
	}
	apply := func() {
		t.Helper()
		if err := s.DB.Transaction(func(tx *gorm.DB) error { return retainHistory(tx, p, time.Now().UTC()) }); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	var count int64
	s.DB.Model(&Change{}).Count(&count)
	if count == 0 {
		t.Fatal("default retention deleted history")
	}
	p.RetentionDays = 1
	apply()
	s.DB.Model(&Change{}).Count(&count)
	if count != 0 {
		t.Fatal("history not expired")
	}
	s.DB.Model(&Run{}).Where("id='unused'").Count(&count)
	if count != 0 {
		t.Fatal("unused run retained")
	}
	s.DB.Model(&SourceResult{}).Where("run_id='unused'").Count(&count)
	if count != 0 {
		t.Fatal("orphaned source outcomes")
	}
	s.DB.Model(&Run{}).Where("id IN ?", []string{run.ID, "other"}).Count(&count)
	if count != 2 {
		t.Fatal("referenced or foreign run removed")
	}
	s.DB.Model(&Resource{}).Count(&count)
	if count != 4 {
		t.Fatal("assets removed")
	}
	s.DB.Model(&DocumentNotes{}).Where("notes='preserve'").Count(&count)
	if count != 1 {
		t.Fatal("notes removed")
	}
	var auditAfter int64
	if err := s.DB.Table("operation_events").Count(&auditAfter).Error; err != nil {
		t.Fatal(err)
	}
	if auditBefore != auditAfter {
		t.Fatal("audit removed")
	}
}
