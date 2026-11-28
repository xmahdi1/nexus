package scheduler

import (
	"bytes"
	"context"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/identity"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
)

func schedulerFixture(t *testing.T) (*Scheduler, models.ScheduledTask) {
	t.Helper()
	database, err := db.Init(filepath.Join(t.TempDir(), "scheduler.db"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	t.Cleanup(func() { c.Close() })
	if err := database.Create(&models.Server{ID: "dev", Name: "Lab", Host: "192.0.2.10", Username: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	due := time.Now().Add(-time.Minute)
	task := models.ScheduledTask{ID: "task", ServerID: "dev", ActorID: authorization.LegacyPrincipal, CreatedBy: authorization.LegacyPrincipal, Command: "NEVER EXECUTE THIS FIXTURE", IntervalMinutes: 60, Enabled: true, NextRunAt: &due, LastStatus: "pending"}
	if err := database.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	return New(database, nil, nil), task
}
func TestQueuedTaskRechecksActorAndScope(t *testing.T) {
	s, task := schedulerFixture(t)
	executed := false
	s.execute = func(context.Context, models.ScheduledTask) (string, error) { executed = true; return "", nil }
	if err := s.db.Where("principal_id=? AND role_id=?", task.ActorID, "host-control").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	s.runTask(task)
	var stored models.ScheduledTask
	s.db.First(&stored, "id=?", task.ID)
	if executed || stored.LastStatus != "denied" {
		t.Fatal("revoked queued task executed")
	}
	var events int64
	s.db.Table("authorization_events").Where("actor_id=? AND outcome='denied'", task.ActorID).Count(&events)
	if events != 1 {
		t.Fatal("denied task not recorded")
	}
}

func TestAnsibleTargetReservationBlocksScheduledClaims(t *testing.T) {
	s, task := schedulerFixture(t)
	executed := false
	s.execute = func(context.Context, models.ScheduledTask) (string, error) { executed = true; return "", nil }
	if err := s.db.Create(&models.ExecutionHostLock{ServerID: task.ServerID, RunID: "fixture-ansible-run"}).Error; err != nil {
		t.Fatal(err)
	}
	s.runTask(task)
	var current models.ScheduledTask
	s.db.First(&current, "id=?", task.ID)
	if executed || current.LastStatus != "pending" || current.RunID != "" {
		t.Fatal("reserved Ansible target received a scheduled command")
	}
}
func TestRunningTaskStopsWhenAccessRevoked(t *testing.T) {
	s, task := schedulerFixture(t)
	started := make(chan struct{})
	finished := make(chan struct{})
	s.execute = func(ctx context.Context, _ models.ScheduledTask) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}
	go func() { s.runTask(task); close(finished) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not start")
	}
	if err := s.db.Where("principal_id=? AND role_id=?", task.ActorID, "host-control").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked execution stayed running")
	}
	var stored models.ScheduledTask
	s.db.First(&stored, "id=?", task.ID)
	if stored.LastStatus != "cancelled" {
		t.Fatalf("wrong terminal state: %s", stored.LastStatus)
	}
}
func TestConflictingTaskClaimsAreSerialized(t *testing.T) {
	s, task := schedulerFixture(t)
	var calls atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	s.execute = func(context.Context, models.ScheduledTask) (string, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		return "fixture output", nil
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.runTask(task) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("fixture did not start")
	}
	go func() { defer wg.Done(); s.runTask(task) }()
	// The database claim, not a goroutine sleep, determines eligibility.
	other := task
	other.ID = "other"
	if err := s.db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	s.runTask(other)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate/conflicting execution: %d", calls.Load())
	}
}
func TestExpiredLeaseNeverSilentlyRetries(t *testing.T) {
	s, task := schedulerFixture(t)
	executed := false
	s.execute = func(context.Context, models.ScheduledTask) (string, error) { executed = true; return "", nil }
	expired := time.Now().Add(-time.Minute)
	s.db.Model(&task).Updates(map[string]any{"last_status": "running", "lease_until": expired})
	s.runDueTasks()
	var stored models.ScheduledTask
	s.db.First(&stored, "id=?", task.ID)
	if executed || stored.Enabled || stored.LastStatus != "interrupted" {
		t.Fatal("uncertain execution retried")
	}
}

func TestInvitedActorDisablementStopsQueuedAndRunningTasks(t *testing.T) {
	s, task := schedulerFixture(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("scheduler owner password"), bcrypt.MinCost)
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: bytes.Repeat([]byte{3}, 32)}
	if _, err := identity.BootstrapOwner(s.db, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if err := auth.ActivateOwner(s.db, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(s.db, cfg)
	login, err := service.Login("owner", "scheduler owner password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := service.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := service.CreateInvitation(admin, auth.InviteOptions{Username: "worker", RoleID: "admin", ScopeType: "server", ScopeID: "dev"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptInvitation(invitation.Token, "worker fixture password"); err != nil {
		t.Fatal(err)
	}
	if _, err := authorization.New(s.db).AddGrant(admin.User.ID, invitation.Invitation.UserID, "host-control", "server", "dev", ""); err != nil {
		t.Fatal(err)
	}
	task.ActorID = invitation.Invitation.UserID
	if err := s.db.Model(&task).Update("actor_id", task.ActorID).Error; err != nil {
		t.Fatal(err)
	}
	started, finished := make(chan struct{}), make(chan struct{})
	s.execute = func(ctx context.Context, _ models.ScheduledTask) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}
	go func() { s.runTask(task); close(finished) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("task did not start")
	}
	if err := service.ChangeStatus(admin, task.ActorID, "disabled", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("disabled actor kept executing")
	}
	queued := task
	queued.ID = "queued"
	queued.LastStatus = "pending"
	queued.LeaseUntil = nil
	if err := s.db.Create(&queued).Error; err != nil {
		t.Fatal(err)
	}
	s.execute = func(context.Context, models.ScheduledTask) (string, error) {
		t.Error("disabled queued actor executed")
		return "", nil
	}
	s.runTask(queued)
	var stored models.ScheduledTask
	s.db.First(&stored, "id=?", queued.ID)
	if stored.LastStatus != "denied" {
		t.Fatal("queued task not denied", stored.LastStatus)
	}
}

func TestProtectedTargetDoesNotRunWithoutInteractiveProof(t *testing.T) {
	s, task := schedulerFixture(t)
	if err := s.db.Exec(`INSERT INTO server_groups(id,name,require_mfa,created_at) VALUES('protected','Production',1,CURRENT_TIMESTAMP);INSERT INTO server_group_members(group_id,server_id)VALUES('protected','dev')`).Error; err != nil {
		t.Fatal(err)
	}
	executed := false
	s.execute = func(context.Context, models.ScheduledTask) (string, error) { executed = true; return "", nil }
	s.runTask(task)
	var stored models.ScheduledTask
	s.db.First(&stored, "id=?", task.ID)
	if executed || stored.LastStatus != "denied" {
		t.Fatal("protected target ran unattended")
	}
}
