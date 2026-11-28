package operations

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/githubrunner"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type fixtureController struct {
	runnerInput *[]byte
	*jobsupervisor.Service
	guard      func() bool
	dispatches *atomic.Int32
	controls   chan string
	lost       bool
}

func (f *fixtureController) DispatchRunner(ctx context.Context, run models.SupervisedRun, command string, input []byte, runtime int) (jobsupervisor.Snapshot, error) {
	if f.runnerInput != nil {
		*f.runnerInput = append([]byte{}, input...)
	}
	return f.Dispatch(ctx, run, command)
}

func TestRunnerSetupKeepsTokenPrivateAndNeverReplays(t *testing.T) {
	s, a, calls, _ := operationFixture(t)
	setup := githubrunner.Setup{Profile: githubrunner.Profile{URL: "https://github.com/example/repository", Name: "build", Labels: []string{"trusted"}, LifetimeSeconds: 900}, RequestID: strings.Repeat("f", 32), RegistrationToken: strings.Repeat("T", 26)}
	if _, err := s.StartRunner(context.Background(), a.User.ID, a.Session.ID, "dev", setup); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("ungranted runner admitted", err)
	}
	grant := authorization.Grant{ID: "runner-grant", PrincipalID: a.User.ID, PrincipalKind: "legacy", RoleID: "github-runners", ScopeType: "server", ScopeID: "dev", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	if err := s.DB.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartRunner(context.Background(), a.User.ID, a.Session.ID, "dev", setup); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("disabled automation admitted runner", err)
	}
	s.AutomationEnabled = true
	var received []byte
	cipher, keyErr := nexuscrypto.Encrypt(bytes.Repeat([]byte{6}, 32), []byte("runner fixture SSH key"))
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if err := s.DB.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"username": "root", "private_key_enc": cipher, "known_host_key": "SHA256:" + strings.Repeat("a", 43)}).Error; err != nil {
		t.Fatal(err)
	}
	old := s.newController
	s.newController = func(guard func() bool) controller {
		f := old(guard).(*fixtureController)
		f.runnerInput = &received
		return f
	}
	run, err := s.StartRunner(context.Background(), a.User.ID, a.Session.ID, "dev", setup)
	if err != nil || calls.Load() != 1 || !strings.Contains(string(received), setup.RegistrationToken) {
		t.Fatal("private runner dispatch failed", err)
	}
	if strings.Contains(run.OperationContext, setup.RegistrationToken) || strings.Contains(githubrunner.Command(), setup.RegistrationToken) {
		t.Fatal("registration token entered metadata/argv")
	}
	if _, err := s.StartRunner(context.Background(), a.User.ID, a.Session.ID, "dev", setup); err != nil || calls.Load() != 1 {
		t.Fatal("enrollment replayed", err)
	}
	setup.RegistrationToken = strings.Repeat("N", 26)
	if _, err := s.StartRunner(context.Background(), a.User.ID, a.Session.ID, "dev", setup); !errors.Is(err, ErrConflict) || calls.Load() != 1 {
		t.Fatal("changed input reused runner identity", err)
	}
	if err := s.DB.Delete(&grant).Error; err != nil {
		t.Fatal(err)
	}
	if s.Allowed(run) {
		t.Fatal("runner authority survived revocation")
	}
}

func (f *fixtureController) Dispatch(ctx context.Context, run models.SupervisedRun, command string) (jobsupervisor.Snapshot, error) {
	f.dispatches.Add(1)
	if f.guard == nil || !f.guard() {
		result := jobsupervisor.Snapshot{State: "not_started", NoDispatch: true}
		return result, f.Save(run, result)
	}
	now := time.Now().UTC()
	if err := f.DB.Model(&run).Updates(map[string]any{"dispatch_started_at": now, "state": "dispatching"}).Error; err != nil {
		return jobsupervisor.Snapshot{}, err
	}
	result := jobsupervisor.Snapshot{State: "running", Verified: true, InvocationID: strings.Repeat("b", 32), Output: "private operation output"}
	if f.lost {
		result = jobsupervisor.Snapshot{State: "unknown"}
		return result, errors.Join(f.Save(run, result), errors.New("fixture lost acknowledgement"))
	}
	return result, f.Save(run, result)
}
func (f *fixtureController) Inspect(ctx context.Context, run models.SupervisedRun, action string) (jobsupervisor.Snapshot, error) {
	if f.controls != nil {
		f.controls <- action
	}
	if action == "cancel" {
		result := jobsupervisor.Snapshot{State: "cancelled", Verified: true, Empty: true, InvocationID: run.InvocationID}
		return result, f.Save(run, result)
	}
	return f.Cached(run)
}
func operationFixture(t *testing.T) (*Service, *auth.Access, *atomic.Int32, chan string) {
	t.Helper()
	key := bytes.Repeat([]byte{6}, 32)
	database, err := db.Init(filepath.Join(t.TempDir(), "operations.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	t.Cleanup(func() { connection.Close() })
	if err := database.Create(&models.Server{ID: "dev", Name: "Fixture", Host: "192.0.2.1", Username: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("operation fixture password"), bcrypt.MinCost)
	sessions := auth.NewService(database, &config.Config{EncryptionKey: key, PasswordHash: string(hash)})
	login, err := sessions.Login("", "operation fixture password", "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	access, err := sessions.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	service := New(database, key, nil, sessions, true)
	calls := &atomic.Int32{}
	controls := make(chan string, 16)
	service.newController = func(guard func() bool) controller {
		return &fixtureController{Service: jobsupervisor.NewService(database, key, nil), guard: guard, dispatches: calls, controls: controls}
	}
	return service, access, calls, controls
}
func TestRequestIdentitySurvivesLostAcknowledgementWithoutReplay(t *testing.T) {
	s, a, calls, _ := operationFixture(t)
	old := s.newController
	s.newController = func(guard func() bool) controller { f := old(guard).(*fixtureController); f.lost = true; return f }
	id := strings.Repeat("a", 32)
	first, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "compose-up", "/opt/fixture/compose.yml", "")
	if err == nil || first.ID != id || first.State != "unknown" {
		t.Fatal("lost acknowledgement discarded identity", err)
	}
	second, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "compose-up", "/opt/fixture/compose.yml", "")
	if err != nil || second.ID != first.ID || calls.Load() != 1 {
		t.Fatal("identical request replayed command", err, calls.Load())
	}
	if _, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "compose-down", "/opt/fixture/compose.yml", ""); !errors.Is(err, ErrConflict) {
		t.Fatal("request ID reused for another action", err)
	}
	if _, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", strings.Repeat("c", 32), "compose-up", "/opt/other.yml", ""); !errors.Is(err, ErrBusy) {
		t.Fatal("unresolved host admitted another command", err)
	}
}

func TestAnsibleEnvironmentRequiresOptInAndSeparateGrants(t *testing.T) {
	s, a, calls, _ := operationFixture(t)
	id := strings.Repeat("d", 32)
	if _, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "ansible-environment-install", "", ""); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("ungranted environment action admitted", err)
	}
	grant := authorization.Grant{ID: "ansible-environment-grant", PrincipalID: a.User.ID, PrincipalKind: "legacy", RoleID: "ansible-environment", ScopeType: "server", ScopeID: "dev", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	if err := s.DB.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "ansible-environment-install", "", ""); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("disabled automation admitted action", err)
	}
	s.AutomationEnabled = true
	run, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "ansible-environment-install", "", "")
	if err != nil || !s.Allowed(run) || calls.Load() != 1 {
		t.Fatal("authorized environment action failed", err)
	}
	if _, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", id, "ansible-environment-install", "", ""); err != nil || calls.Load() != 1 {
		t.Fatal("environment installation replayed", err)
	}
	s.AutomationEnabled = false
	if s.Allowed(run) {
		t.Fatal("feature removal retained authority")
	}
	s.AutomationEnabled = true
	if err := s.DB.Delete(&grant).Error; err != nil {
		t.Fatal(err)
	}
	if s.Allowed(run) {
		t.Fatal("environment grant removal retained authority")
	}
}
func TestRestartReconciliationCancelsRevokedAndDisabledOperations(t *testing.T) {
	for _, reason := range []string{"session", "grant", "disabled", "cancel_requested"} {
		t.Run(reason, func(t *testing.T) {
			s, a, _, controls := operationFixture(t)
			run, err := s.Start(context.Background(), a.User.ID, a.Session.ID, "dev", strings.Repeat("a", 32), "compose-up", "/opt/fixture.yml", "")
			if err != nil {
				t.Fatal(err)
			}
			if reason == "session" {
				if err := s.Sessions.Revoke(a, a.Session.ID, false); err != nil {
					t.Fatal(err)
				}
			}
			if reason == "grant" {
				if err := s.DB.Where("principal_id=? AND role_id='host-control'", a.User.ID).Delete(&authorization.Grant{}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if reason == "disabled" {
				s.Enabled = false
			}
			if reason == "cancel_requested" {
				now := time.Now().UTC()
				if err := s.DB.Model(&run).Update("cancel_requested_at", now).Error; err != nil {
					t.Fatal(err)
				}
				if !s.Allowed(run) {
					t.Fatal("fixture unexpectedly lost authority")
				}
			}
			if reason != "cancel_requested" && s.Allowed(run) {
				t.Fatal("revoked operation still allowed")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.Reconcile(ctx)
			select {
			case action := <-controls:
				if action != "cancel" {
					t.Fatal("revocation did not request cancellation")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("reconciliation stalled")
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				latest, e := s.Get("dev", run.ID)
				if e == nil && latest.FinishedAt != nil && latest.State == "cancelled" {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("terminal cancellation not retained")
		})
	}
}
func TestOrphanReservationIsResolvedWithoutSubmittingCommand(t *testing.T) {
	s, a, calls, _ := operationFixture(t)
	run := models.SupervisedRun{ID: strings.Repeat("a", 32), Kind: "operation", Action: "compose-up", SourceSessionID: a.Session.ID, ServerID: "dev", ActorID: a.User.ID, State: "prepared", CreatedAt: time.Now().Add(-2 * time.Minute), CommandHash: jobsupervisor.Digest("fixture")}
	if err := s.DB.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	result, err := s.Observe(context.Background(), run, "inspect")
	if err != nil || !result.NoDispatch || result.State != "not_started" || calls.Load() != 0 {
		t.Fatal("orphan reservation dispatched or unresolved", err)
	}
	if _, err := s.Get("another-server", run.ID); err == nil {
		t.Fatal("cross-server run visible")
	}
}
