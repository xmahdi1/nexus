package ansible

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/operations"
	"golang.org/x/crypto/ssh"
)

type fixtureJob struct {
	*jobsupervisor.Service
	dispatches int
	unknown    bool
	input      []byte
}

func (j *fixtureJob) DispatchAnsible(_ context.Context, run models.SupervisedRun, command string, input []byte, _ int) (jobsupervisor.Snapshot, error) {
	j.dispatches++
	j.input = append([]byte(nil), input...)
	if jobsupervisor.DigestWithInput(command, input) != run.CommandHash || !j.Guard() {
		return jobsupervisor.Snapshot{}, ErrDenied
	}
	now := time.Now().UTC()
	j.DB.Model(&run).Update("dispatch_started_at", now)
	result := jobsupervisor.Snapshot{State: "running", Verified: true, InvocationID: strings.Repeat("f", 32)}
	if j.unknown {
		result = jobsupervisor.Snapshot{State: "unknown"}
	}
	if err := j.Save(run, result); err != nil {
		return result, err
	}
	if j.unknown {
		return result, errors.New("fixture lost acknowledgement")
	}
	return result, nil
}
func (j *fixtureJob) Inspect(ctx context.Context, run models.SupervisedRun, action string) (jobsupervisor.Snapshot, error) {
	if action == "cancel" && run.DispatchStartedAt != nil {
		result := jobsupervisor.Snapshot{State: "cancelled", Verified: true, Empty: true, InvocationID: strings.Repeat("f", 32)}
		return result, j.Save(run, result)
	}
	return j.Service.Inspect(ctx, run, action)
}

func TestExecutionReservesAllHostsAndNeverReplaysUnknownDispatch(t *testing.T) {
	s, a, approver, project, revision := fixture(t)
	plan, err := s.Prepare(a, "controller", project.ID, planInput(revision))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(approver, "controller", plan.ID, plan.Digest, revision.Digest); err != nil {
		t.Fatal(err)
	}
	r := NewRuntime(s, nil, true)
	job := &fixtureJob{Service: jobsupervisor.NewService(s.DB, s.Key, nil), unknown: true}
	r.controller = func(guard func() bool) jobController { job.Guard = guard; return job }
	r.input = func(_ context.Context, _ Plan, identity string, _ map[string]string) ([]byte, error) {
		var locks []models.ExecutionHostLock
		if s.DB.Where("run_id=?", identity).Find(&locks).Error != nil || len(locks) != 2 {
			t.Fatal("credentials requested before controller and target reservations", locks)
		}
		return []byte("fixture-private-execution-input"), nil
	}
	id := strings.Repeat("a", 32)
	run, err := r.Start(context.Background(), a, "controller", plan.ID, id, nil)
	if err == nil || run.State != "unknown" || run.FinishedAt != nil || job.dispatches != 1 {
		t.Fatal("lost acknowledgement invented completion", run.State, err)
	}
	if existing, err := r.Start(context.Background(), a, "controller", plan.ID, id, nil); err != nil || existing.ID != run.ID || job.dispatches != 1 {
		t.Fatal("same identity replayed", err)
	}
	if _, err := r.Start(context.Background(), a, "controller", plan.ID, strings.Repeat("b", 32), nil); !errors.Is(err, ErrConflict) {
		t.Fatal("one plan admitted twice", err)
	}
	op := operations.New(s.DB, s.Key, nil, s.Sessions, true, true)
	if _, err := op.Start(context.Background(), a.User.ID, a.Session.ID, "dev", strings.Repeat("c", 32), "ansible-environment-health", "", ""); !errors.Is(err, operations.ErrBusy) {
		t.Fatal("target lock ignored by interactive operation", err)
	}
	if _, err := r.Observe(context.Background(), run, "cancel"); err != nil {
		t.Fatal(err)
	}
	var count int64
	s.DB.Model(&models.ExecutionHostLock{}).Where("run_id=?", id).Count(&count)
	if count != 0 {
		t.Fatal("verified cancellation retained host locks")
	}
	if _, err := r.Start(context.Background(), a, "controller", plan.ID, strings.Repeat("d", 32), nil); !errors.Is(err, ErrConflict) {
		t.Fatal("cancelled plan replayed", err)
	}
	if len(jobCommand()) > 16384 {
		t.Fatal("fixed adapter exceeds command channel limit", len(jobCommand()))
	}
}

func TestExecutionRevocationDuringPreparationNeverDispatches(t *testing.T) {
	s, a, b, p, rev := fixture(t)
	plan, err := s.Prepare(a, "controller", p.ID, planInput(rev))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Approve(b, "controller", plan.ID, plan.Digest, rev.Digest); err != nil {
		t.Fatal(err)
	}
	r := NewRuntime(s, nil, true)
	job := &fixtureJob{Service: jobsupervisor.NewService(s.DB, s.Key, nil)}
	r.controller = func(guard func() bool) jobController { job.Guard = guard; return job }
	r.input = func(context.Context, Plan, string, map[string]string) ([]byte, error) {
		if err := s.DB.Where("principal_id=? AND role_id='ansible-approver'", b.User.ID).Delete(&authorization.Grant{}).Error; err != nil {
			t.Fatal(err)
		}
		return []byte("fixture-only"), nil
	}
	run, err := r.Start(context.Background(), a, "controller", plan.ID, strings.Repeat("e", 32), nil)
	if err == nil || job.dispatches != 0 || run.State != "not_started" || run.FinishedAt == nil {
		t.Fatal("revoked approval dispatched", run.State, err)
	}
	var count int64
	s.DB.Model(&models.ExecutionHostLock{}).Count(&count)
	if count != 0 {
		t.Fatal("proved no-dispatch retained locks")
	}
}

func TestAbandonedExecutionReservationRetiresWithoutReplay(t *testing.T) {
	s, a, b, p, rev := fixture(t)
	plan, err := s.Prepare(a, "controller", p.ID, planInput(rev))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b, "controller", plan.ID, plan.Digest, rev.Digest); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("7", 32)
	run := models.SupervisedRun{ID: id, Kind: "ansible", ServerID: "controller", ActorID: a.User.ID, SourceSessionID: a.Session.ID, OperationContext: plan.ID, State: "prepared", CommandHash: jobsupervisor.Digest("reserved-private-input"), CreatedAt: time.Now().Add(-3 * time.Minute)}
	if err := s.DB.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Exec("INSERT INTO ansible_run_plans(run_id,plan_id) VALUES(?,?)", id, plan.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, server := range []string{"controller", "dev"} {
		if err := s.DB.Create(&models.ExecutionHostLock{ServerID: server, RunID: id}).Error; err != nil {
			t.Fatal(err)
		}
	}
	r := NewRuntime(s, nil, true)
	result, err := r.Observe(context.Background(), run, "inspect")
	if err != nil || result.State != "not_started" || !result.NoDispatch {
		t.Fatal("abandoned reservation was not retired locally", result.State, err)
	}
	run, err = r.Get("controller", id)
	if err != nil {
		t.Fatal(err)
	}
	if run.FinishedAt == nil || run.DispatchStartedAt != nil || !run.ArtifactsRemoved {
		t.Fatal("invalid pre-dispatch retirement")
	}
	var count int64
	s.DB.Model(&models.ExecutionHostLock{}).Count(&count)
	if count != 0 {
		t.Fatal("retired reservation retained target locks")
	}
	r.input = func(context.Context, Plan, string, map[string]string) ([]byte, error) {
		t.Fatal("recovery replayed private preparation")
		return nil, nil
	}
	if _, err := r.Start(context.Background(), a, "controller", plan.ID, id, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(context.Background(), a, "controller", plan.ID, strings.Repeat("8", 32), nil); !errors.Is(err, ErrConflict) {
		t.Fatal("single-use retired plan replayed", err)
	}
}

func pinnedFixture(t *testing.T) (models.Server, []byte, ssh.PublicKey, *atomic.Int32) {
	t.Helper()
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPrivate)
	_, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := ssh.NewSignerFromKey(clientPrivate)
	pemKey, err := ssh.MarshalPrivateKey(clientPrivate, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(pemKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	commands := &atomic.Int32{}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(clientSigner.PublicKey().Marshal()) {
			return nil, ErrDenied
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				connection, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer connection.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					commands.Add(1)
					channel.Reject(ssh.Prohibited, "no command channels")
				}
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	server := models.Server{ID: "dev", Host: "127.0.0.1", Port: port, Username: "fixture", KnownHostKey: ssh.FingerprintSHA256(hostSigner.PublicKey())}
	return server, key, hostSigner.PublicKey(), commands
}

func TestFreshTargetAuthenticatesExistingPinWithoutStartingCommands(t *testing.T) {
	server, key, public, commands := pinnedFixture(t)
	resolved, err := freshTarget(context.Background(), server, key)
	if err != nil || resolved.PrivateKey != string(key) || !strings.Contains(resolved.KnownHosts, string(ssh.MarshalAuthorizedKey(public))) {
		t.Fatal("pinned credential resolution failed", err)
	}
	server.KnownHostKey = "SHA256:" + strings.Repeat("a", 43)
	if _, err = freshTarget(context.Background(), server, key); err == nil {
		t.Fatal("changed target host key accepted")
	}
	if commands.Load() != 0 {
		t.Fatal("credential preflight started a target command")
	}
}

func TestApprovedExecutionResolvesOnlySelectedCredentialsIntoPrivateStdin(t *testing.T) {
	s, a, b, p, rev := fixture(t)
	server, key, public, commands := pinnedFixture(t)
	cipher, err := nexuscrypto.Encrypt(s.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"host": server.Host, "port": server.Port, "username": server.Username, "known_host_key": server.KnownHostKey, "private_key_enc": cipher}).Error; err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(private, "controller-fixture")
	if err != nil {
		t.Fatal(err)
	}
	controllerKey := pem.EncodeToMemory(block)
	controllerCipher, err := nexuscrypto.Encrypt(s.Key, controllerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&models.Server{}).Where("id='controller'").Update("private_key_enc", controllerCipher).Error; err != nil {
		t.Fatal(err)
	}
	plan, err := s.Prepare(a, "controller", p.ID, planInput(rev))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(b, "controller", plan.ID, plan.Digest, rev.Digest); err != nil {
		t.Fatal(err)
	}
	r := NewRuntime(s, nil, true)
	job := &fixtureJob{Service: jobsupervisor.NewService(s.DB, s.Key, nil)}
	r.controller = func(guard func() bool) jobController { job.Guard = guard; return job }
	run, err := r.Start(context.Background(), a, "controller", plan.ID, strings.Repeat("9", 32), nil)
	if err != nil || run.State != "running" || job.dispatches != 1 {
		t.Fatal("approved private preparation failed", run.State, err)
	}
	defer clear(job.input)
	var payload struct {
		Targets   []privateTarget `json:"targets"`
		Variables map[string]any  `json:"variables"`
	}
	if err := json.Unmarshal(job.input, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Targets) != 1 || payload.Targets[0].PrivateKey != string(key) || !strings.Contains(payload.Targets[0].KnownHosts, string(ssh.MarshalAuthorizedKey(public))) || payload.Variables["message"] != "fixture-private-variable" {
		t.Fatal("wrong private target/variable delivery")
	}
	if strings.Contains(string(job.input), string(controllerKey)) || strings.Contains(string(job.input), a.Session.ID) || commands.Load() != 0 {
		t.Fatal("controller authority exported or target command started")
	}
	metadata, _ := json.Marshal(run)
	if strings.Contains(string(metadata), "fixture-private-variable") || strings.Contains(string(metadata), "PRIVATE KEY") {
		t.Fatal("private execution input persisted as metadata")
	}
	if _, err := r.Observe(context.Background(), run, "cancel"); err != nil {
		t.Fatal(err)
	}
}
