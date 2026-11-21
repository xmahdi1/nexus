package operations

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
)

func TestInteractiveVMRecoveryAndSessionRevocation(t *testing.T) {
	address := os.Getenv("NEXUS_SUPERVISION_SSH")
	if address == "" {
		t.Skip("run scripts/supervision_lab.py")
	}
	host, port, err := net.SplitHostPort(address)
	nonce := os.Getenv("NEXUS_SUPERVISION_NONCE")
	if err != nil || host != "127.0.0.1" || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(nonce) {
		t.Fatal("owned loopback fixture required")
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(os.Getenv("NEXUS_SUPERVISION_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("NEXUS_SUPERVISION_HOST_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	defer pool.Remove("dev")
	pool.SetHostKeyCallback(func(id, fingerprint string) error {
		if id != "dev" || fingerprint != ssh.FingerprintSHA256(public) {
			return fmt.Errorf("fixture host key mismatch")
		}
		return nil
	})
	target := nexusssh.ServerConfig{ID: "dev", Host: host, Port: number, User: "root", PrivKey: private}
	client, err := pool.GetContext(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := nexusssh.Run(context.Background(), client, "cat /nexus-fixture-nonce", nil, 5*time.Second)
	if err != nil || strings.TrimSpace(marker) != nonce {
		t.Fatal("fixture ownership mismatch")
	}
	// Only this owned, disposable guest receives the adapter stub. The cgroup,
	// systemd and SSH lifecycle are real; no Docker daemon is installed or shared.
	directory := "/tmp/nexus-interactive-" + nonce
	stub := "#!/bin/sh\nprintf x >> " + directory + "/calls\ncase \"$3\" in restart) printf adapter-running; sleep 300 & setsid sh -c 'sleep 300' & wait;; *) printf adapter-complete;; esac\n"
	command := "[ ! -e /usr/local/bin/docker ] && [ ! -L /usr/local/bin/docker ] && mkdir -p /usr/local/bin " + directory + " && umask 077 && cat > /usr/local/bin/docker && chmod 700 /usr/local/bin/docker"
	if _, err := nexusssh.Run(context.Background(), client, command, strings.NewReader(stub), 5*time.Second); err != nil {
		t.Fatal("could not prepare owned adapter stub")
	}
	defer func() {
		_, _ = nexusssh.Run(context.Background(), client, "rm -f /usr/local/bin/docker", nil, 5*time.Second)
	}()
	fixture, access, _, _ := operationFixture(t)
	key := bytes.Repeat([]byte{6}, 32)
	sealed, err := nexuscrypto.Encrypt(key, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.DB.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"host": host, "port": number, "username": "root", "private_key_enc": sealed}).Error; err != nil {
		t.Fatal(err)
	}
	service := New(fixture.DB, key, pool, fixture.Sessions, true)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	id := strings.Repeat("a", 32)
	run, err := service.Start(ctx, access.User.ID, access.Session.ID, "dev", id, "compose-up", directory+"/compose.yml", "")
	if err != nil {
		t.Fatal("interactive adapter submission failed", err)
	}
	wait := func(id, state string) models.SupervisedRun {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			current, e := service.Get("dev", id)
			if e != nil {
				t.Fatal(e)
			}
			if current.FinishedAt != nil {
				if current.State != state {
					t.Fatal("unexpected terminal state", current.State)
				}
				return current
			}
			if state != "cancelled" {
				if _, e := service.Observe(ctx, current, "inspect"); e != nil {
					t.Fatal("could not inspect interactive adapter", e)
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("interactive adapter did not settle")
		return models.SupervisedRun{}
	}
	run = wait(run.ID, "exited")
	observation, err := service.Observe(ctx, run, "cached")
	if err != nil || observation.Output != "adapter-complete" || !observation.Terminal() {
		t.Fatal("saved adapter result missing", err)
	}
	// The environment action uses the same real durable unit/cgroup protocol.
	// Older guest Python is reported as unsupported without creating an account.
	if err := fixture.DB.Create(&authorization.Grant{ID: "environment-lab", PrincipalID: access.User.ID, PrincipalKind: "legacy", RoleID: "ansible-environment", ScopeType: "server", ScopeID: "dev", CreatedBy: access.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	service.AutomationEnabled = true
	envRun, err := service.Start(ctx, access.User.ID, access.Session.ID, "dev", strings.Repeat("e", 32), "ansible-environment-health", "", "")
	if err != nil {
		t.Fatal("environment health dispatch", err)
	}
	envRun = wait(envRun.ID, "exited")
	envObservation, err := service.Observe(ctx, envRun, "cached")
	if err != nil || (!strings.Contains(envObservation.Output, `"state": "unsupported"`) && !strings.Contains(envObservation.Output, `"state": "absent"`)) {
		t.Fatal("environment prerequisites were not reported", err)
	}
	if _, err := service.Observe(ctx, envRun, "release"); err != nil {
		t.Fatal(err)
	}
	// A replacement controller may observe/reuse identity, but never dispatch it.
	pool.Remove("dev")
	service = New(fixture.DB, key, pool, fixture.Sessions, true)
	if _, err := service.Start(ctx, access.User.ID, access.Session.ID, "dev", id, "compose-up", directory+"/compose.yml", ""); err != nil {
		t.Fatal("restart lost run identity", err)
	}
	longID := strings.Repeat("c", 32)
	running, err := service.Start(ctx, access.User.ID, access.Session.ID, "dev", longID, "container-restart", "", "abcdef123456")
	if err != nil {
		t.Fatal("long adapter did not start", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		observed, e := service.Observe(ctx, running, "inspect")
		if e != nil {
			t.Fatal("long adapter could not be inspected", e)
		}
		running, e = service.Get("dev", longID)
		if e != nil {
			t.Fatal(e)
		}
		if observed.State == "running" && observed.InvocationID != "" && strings.Contains(observed.Output, "adapter-running") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if running.InvocationID == "" || running.State != "running" {
		t.Fatal("long adapter has no verified running invocation", running.State, running.Detail)
	}
	pool.Remove("dev")
	service = New(fixture.DB, key, pool, fixture.Sessions, true)
	if err := fixture.Sessions.Revoke(access, access.Session.ID, false); err != nil {
		t.Fatal(err)
	}
	service.Run(ctx)
	running = wait(running.ID, "cancelled")
	observation, err = service.Observe(ctx, running, "cached")
	if err != nil || !observation.Terminal() {
		t.Fatal("revocation did not verify an empty command cgroup", err)
	}
	client, err = pool.GetContext(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	count, err := nexusssh.Run(ctx, client, "cat "+directory+"/calls", nil, 5*time.Second)
	if err != nil || count != "xx" {
		t.Fatal("adapter command replayed", err)
	}
	if released, err := service.Observe(ctx, running, "release"); err != nil || !released.Released {
		t.Fatal("owned artifacts not released", err)
	}
	t.Log("Interactive Compose/container adapter stubs: real pinned SSH/systemd/cgroup completion, encrypted output, disconnect/restart without replay and persisted-session revocation cancellation passed. Docker daemon side effects are outside this fixture.")
}
