package backups

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
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
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func fixture(t *testing.T, local bool) (*Runtime, *auth.Access, Definition) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	root := t.TempDir()
	database, err := db.Init(filepath.Join(root, "fixture.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	t.Cleanup(func() { connection.Close() })
	password := "Backup fixture password only"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	cfg := &config.Config{EncryptionKey: key, PasswordHash: string(hash), DBPath: filepath.Join(root, "fixture.db"), BackupsEnabled: true, BackupWorkRoot: filepath.Join(root, "work"), OperationSupervisionEnabled: true}
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewService(database, cfg)
	login, err := sessions.Login("owner", password, "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	access, err := sessions.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	role := "backup-administrator"
	if local {
		role = "nexus-backup-administrator"
	}
	if err := database.Create(&authorization.Grant{ID: "backup-fixture-role", PrincipalID: access.User.ID, PrincipalKind: "user", RoleID: role, ScopeType: "global", CreatedBy: access.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if !local {
		pub, keyMaterial, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(keyMaterial, "")
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := nexuscrypto.Encrypt(key, pem.EncodeToMemory(block))
		if err != nil {
			t.Fatal(err)
		}
		public, _ := ssh.NewPublicKey(pub)
		if err := database.Create(&models.Server{ID: "server", Name: "Server", Host: "192.0.2.1", Port: 22, Username: "root", KnownHostKey: ssh.FingerprintSHA256(public), PrivateKeyEnc: sealed}).Error; err != nil {
			t.Fatal(err)
		}
	}
	source := Source{Kind: "files", Label: "Application files", Path: "/srv/fixture"}
	if local {
		source = Source{Kind: "nexus", Label: "Nexus"}
	}
	definition := Definition{Name: "Fixture backup", Repository: Repository{Kind: "local", Location: filepath.Join(root, "repository"), Password: "fixture-repository-password"}, Sources: []Source{source}, Timing: Timing{Mode: "manual"}, RuntimeSeconds: 60, AllowLiveFiles: true}
	return Configured(database, cfg, nil), access, definition
}
func TestPolicyScopeSecretsAndImmutableIdentity(t *testing.T) {
	r, a, definition := fixture(t, false)
	id := strings.Repeat("a", 32)
	view, err := r.Create(a, "server", id, definition)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(view)
	if strings.Contains(string(data), definition.Repository.Password) || strings.Contains(string(data), "configEnc") {
		t.Fatal("policy metadata leaked credentials")
	}
	if again, err := r.Create(a, "server", id, definition); err != nil || again.ID != id {
		t.Fatal("policy identity not stable", err)
	}
	changed := definition
	changed.Repository.Password = "other-password"
	if _, err := r.Create(a, "server", id, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("identity accepted different credentials", err)
	}
	if _, err := r.Policies(a, ""); !errors.Is(err, ErrDenied) {
		t.Fatal("server backup role accessed Nexus recovery", err)
	}
	var row Policy
	r.DB.First(&row, "id=?", view.ID)
	original := row.ConfigEnc
	r.DB.Model(&row).Update("name", "substituted")
	if _, err := r.Policies(a, "server"); !errors.Is(err, ErrConflict) {
		t.Fatal("metadata substitution accepted", err)
	}
	r.DB.Model(&row).Updates(map[string]any{"name": view.Name, "config_enc": original})
	r.DB.Model(&models.Server{}).Where("id='server'").Update("host", "192.0.2.2")
	if _, err := r.Start(a, "server", id, strings.Repeat("b", 32), "backup", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("changed host dispatched", err)
	}
}

type fakeController struct {
	*jobsupervisor.Service
	calls atomic.Int32
}

func (f *fakeController) DispatchBackup(_ context.Context, run models.SupervisedRun, command string, input []byte, _ int) (jobsupervisor.Snapshot, error) {
	if !f.Guard() || jobsupervisor.DigestWithInput(command, input) != run.CommandHash {
		return jobsupervisor.Snapshot{}, ErrDenied
	}
	now := time.Now().UTC()
	if err := f.DB.Model(&run).Update("dispatch_started_at", now).Error; err != nil {
		return jobsupervisor.Snapshot{}, err
	}
	snapshot := jobsupervisor.Snapshot{State: "unknown"}
	err := f.Save(run, snapshot)
	f.calls.Add(1)
	if err != nil {
		return snapshot, err
	}
	return snapshot, errors.New("acknowledgement lost")
}
func wait(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("backup condition did not settle")
}
func TestUnknownBackupSubmissionNeverReplaysAndKeepsHostReserved(t *testing.T) {
	r, a, definition := fixture(t, false)
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	controller := &fakeController{Service: jobsupervisor.NewService(r.DB, r.Key, nil)}
	r.controller = func(guard func() bool) jobController { controller.Guard = guard; return controller }
	id := strings.Repeat("b", 32)
	run, err := r.Start(a, "server", policy.ID, id, "backup", "")
	if err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { return controller.calls.Load() == 1 })
	wait(t, func() bool { _, active := activeRuns.Load(localKey{r.DB, id}); return !active })
	if _, err := r.Start(a, "server", policy.ID, id, "backup", ""); err != nil {
		t.Fatal("retained submission lost", err)
	}
	if _, err := r.Start(a, "server", policy.ID, strings.Repeat("c", 32), "backup", ""); !errors.Is(err, ErrBusy) {
		t.Fatal("unknown backup released host", err)
	}
	if controller.calls.Load() != 1 {
		t.Fatal("unknown command replayed")
	}
	current, err := r.Get("server", run.ID)
	if err != nil || current.FinishedAt != nil || current.State != "unknown" {
		t.Fatal("invented completion", err, current.State)
	}
}
func TestSchedulesPauseUntilCheckedAndRejectProtectedHosts(t *testing.T) {
	r, a, definition := fixture(t, false)
	definition.Timing = Timing{Mode: "interval", IntervalMinutes: 60}
	policy, err := r.Create(a, "server", strings.Repeat("a", 32), definition)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Enabled {
		t.Fatal("new policy scheduled before repository validation")
	}
	if err := r.SetEnabled(a, "server", policy.ID, true); !errors.Is(err, ErrInput) {
		t.Fatal("untested repository enabled", err)
	}
	now := time.Now().UTC()
	r.DB.Model(&Policy{}).Where("id=?", policy.ID).Update("last_check_at", now)
	if err := r.SetEnabled(a, "server", policy.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(a, "server", policy.ID, false); err != nil {
		t.Fatal(err)
	}
	var row Policy
	r.DB.First(&row, "id=?", policy.ID)
	if row.Enabled || row.LastState != "paused" {
		t.Fatal("pause not retained")
	}
	if err := r.DB.Create(&authorization.Group{ID: "protected", Name: "Protected", RequireMFA: true, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if err := r.DB.Exec("INSERT INTO server_group_members(group_id,server_id)VALUES('protected','server')").Error; err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnabled(a, "server", policy.ID, true); !errors.Is(err, ErrDenied) {
		t.Fatal("protected host gained unattended authority", err)
	}
	r.DB.Exec("DELETE FROM server_group_members WHERE group_id='protected'")
	r.DB.Where("id=?", "backup-fixture-role").Delete(&authorization.Grant{})
	if err := r.SetEnabled(a, "server", policy.ID, true); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked owner resumed schedule", err)
	}
}
func TestSourceAndRepositoryValidationDoesNotAcceptExecutableInput(t *testing.T) {
	_, _, base := fixture(t, false)
	cases := []func(*Definition){
		func(d *Definition) { d.Repository.Kind = "command"; d.Repository.Location = "exec:fixture" },
		func(d *Definition) {
			d.Repository.Kind = "s3"
			d.Repository.Location = "s3:https://user:secret@example.test/repository"
			d.Repository.AccessKey = "key"
			d.Repository.SecretKey = "secret"
		},
		func(d *Definition) { d.Sources = []Source{{Kind: "files", Path: "/proc/1/environ"}} },
		func(d *Definition) {
			d.Sources = []Source{{Kind: "postgres", Database: Database{Host: "localhost;command", User: "postgres", Port: 5432}}}
		},
		func(d *Definition) {
			d.Sources = []Source{{Kind: "docker-bind", ContainerID: "--privileged", Path: "/srv"}}
		},
		func(d *Definition) { d.Sources = []Source{{Kind: "nexus"}} },
		func(d *Definition) { d.AllowLiveFiles = false },
	}
	for _, mutate := range cases {
		data := base
		mutate(&data)
		if data.Validate(false) == nil {
			t.Fatal("invalid backup accepted")
		}
	}
}

func TestRepositoryCannotUseManagedStaging(t *testing.T) {
	for _, local := range []bool{false, true} {
		r, a, definition := fixture(t, local)
		server, root := "server", "/var/lib/nexus-backups"
		if local {
			server, root = "", r.WorkRoot
		}
		for _, location := range []string{root, root + "/jobs/" + strings.Repeat("b", 32), root + "/restores/repository"} {
			definition.Repository.Location = location
			if _, err := r.Create(a, server, strings.Repeat("a", 32), definition); !errors.Is(err, ErrInput) {
				t.Fatalf("managed repository accepted: %s: %v", location, err)
			}
		}
	}
}
