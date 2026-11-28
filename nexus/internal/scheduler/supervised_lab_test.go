package scheduler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func supervisedGuest(t *testing.T) (*nexusssh.Pool, nexusssh.ServerConfig) {
	t.Helper()
	address := os.Getenv("NEXUS_SUPERVISION_SSH")
	if address == "" {
		t.Skip("run scripts/supervision_lab.py")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" || len(os.Getenv("NEXUS_SUPERVISION_NONCE")) != 32 {
		t.Fatal("disposable guest required")
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(os.Getenv("NEXUS_SUPERVISION_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("NEXUS_SUPERVISION_HOST_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	pool.SetHostKeyCallback(func(id, fingerprint string) error {
		if id != "guest" || fingerprint != ssh.FingerprintSHA256(public) {
			return fmt.Errorf("guest host key mismatch")
		}
		return nil
	})
	target := nexusssh.ServerConfig{ID: "guest", Host: host, Port: number, User: "root", PrivKey: key}
	client, err := pool.GetContext(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := nexusssh.Run(context.Background(), client, "cat /nexus-fixture-nonce", nil, 5*time.Second)
	if err != nil || strings.TrimSpace(nonce) != os.Getenv("NEXUS_SUPERVISION_NONCE") {
		t.Fatal("guest marker mismatch", err)
	}
	t.Cleanup(func() { pool.Remove("guest"); clear(key) })
	return pool, target
}
func supervisedDatabase(t *testing.T, pool *nexusssh.Pool, target nexusssh.ServerConfig, command string) (*gorm.DB, []byte, models.ScheduledTask, string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "supervised.db")
	database, err := db.Init(path, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	t.Cleanup(func() { connection.Close(); clear(key) })
	sealed, err := nexuscrypto.Encrypt(key, target.PrivKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.Server{ID: target.ID, Host: target.Host, Port: target.Port, Username: target.User, PrivateKeyEnc: sealed}).Error; err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Add(-time.Minute)
	task := models.ScheduledTask{ID: "supervised-fixture", ServerID: target.ID, ActorID: authorization.LegacyPrincipal, CreatedBy: authorization.LegacyPrincipal, Command: command, Supervised: true, Enabled: true, IntervalMinutes: 60, NextRunAt: &due, LastStatus: "pending"}
	if err := database.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	return database, key, task, path
}

func TestSupervisedVMRestartRecoversWithoutReplay(t *testing.T) {
	pool, target := supervisedGuest(t)
	if os.Getenv("NEXUS_SUPERVISION_CHILD") == "1" {
		encoded, err := os.ReadFile(os.Getenv("NEXUS_SUPERVISION_CHILD_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		clear(encoded)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		database, err := db.Init(os.Getenv("NEXUS_SUPERVISION_CHILD_DB"), key)
		if err != nil {
			t.Fatal(err)
		}
		connection, _ := database.DB()
		defer connection.Close()
		var task models.ScheduledTask
		if err := database.First(&task, "id='supervised-fixture'").Error; err != nil {
			t.Fatal(err)
		}
		New(database, key, pool, true).runTask(task)
		return
	}
	nonce := os.Getenv("NEXUS_SUPERVISION_NONCE")
	command := "printf x >> /tmp/nexus-scheduler-" + nonce + "; printf recovered-output; sleep 15"
	database, key, task, path := supervisedDatabase(t, pool, target, command)
	keyFile := filepath.Join(t.TempDir(), "fixture-key.base64")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	child := exec.Command(os.Args[0], "-test.run=^TestSupervisedVMRestartRecoversWithoutReplay$", "-test.v")
	child.Env = append(os.Environ(), "NEXUS_SUPERVISION_CHILD=1", "NEXUS_SUPERVISION_CHILD_DB="+path, "NEXUS_SUPERVISION_CHILD_KEY="+keyFile)
	child.Stdout = &logs
	child.Stderr = &logs
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	var run models.SupervisedRun
	ready := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if database.Where("task_id=? AND state='running' AND verified_at IS NOT NULL", task.ID).First(&run).Error == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal("child did not observe its running unit", logs.String())
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	restarted := New(database, key, pool, true)
	restarted.reconcileSupervised()
	deadline = time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		restarted.reconcileSupervised()
		database.First(&task, "id=?", task.ID)
		_, active := restarted.activeSupervised.Load(run.ID)
		if task.RunID == "" && task.LastStatus == "ok" && !active {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if task.RunID != "" || task.LastStatus != "ok" {
		t.Fatal("restart did not reconcile original run", task.LastStatus)
	}
	if strings.Contains(task.LastOutput, "recovered-output") {
		t.Fatal("protected output duplicated into task plaintext")
	}
	database.First(&run, "id=?", run.ID)
	result, err := jobsupervisor.NewService(database, key, pool).Cached(run)
	if err != nil || !result.Terminal() || result.Output != "recovered-output" {
		t.Fatal("recovered output/proof lost", result.State, err)
	}
	client, err := pool.GetContext(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	count, err := nexusssh.Run(context.Background(), client, "cat /tmp/nexus-scheduler-"+nonce, nil, 5*time.Second)
	if err != nil || count != "x" {
		t.Fatal("restart replayed command", count, err)
	}
	t.Log("Killed the local scheduler process after dispatch; a fresh scheduler recovered the same unit and encrypted output without replay.")
}

func TestSupervisedVMRevocationStopsManagedChildren(t *testing.T) {
	pool, target := supervisedGuest(t)
	database, key, task, _ := supervisedDatabase(t, pool, target, "trap '' TERM; sleep 300 & wait")
	scheduler := New(database, key, pool, true)
	finished := make(chan struct{})
	go func() { scheduler.runTask(task); close(finished) }()
	var run models.SupervisedRun
	ready := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if database.Where("task_id=? AND state='running' AND verified_at IS NOT NULL", task.ID).First(&run).Error == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("supervised task did not start")
	}
	if err := database.Where("principal_id=? AND role_id=?", task.ActorID, "host-control").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(25 * time.Second):
		t.Fatal("revoked task did not terminate")
	}
	database.First(&task, "id=?", task.ID)
	database.First(&run, "id=?", run.ID)
	if task.Enabled || task.RunID != "" || run.State != "cancelled" || run.CancelRequestedAt == nil || run.FinishedAt == nil {
		t.Fatal("revocation did not produce durable verified cancellation", task.LastStatus, run.State)
	}
	result, err := jobsupervisor.NewService(database, key, pool).Cached(run)
	if err != nil || !result.Terminal() || !result.Empty {
		t.Fatal("revocation claimed unverified termination", result, err)
	}
}
