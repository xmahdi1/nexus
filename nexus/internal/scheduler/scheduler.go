package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

type Scheduler struct {
	db                *gorm.DB
	encKey            []byte
	pool              *nexusssh.Pool
	supervisedEnabled bool
	activeSupervised  sync.Map
	reconcileSlots    chan struct{}
	slots             chan struct{}
	// Injection boundary used only by local tests; production uses execSSH.
	execute func(context.Context, models.ScheduledTask) (string, error)
}

func New(db *gorm.DB, key []byte, pool *nexusssh.Pool, enabled ...bool) *Scheduler {
	s := &Scheduler{db: db, encKey: key, pool: pool, slots: make(chan struct{}, 4), reconcileSlots: make(chan struct{}, 2)}
	s.execute = s.execSSH
	if len(enabled) > 0 {
		s.supervisedEnabled = enabled[0]
	}
	return s
}
func (s *Scheduler) Start() {
	go func() {
		s.runDueTasks()
		lastDue := time.Now()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			s.reconcileSupervised()
			if now.Sub(lastDue) >= 30*time.Second {
				s.runDueTasks()
				lastDue = now
			}
		}
	}()
}
func (s *Scheduler) runDueTasks() {
	s.reconcileSupervised()
	// Never silently retry an execution whose outcome is uncertain after a crash.
	if err := s.db.Model(&models.ScheduledTask{}).Where("supervised=0 AND last_status='running' AND (lease_until IS NULL OR julianday(lease_until)<=julianday(?))", time.Now().UTC()).Updates(map[string]any{"last_status": "interrupted", "enabled": false, "run_id": "", "lease_until": nil, "last_output": "Execution lease expired; review remote state before enabling again."}).Error; err != nil {
		return
	}
	var tasks []models.ScheduledTask
	if s.db.Where("enabled=? AND julianday(next_run_at)<=julianday(?) AND last_status!=?", true, time.Now().UTC(), "running").Order("julianday(next_run_at)").Limit(128).Find(&tasks).Error != nil {
		return
	}
	for _, task := range tasks {
		select {
		case s.slots <- struct{}{}:
			go func(task models.ScheduledTask) { defer func() { <-s.slots }(); s.runTask(task) }(task)
		default:
			return
		}
	}
}
func permitted(db *gorm.DB, task models.ScheduledTask) bool {
	protected, err := authorization.New(db).Protected(task.ServerID)
	if err != nil || protected {
		return false
	}
	return authorization.New(db).All(task.ActorID, task.ServerID, "jobs.execute", "servers.execute", "secrets.use")
}
func (s *Scheduler) runTask(candidate models.ScheduledTask) {
	var task models.ScheduledTask
	claimed := false
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&task, "id=? AND enabled=? AND julianday(next_run_at)<=julianday(?) AND last_status!=?", candidate.ID, true, time.Now().UTC(), "running").Error; err != nil {
			return err
		}
		var running int64
		if err := tx.Model(&models.ScheduledTask{}).Where("server_id=? AND last_status='running'", task.ServerID).Count(&running).Error; err != nil {
			return err
		}
		if running > 0 {
			return nil
		}
		var unresolved int64
		if err := tx.Model(&models.SupervisedRun{}).Where("server_id=? AND finished_at IS NULL", task.ServerID).Count(&unresolved).Error; err != nil {
			return err
		}
		if unresolved > 0 {
			return nil
		}
		if err := tx.Model(&models.ExecutionHostLock{}).Where("server_id=?", task.ServerID).Count(&unresolved).Error; err != nil {
			return err
		}
		if unresolved > 0 {
			return nil
		}
		if task.Supervised && !s.supervisedEnabled {
			if err := tx.Model(&task).Updates(map[string]any{"last_status": "denied", "last_output": "Job supervision is disabled.", "enabled": false}).Error; err != nil {
				return err
			}
			return authorization.New(tx).Record(task.ActorID, "tasks.execute", task.ID, "denied", "")
		}
		if !permitted(tx, task) {
			next := time.Now().UTC().Add(time.Duration(max(task.IntervalMinutes, 1)) * time.Minute)
			if err := tx.Model(&task).Updates(map[string]any{"last_status": "denied", "last_output": "Execution denied by current authorization.", "next_run_at": next}).Error; err != nil {
				return err
			}
			return authorization.New(tx).Record(task.ActorID, "tasks.execute", task.ID, "denied", "")
		}
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		task.RunID = hex.EncodeToString(random)
		if err := tx.Model(&task).Updates(map[string]any{"last_status": "running", "run_id": task.RunID, "lease_until": time.Now().UTC().Add(11 * time.Minute)}).Error; err != nil {
			return err
		}
		if task.Supervised {
			if err := s.prepareSupervised(tx, task); err != nil {
				return err
			}
		}
		if err := authorization.New(tx).Record(task.ActorID, "tasks.execute", task.ID, "started", task.RunID); err != nil {
			return err
		}
		claimed = true
		return nil
	}); err != nil || !claimed {
		return
	}
	if task.Supervised {
		s.runSupervised(task, true)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !permitted(s.db, task) {
					cancel()
					return
				}
			}
		}
	}()
	output := ""
	var err error
	// Recheck after claiming and immediately before opening a transport.
	if !permitted(s.db, task) {
		err = authorization.ErrDenied
	} else {
		output, err = s.execute(ctx, task)
	}
	now := time.Now().UTC()
	next := now.Add(time.Duration(max(task.IntervalMinutes, 1)) * time.Minute)
	status := "ok"
	if err != nil {
		status = "failed"
		if output == "" {
			output = "Remote execution failed."
		}
	}
	if ctx.Err() != nil || errors.Is(err, authorization.ErrDenied) {
		status = "cancelled"
		output = "Execution stopped after timeout or authorization revocation; remote side effects may already have occurred."
	}
	if len(output) > 4096 {
		output = output[:4096] + "\n… (truncated)"
	}
	s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ScheduledTask{}).Where("id=? AND run_id=? AND last_status='running'", task.ID, task.RunID).Updates(map[string]any{"last_run_at": now, "next_run_at": next, "last_output": output, "last_status": status, "run_id": "", "lease_until": nil}).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(task.ActorID, "tasks.execute", task.ID, status, task.RunID)
	})
}

type boundedOutput struct {
	mu     sync.Mutex
	data   []byte
	cancel context.CancelFunc
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := (64 << 10) - len(w.data)
	if len(p) > remaining {
		w.data = append(w.data, p[:remaining]...)
		w.cancel()
		return remaining, fmt.Errorf("output limit reached")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
func (s *Scheduler) execSSH(ctx context.Context, task models.ScheduledTask) (string, error) {
	if !permitted(s.db, task) {
		return "", authorization.ErrDenied
	}
	var server models.Server
	if err := s.db.First(&server, "id=?", task.ServerID).Error; err != nil {
		return "", err
	}
	key, err := nexuscrypto.Decrypt(s.encKey, server.PrivateKeyEnc)
	if err != nil {
		return "", err
	}
	client, err := s.pool.GetContext(ctx, nexusssh.ServerConfig{ID: server.ID, Host: server.Host, Port: server.Port, User: server.Username, PrivKey: key})
	if err != nil {
		return "", err
	}
	if !permitted(s.db, task) {
		return "", authorization.ErrDenied
	}
	type sessionResult struct {
		session *ssh.Session
		err     error
	}
	opened := make(chan sessionResult, 1)
	go func() { session, err := client.NewSession(); opened <- sessionResult{session, err} }()
	var session *ssh.Session
	select {
	case result := <-opened:
		session, err = result.session, result.err
	case <-ctx.Done():
		client.Close()
		s.pool.Remove(server.ID)
		result := <-opened
		if result.session != nil {
			result.session.Close()
		}
		return "", ctx.Err()
	}
	if err != nil {
		return "", err
	}
	if ctx.Err() != nil || !permitted(s.db, task) {
		session.Close()
		return "", authorization.ErrDenied
	}
	defer session.Close()
	execution, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &boundedOutput{cancel: cancel}
	session.Stdout = output
	session.Stderr = output
	done := make(chan error, 1)
	go func() { done <- session.Run(task.Command) }()
	select {
	case err = <-done:
	case <-execution.Done():
		session.Close()
		err = execution.Err()
		<-done
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	return string(output.data), err
}
