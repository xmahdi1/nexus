package scheduler

import (
	"fmt"
	"strings"
	"sync"
	"time"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type Scheduler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
	mu     sync.Mutex
}

func New(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *Scheduler {
	return &Scheduler{db: db, encKey: encKey, pool: pool}
}

func (s *Scheduler) Start() {
	go func() {
		s.runDueTasks()
		for range time.NewTicker(30 * time.Second).C {
			s.runDueTasks()
		}
	}()
}

func (s *Scheduler) runDueTasks() {
	var tasks []models.ScheduledTask
	now := time.Now()
	s.db.Where("enabled = ? AND next_run_at <= ? AND last_status != ?", true, now, "running").Find(&tasks)
	for _, task := range tasks {
		go s.runTask(task)
	}
}

func (s *Scheduler) runTask(task models.ScheduledTask) {
	s.mu.Lock()
	s.db.Model(&task).Updates(map[string]any{"last_status": "running"})
	s.mu.Unlock()

	output, err := s.execSSH(task.ServerID, task.Command)

	now := time.Now()
	next := now.Add(time.Duration(task.IntervalMinutes) * time.Minute)
	status := "ok"
	if err != nil {
		status = "failed"
		if output == "" {
			output = err.Error()
		}
	}
	if len(output) > 4096 {
		output = output[:4096] + "\n… (truncated)"
	}
	s.db.Model(&task).Updates(map[string]any{
		"last_run_at": &now,
		"next_run_at": &next,
		"last_output": output,
		"last_status": status,
	})
}

func (s *Scheduler) execSSH(serverID, command string) (string, error) {
	var server models.Server
	if err := s.db.First(&server, "id = ?", serverID).Error; err != nil {
		return "", fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(s.encKey, server.PrivateKeyEnc)
	if err != nil {
		return "", fmt.Errorf("key decrypt failed")
	}
	client, err := s.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return "", fmt.Errorf("ssh: %w", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		s.pool.Remove(serverID)
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(command)
	return strings.TrimSpace(string(out)), err
}
