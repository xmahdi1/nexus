package monitor

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type ServerStatus struct {
	ServerID   string    `json:"serverId"`
	Name       string    `json:"name"`
	Host       string    `json:"host"`
	Tags       string    `json:"tags"`
	Online     bool      `json:"online"`
	LatencyMs  int64     `json:"latencyMs"`
	CheckedAt  time.Time `json:"checkedAt"`
	LastOnline time.Time `json:"lastOnline"`
}

type Monitor struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool

	statuses       sync.Map
	prevOnline     sync.Map
	prevContStates sync.Map
	lastAlerted    sync.Map

	bot   *Bot
	botMu sync.RWMutex
}

func New(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *Monitor {
	m := &Monitor{db: db, encKey: encKey, pool: pool}
	m.reloadBot()
	return m
}

func (m *Monitor) Start() {
	go func() {
		m.checkAllServers()
		for range time.NewTicker(30 * time.Second).C {
			m.checkAllServers()
		}
	}()
	go func() {
		time.Sleep(15 * time.Second)
		m.checkAllContainers()
		for range time.NewTicker(60 * time.Second).C {
			m.checkAllContainers()
		}
	}()
	go func() {
		time.Sleep(45 * time.Second)
		m.checkAllResources()
		for range time.NewTicker(1 * time.Minute).C {
			m.checkAllResources()
		}
	}()
}

func (m *Monitor) GetStatuses() []ServerStatus {
	var out []ServerStatus
	m.statuses.Range(func(_, v any) bool {
		s := *v.(*ServerStatus)
		out = append(out, s)
		return true
	})
	return out
}

func (m *Monitor) ReloadBot() { m.reloadBot() }

func (m *Monitor) reloadBot() {
	var cfg models.AlertConfig
	if err := m.db.First(&cfg, "id = ?", "default").Error; err != nil {
		return
	}
	m.botMu.Lock()
	defer m.botMu.Unlock()
	if cfg.TelegramEnabled && cfg.TelegramToken != "" && cfg.TelegramChatID != "" {
		m.bot = NewBot(cfg.TelegramToken, cfg.TelegramChatID)
	} else {
		m.bot = nil
	}
}

func (m *Monitor) shouldNotify(t AlertType) bool {
	var cfg models.AlertConfig
	if err := m.db.First(&cfg, "id = ?", "default").Error; err != nil {
		return false
	}
	switch t {
	case AlertServerDown:
		return cfg.NotifyServerDown
	case AlertServerUp:
		return cfg.NotifyServerUp
	case AlertContainerDown, AlertContainerUp:
		return cfg.NotifyContainer
	}
	return true
}

func (m *Monitor) notify(a Alert) {
	permission := "metrics.read"
	switch a.Type {
	case AlertServerDown, AlertServerUp:
		permission = "servers.connect"
	case AlertContainerDown, AlertContainerUp:
		permission = "docker.read"
	}
	if !authorization.New(m.db).All(authorization.MonitorPrincipal, a.ServerID, permission, "notifications.send") {
		return
	}
	if !m.shouldNotify(a.Type) {
		return
	}
	m.botMu.RLock()
	bot := m.bot
	m.botMu.RUnlock()
	if bot == nil {
		return
	}
	go func() { _ = bot.Notify(a) }()
}

func (m *Monitor) checkAllServers() {
	var servers []models.Server
	m.db.Find(&servers)
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(sv models.Server) { defer wg.Done(); m.checkServer(sv) }(s)
	}
	wg.Wait()
}

func (m *Monitor) checkServer(server models.Server) {
	if !authorization.New(m.db).All(authorization.MonitorPrincipal, server.ID, "servers.connect") {
		return
	}
	latency, online := tcpPing(server.Host, server.Port, 5*time.Second)
	now := time.Now()
	status := &ServerStatus{
		ServerID: server.ID, Name: server.Name, Host: server.Host, Tags: server.Tags,
		Online: online, LatencyMs: latency.Milliseconds(), CheckedAt: now,
	}
	var prevLastOnline time.Time
	if existing, ok := m.statuses.Load(server.ID); ok {
		prevLastOnline = existing.(*ServerStatus).LastOnline
		status.LastOnline = prevLastOnline
	}
	if online {
		status.LastOnline = now
	}
	m.statuses.Store(server.ID, status)

	if prev, hadPrev := m.prevOnline.Load(server.ID); hadPrev {
		wasOnline := prev.(bool)
		if wasOnline && !online {
			m.notify(Alert{ServerID: server.ID, Type: AlertServerDown, ServerName: server.Name, ServerHost: server.Host, OccurredAt: now})
		} else if !wasOnline && online {
			downtime := ""
			if !prevLastOnline.IsZero() {
				if d := now.Sub(prevLastOnline); d > time.Minute {
					downtime = fmtDuration(d)
				}
			}
			m.notify(Alert{ServerID: server.ID, Type: AlertServerUp, ServerName: server.Name, ServerHost: server.Host, Detail: downtime, OccurredAt: now})
		}
	}
	m.prevOnline.Store(server.ID, online)
}
func (m *Monitor) RemoveServer(serverID string) {
	m.statuses.Delete(serverID)
	m.prevOnline.Delete(serverID)
	m.prevContStates.Delete(serverID)
	m.lastAlerted.Delete(serverID + ":cpu")
	m.lastAlerted.Delete(serverID + ":ram")
	m.lastAlerted.Delete(serverID + ":disk")
}
func tcpPing(host string, port int, timeout time.Duration) (time.Duration, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return 0, false
	}
	conn.Close()
	return time.Since(start), true
}

func (m *Monitor) checkAllResources() {
	var servers []models.Server
	m.db.Find(&servers)
	for _, s := range servers {
		if st, ok := m.statuses.Load(s.ID); ok && !st.(*ServerStatus).Online {
			continue
		}
		go m.checkResources(s)
	}
}

func (m *Monitor) checkResources(server models.Server) {
	if !authorization.New(m.db).All(authorization.MonitorPrincipal, server.ID, "metrics.read", "secrets.use") {
		return
	}
	var cfg models.ServerAlertConfig
	if err := m.db.First(&cfg, "id = ?", server.ID).Error; err != nil {
		return
	}
	if !cfg.CPUEnabled && !cfg.RAMEnabled && !cfg.DiskEnabled {
		return
	}

	privKey, err := nexuscrypto.Decrypt(m.encKey, server.PrivateKeyEnc)
	if err != nil {
		return
	}
	client, err := m.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return
	}

	out, err := m.command(client, server.ID, "metrics.read", `
read -r _ u1 n1 s1 i1 io1 irq1 sirq1 _ < /proc/stat
sleep 1
read -r _ u2 n2 s2 i2 io2 irq2 sirq2 _ < /proc/stat
ud=$((u2-u1)); nd=$((n2-n1)); sd=$((s2-s1)); id=$((i2-i1)); iod=$((io2-io1)); irqd=$((irq2-irq1)); sirqd=$((sirq2-sirq1))
total=$((ud+nd+sd+id+iod+irqd+sirqd))
idle=$((id+iod))
if [ "$total" -gt 0 ]; then
  CPU=$(awk -v t="$total" -v idle="$idle" 'BEGIN{printf "%.1f", (1-idle/t)*100}')
else
  CPU=0
fi
RAM=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t>0)printf "%.0f",(1-a/t)*100;else print 0}' /proc/meminfo 2>/dev/null || echo 0)
DISK=$(df / 2>/dev/null | awk 'NR==2{sub(/%/,"",$5);print $5}' || echo 0)
printf "%s %s %s\n" "${CPU:-0}" "${RAM:-0}" "${DISK:-0}"
`)
	if err != nil {
		return
	}

	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 3 {
		return
	}

	cpu, _ := strconv.ParseFloat(parts[0], 64)
	ram, _ := strconv.ParseFloat(parts[1], 64)
	disk, _ := strconv.ParseFloat(parts[2], 64)

	now := time.Now()
	cooldown := time.Hour

	if cfg.CPUEnabled && cpu >= cfg.CPUThreshold {
		key := server.ID + ":cpu"
		if last, ok := m.lastAlerted.Load(key); !ok || now.Sub(last.(time.Time)) > cooldown {
			m.notify(Alert{ServerID: server.ID, Type: AlertHighResource, ServerName: server.Name, ServerHost: server.Host,
				Detail: fmt.Sprintf("CPU %.1f%% (threshold %.0f%%)", cpu, cfg.CPUThreshold), OccurredAt: now})
			m.lastAlerted.Store(key, now)
		}
	}
	if cfg.RAMEnabled && ram >= cfg.RAMThreshold {
		key := server.ID + ":ram"
		if last, ok := m.lastAlerted.Load(key); !ok || now.Sub(last.(time.Time)) > cooldown {
			m.notify(Alert{ServerID: server.ID, Type: AlertHighResource, ServerName: server.Name, ServerHost: server.Host,
				Detail: fmt.Sprintf("RAM %.0f%% (threshold %.0f%%)", ram, cfg.RAMThreshold), OccurredAt: now})
			m.lastAlerted.Store(key, now)
		}
	}
	if cfg.DiskEnabled && disk >= cfg.DiskThreshold {
		key := server.ID + ":disk"
		if last, ok := m.lastAlerted.Load(key); !ok || now.Sub(last.(time.Time)) > cooldown {
			m.notify(Alert{ServerID: server.ID, Type: AlertHighResource, ServerName: server.Name, ServerHost: server.Host,
				Detail: fmt.Sprintf("Disk %.0f%% (threshold %.0f%%)", disk, cfg.DiskThreshold), OccurredAt: now})
			m.lastAlerted.Store(key, now)
		}
	}
}

func (m *Monitor) checkAllContainers() {
	var monitored []models.MonitoredContainer
	m.db.Find(&monitored)
	if len(monitored) == 0 {
		return
	}
	byServer := map[string][]models.MonitoredContainer{}
	for _, mc := range monitored {
		byServer[mc.ServerID] = append(byServer[mc.ServerID], mc)
	}
	for serverID, containers := range byServer {
		if st, ok := m.statuses.Load(serverID); ok && !st.(*ServerStatus).Online {
			continue
		}
		go m.checkContainers(serverID, containers)
	}
}

func (m *Monitor) SeedContainer(serverID, containerID, name string) {
	if !authorization.New(m.db).All(authorization.MonitorPrincipal, serverID, "docker.read", "secrets.use") {
		return
	}
	var server models.Server
	if err := m.db.First(&server, "id = ?", serverID).Error; err != nil {
		return
	}
	privKey, err := nexuscrypto.Decrypt(m.encKey, server.PrivateKeyEnc)
	if err != nil {
		return
	}
	client, err := m.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return
	}

	out, err := m.command(client, server.ID, "docker.read", fmt.Sprintf(
		"docker inspect --format='{{.State.Status}}' -- %s 2>/dev/null", "'"+strings.ReplaceAll(containerID, "'", "'\"'\"'")+"'",
	))
	if err != nil {
		return
	}

	state := strings.TrimSpace(string(out))
	if state == "" || name == "" {
		return
	}

	prevRaw, _ := m.prevContStates.Load(serverID)
	prevStates, _ := prevRaw.(map[string]string)
	merged := map[string]string{}
	for k, v := range prevStates {
		merged[k] = v
	}
	merged[name] = state
	m.prevContStates.Store(serverID, merged)
}

func (m *Monitor) checkContainers(serverID string, monitored []models.MonitoredContainer) {
	if !authorization.New(m.db).All(authorization.MonitorPrincipal, serverID, "docker.read", "secrets.use") {
		return
	}
	var server models.Server
	if err := m.db.First(&server, "id = ?", serverID).Error; err != nil {
		return
	}
	privKey, err := nexuscrypto.Decrypt(m.encKey, server.PrivateKeyEnc)
	if err != nil {
		return
	}
	client, err := m.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return
	}

	out, err := m.command(client, server.ID, "docker.read", `docker ps -a --format '{{.Names}}|{{.State}}' 2>/dev/null`)

	if err != nil {
		return
	}

	currentStates := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) == 2 {
			name := strings.TrimPrefix(strings.TrimSpace(parts[0]), "/")
			currentStates[name] = strings.TrimSpace(parts[1])
		}
	}

	prevRaw, _ := m.prevContStates.Load(serverID)
	prevStates, _ := prevRaw.(map[string]string)
	now := time.Now()

	for _, mc := range monitored {
		if mc.Name == "" {
			continue
		}
		cur := currentStates[mc.Name]
		prev := ""
		if prevStates != nil {
			prev = prevStates[mc.Name]
		}
		if prev != "" {
			if prev == "running" && cur != "running" && cur != "" {
				m.notify(Alert{ServerID: server.ID, Type: AlertContainerDown, ServerName: server.Name, ServerHost: server.Host, Detail: mc.Name, OccurredAt: now})
			} else if prev != "running" && cur == "running" {
				m.notify(Alert{ServerID: server.ID, Type: AlertContainerUp, ServerName: server.Name, ServerHost: server.Host, Detail: mc.Name, OccurredAt: now})
			}
		}
	}

	normalized := map[string]string{}
	for _, mc := range monitored {
		if mc.Name == "" {
			continue
		}
		normalized[mc.Name] = currentStates[mc.Name]
	}
	m.prevContStates.Store(serverID, normalized)
}

func fmtDuration(d time.Duration) string {
	h := int(d.Hours())
	min := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, min)
	}
	return fmt.Sprintf("%dm", min)
}

func (m *Monitor) command(client *ssh.Client, serverID, permission, command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	policy := authorization.New(m.db)
	defer policy.Watch(authorization.MonitorPrincipal, serverID, cancel, permission, "secrets.use")()
	if !policy.All(authorization.MonitorPrincipal, serverID, permission, "secrets.use") {
		return "", errors.New("monitor access revoked")
	}
	out, err := nexusssh.Run(ctx, client, command, nil, 30*time.Second)
	if err != nil {
		return "", err
	}
	if !policy.All(authorization.MonitorPrincipal, serverID, permission, "secrets.use") {
		return "", errors.New("monitor access revoked")
	}
	return out, nil
}
