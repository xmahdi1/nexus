package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type Process struct {
	PID    int     `json:"pid"`
	Name   string  `json:"name"`
	CPU    float64 `json:"cpu"`
	Memory float64 `json:"memory"`
}

type Metrics struct {
	CPU       float64   `json:"cpu"`
	MemTotal  int64     `json:"memTotal"`
	MemUsed   int64     `json:"memUsed"`
	SwapTotal int64     `json:"swapTotal"`
	SwapUsed  int64     `json:"swapUsed"`
	DiskTotal int64     `json:"diskTotal"`
	DiskUsed  int64     `json:"diskUsed"`
	Load1     float64   `json:"load1"`
	Load5     float64   `json:"load5"`
	Load15    float64   `json:"load15"`
	NetRxRate float64   `json:"netRxRate"`
	NetTxRate float64   `json:"netTxRate"`
	Uptime    string    `json:"uptime"`
	OS        string    `json:"os"`
	Kernel    string    `json:"kernel"`
	Processes []Process `json:"processes"`
}

type cpuSnapshot struct {
	total, idle float64
	at          time.Time
}

type netSnapshot struct {
	rx, tx int64
	at     time.Time
}

var (
	prevCPU sync.Map
	prevNet sync.Map
)

const metricsScript = `
PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
echo "=STAT="
cat /proc/stat 2>/dev/null | head -1
echo "=MEM="
cat /proc/meminfo 2>/dev/null
echo "=DISK="
df -B1 / 2>/dev/null | tail -1
echo "=UPTIME="
cat /proc/uptime 2>/dev/null
echo "=LOAD="
cat /proc/loadavg 2>/dev/null
echo "=NET="
cat /proc/net/dev 2>/dev/null
echo "=PROC="
ps -e -o pid=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | head -8 || \
  ps aux --no-headers 2>/dev/null | awk '{print $2,$3,$4,$11}' | sort -k2 -rn | head -8
echo "=KERNEL="
uname -r 2>/dev/null
echo "=OS="
grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Linux"
`

type Handler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

func NewHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *Handler {
	return &Handler{db: db, encKey: encKey, pool: pool}
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		writeErr(w, "server not found", http.StatusNotFound)
		return
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		writeErr(w, "key decrypt failed", http.StatusInternalServerError)
		return
	}
	sshClient, err := h.pool.GetContext(r.Context(), nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		writeErr(w, "ssh: "+err.Error(), http.StatusBadGateway)
		return
	}
	out, err := nexusssh.Run(r.Context(), sshClient, strings.TrimSpace(metricsScript), nil, 15*time.Second)
	if err != nil {
		writeErr(w, "metrics collection failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parse(string(out), server.ID))
}

func parse(raw, serverID string) Metrics {
	sections := splitSections(raw)
	m := Metrics{Processes: []Process{}}

	if s, ok := sections["STAT"]; ok {
		m.CPU = parseCPU(s, serverID)
	}
	if s, ok := sections["MEM"]; ok {
		m.MemTotal, m.MemUsed, m.SwapTotal, m.SwapUsed = parseMem(s)
	}
	if s, ok := sections["DISK"]; ok {
		m.DiskTotal, m.DiskUsed = parseDisk(s)
	}
	if s, ok := sections["UPTIME"]; ok {
		m.Uptime = parseUptime(s)
	}
	if s, ok := sections["LOAD"]; ok {
		m.Load1, m.Load5, m.Load15 = parseLoad(s)
	}
	if s, ok := sections["NET"]; ok {
		m.NetRxRate, m.NetTxRate = parseNet(s, serverID)
	}
	if s, ok := sections["PROC"]; ok {
		m.Processes = parseProcs(s)
	}
	if s, ok := sections["KERNEL"]; ok {
		m.Kernel = strings.TrimSpace(s)
	}
	if s, ok := sections["OS"]; ok {
		m.OS = strings.TrimSpace(s)
	}

	return m
}

func splitSections(raw string) map[string]string {
	result := map[string]string{}
	var current string
	var buf strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "=") && strings.HasSuffix(strings.TrimSpace(line), "=") {
			if current != "" {
				result[current] = buf.String()
				buf.Reset()
			}
			current = strings.Trim(strings.TrimSpace(line), "=")
		} else if current != "" {
			buf.WriteString(line + "\n")
		}
	}
	if current != "" {
		result[current] = buf.String()
	}
	return result
}

func parseCPU(s, serverID string) float64 {
	fields := strings.Fields(strings.TrimSpace(strings.Split(s, "\n")[0]))
	if len(fields) < 5 {
		return 0
	}
	var vals []float64
	for _, f := range fields[1:] {
		v, _ := strconv.ParseFloat(f, 64)
		vals = append(vals, v)
	}
	if len(vals) < 4 {
		return 0
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	total := 0.0
	for _, v := range vals {
		total += v
	}
	now := cpuSnapshot{total: total, idle: idle, at: time.Now()}
	if prev, ok := prevCPU.Load(serverID); ok {
		p := prev.(cpuSnapshot)
		dt := now.total - p.total
		di := now.idle - p.idle
		if dt > 0 {
			prevCPU.Store(serverID, now)
			return math.Round((1-di/dt)*100*10) / 10
		}
	}
	prevCPU.Store(serverID, now)
	return 0
}

func parseMem(s string) (total, used, swapTotal, swapUsed int64) {
	kv := map[string]int64{}
	for _, line := range strings.Split(s, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			v, _ := strconv.ParseInt(parts[1], 10, 64)
			kv[strings.TrimSuffix(parts[0], ":")] = v * 1024
		}
	}
	total = kv["MemTotal"]
	avail := kv["MemAvailable"]
	if avail == 0 {
		avail = kv["MemFree"] + kv["Buffers"] + kv["Cached"]
	}
	return total, total - avail, kv["SwapTotal"], kv["SwapTotal"] - kv["SwapFree"]
}

func parseDisk(s string) (total, used int64) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) >= 3 {
		total, _ = strconv.ParseInt(fields[1], 10, 64)
		used, _ = strconv.ParseInt(fields[2], 10, 64)
	}
	return
}

func parseUptime(s string) string {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) < 1 {
		return "unknown"
	}
	secs, _ := strconv.ParseFloat(fields[0], 64)
	d := int(secs) / 86400
	h := (int(secs) % 86400) / 3600
	min := (int(secs) % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, min)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, min)
	}
	return fmt.Sprintf("%dm", min)
}

func parseLoad(s string) (l1, l5, l15 float64) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) >= 3 {
		l1, _ = strconv.ParseFloat(fields[0], 64)
		l5, _ = strconv.ParseFloat(fields[1], 64)
		l15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

func parseNet(s, serverID string) (rxRate, txRate float64) {
	var rx, tx int64
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Inter") || strings.HasPrefix(line, "face") ||
			strings.HasPrefix(line, "lo:") || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseInt(fields[0], 10, 64)
		t, _ := strconv.ParseInt(fields[8], 10, 64)
		rx += r
		tx += t
	}
	now := netSnapshot{rx: rx, tx: tx, at: time.Now()}
	if prev, ok := prevNet.Load(serverID); ok {
		p := prev.(netSnapshot)
		if elapsed := now.at.Sub(p.at).Seconds(); elapsed > 0 {
			rxRate = float64(now.rx-p.rx) / elapsed
			txRate = float64(now.tx-p.tx) / elapsed
			if rxRate < 0 {
				rxRate = 0
			}
			if txRate < 0 {
				txRate = 0
			}
		}
	}
	prevNet.Store(serverID, now)
	return
}

func parseProcs(s string) []Process {
	skip := map[string]bool{"ps": true, "sh": true, "bash": true, "grep": true}
	var procs []Process
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		name := fields[3]
		if name == "" || skip[name] {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		cpu, _ := strconv.ParseFloat(fields[1], 64)
		mem, _ := strconv.ParseFloat(fields[2], 64)
		procs = append(procs, Process{PID: pid, Name: name, CPU: cpu, Memory: mem})
		if len(procs) >= 7 {
			break
		}
	}
	return procs
}

func writeErr(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
