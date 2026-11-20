package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

type FirewallHandler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

func NewFirewallHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *FirewallHandler {
	return &FirewallHandler{db: db, encKey: encKey, pool: pool}
}

type FirewallRule struct {
	Number int    `json:"number"`
	To     string `json:"to"`
	Action string `json:"action"`
	From   string `json:"from"`
}

type OpenPort struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Address  string `json:"address"`
	Process  string `json:"process"`
	Cmdline  string `json:"cmdline"`
}

type FirewallStatus struct {
	Status    string         `json:"status"`
	Available bool           `json:"available"`
	Rules     []FirewallRule `json:"rules"`
	Ports     []OpenPort     `json:"ports"`
}

var ufwRuleRe = regexp.MustCompile(`^\[ *(\d+)\]\s+(\S+.*?)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+)$`)

var portRe = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?(/(tcp|udp))?$`)

func validPort(p string) bool {
	if !portRe.MatchString(p) {
		return false
	}
	value, protocol, _ := strings.Cut(p, "/")
	low, high, ranged := strings.Cut(value, ":")
	first, _ := strconv.Atoi(low)
	if first < 1 || first > 65535 {
		return false
	}
	if ranged {
		last, _ := strconv.Atoi(high)
		return protocol != "" && last >= first && last <= 65535
	}
	return true
}
func validFrom(f string) bool {
	if f == "" || f == "Anywhere" {
		return true
	}
	if strings.Contains(f, "/") {
		_, _, err := net.ParseCIDR(f)
		return err == nil
	}
	return net.ParseIP(f) != nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func parseUFWOutput(output string) (string, []FirewallRule) {
	status := "inactive"
	rules := make([]FirewallRule, 0)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status:") {
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			continue
		}
		m := ufwRuleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		action := m[3]
		if m[4] != "" {
			action += " " + m[4]
		}
		rules = append(rules, FirewallRule{
			Number: n,
			To:     strings.TrimSpace(m[2]),
			Action: action,
			From:   strings.TrimSpace(m[5]),
		})
	}
	return status, rules
}

func parsePorts(output string) []OpenPort {
	ports := make([]OpenPort, 0)
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 2 {
			continue
		}
		proto := strings.TrimSpace(parts[0])
		port := strings.TrimSpace(parts[1])
		if proto == "" || port == "" {
			continue
		}
		addr, process, cmdline := "", "", ""
		if len(parts) > 2 {
			addr = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			process = strings.TrimSpace(parts[3])
		}
		if len(parts) > 4 {
			cmdline = strings.TrimSpace(parts[4])
		}
		key := proto + "|" + port + "|" + addr
		if seen[key] {
			continue
		}
		seen[key] = true
		ports = append(ports, OpenPort{
			Protocol: proto,
			Port:     port,
			Address:  addr,
			Process:  process,
			Cmdline:  cmdline,
		})
	}
	return ports
}

func (h *FirewallHandler) connect(ctx context.Context, serverID string) (*gossh.Client, error) {
	var srv models.Server
	if err := h.db.First(&srv, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, srv.PrivateKeyEnc)
	if err != nil {
		return nil, err
	}
	return h.pool.GetContext(ctx, nexusssh.ServerConfig{
		ID:      srv.ID,
		Host:    srv.Host,
		Port:    srv.Port,
		User:    srv.Username,
		PrivKey: privKey,
	})
}

func fwRun(ctx context.Context, client *gossh.Client, cmd string) (string, error) {
	out, err := nexusssh.Run(ctx, client, cmd, nil, nexusssh.CommandTimeout)
	return strings.TrimSpace(out), err
}

func (h *FirewallHandler) Status(w http.ResponseWriter, r *http.Request) {
	client, err := h.connect(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}

	ufwOut, err := fwRun(r.Context(), client, `if command -v ufw >/dev/null 2>&1; then ufw status numbered 2>&1; else echo '__UFW_MISSING__'; fi`)
	if err != nil {
		writeErr(w, "Firewall status unavailable.", "remote_error", 502)
		return
	}
	available := !strings.Contains(ufwOut, "__UFW_MISSING__") && !strings.Contains(ufwOut, "command not found")

	result := FirewallStatus{
		Status:    "inactive",
		Available: available,
		Rules:     make([]FirewallRule, 0),
		Ports:     make([]OpenPort, 0),
	}
	if available {
		result.Status, result.Rules = parseUFWOutput(ufwOut)
	}

	portScript := `ss -tlnp 2>/dev/null | grep 'LISTEN' | while IFS= read -r line; do port=$(printf '%s' "$line" | grep -oP ':\K\d+(?=\s)' | head -1); [ -z "$port" ] && continue; addr=$(printf '%s' "$line" | grep -oP '\S*:\d+(?=\s)' | head -1); proc=$(printf '%s' "$line" | grep -oP '"\K[^"]+(?=")' | head -1); pid=$(printf '%s' "$line" | grep -oP 'pid=\K\d+' | head -1); cmd=""; [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] && cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 80 | tr -d '\n'); printf 'tcp|%s|%s|%s|%s\n' "$port" "$addr" "$proc" "$cmd"; done`

	portData, portErr := fwRun(r.Context(), client, portScript)
	if portErr != nil {
		writeErr(w, "Listener status unavailable.", "remote_error", 502)
		return
	} else if portData != "" {
		result.Ports = parsePorts(portData)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *FirewallHandler) Enable(w http.ResponseWriter, r *http.Request) {
	client, err := h.connect(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	if _, err = fwRun(r.Context(), client, `ufw --force enable 2>&1`); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (h *FirewallHandler) Disable(w http.ResponseWriter, r *http.Request) {
	client, err := h.connect(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	if _, err = fwRun(r.Context(), client, `ufw --force disable 2>&1`); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

type addRuleInput struct {
	Port   string `json:"port"`
	Action string `json:"action"`
	From   string `json:"from"`
}

func (h *FirewallHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	var input addRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Port == "" {
		http.Error(w, `{"error":"invalid input"}`, http.StatusBadRequest)
		return
	}
	if input.Action != "allow" && input.Action != "deny" {
		http.Error(w, `{"error":"action must be allow or deny"}`, http.StatusBadRequest)
		return
	}
	if !validPort(input.Port) {
		http.Error(w, `{"error":"invalid port format"}`, http.StatusBadRequest)
		return
	}
	if !validFrom(input.From) {
		http.Error(w, `{"error":"invalid from address"}`, http.StatusBadRequest)
		return
	}
	client, err := h.connect(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	var cmd string
	if input.From != "" && input.From != "Anywhere" {
		port, protocol, _ := strings.Cut(input.Port, "/")
		cmd = fmt.Sprintf("ufw %s from %s to any port %s", input.Action, shellQuote(input.From), shellQuote(port))
		if protocol != "" {
			cmd += " proto " + protocol
		}
		cmd += " 2>&1"
	} else {
		cmd = fmt.Sprintf("ufw %s %s 2>&1", input.Action, shellQuote(input.Port))
	}
	if _, err = fwRun(r.Context(), client, cmd); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (h *FirewallHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	client, err := h.connect(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	n := chi.URLParam(r, "n")
	if number, err := strconv.Atoi(n); err != nil || number < 1 {
		http.Error(w, `{"error":"rule number must be numeric"}`, http.StatusBadRequest)
		return
	}
	if _, err = fwRun(r.Context(), client, fmt.Sprintf("ufw --force delete %s 2>&1", n)); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
