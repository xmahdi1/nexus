package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type Handler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

type DetectResult struct {
	ProxyType string `json:"proxyType"`
	Version   string `json:"version"`
}

func NewHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *Handler {
	db.AutoMigrate(&models.ProxyRule{})
	return &Handler{db: db, encKey: encKey, pool: pool}
}

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
var domainWildcardRe = regexp.MustCompile(`^\*\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
var targetRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+:[0-9]{1,5}$`)
var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validDomain(d string) bool {
	return domainRe.MatchString(d) || domainWildcardRe.MatchString(d)
}

func validTarget(t string) bool {
	return targetRe.MatchString(t)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (h *Handler) ssh(serverID string) (func(string) (string, error), error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	client, err := h.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return func(cmd string) (string, error) {
		sess, err := client.NewSession()
		if err != nil {
			h.pool.Remove(serverID)
			return "", err
		}
		defer sess.Close()
		out, err := sess.CombinedOutput(cmd)
		return strings.TrimSpace(string(out)), err
	}, nil
}

func (h *Handler) Detect(w http.ResponseWriter, r *http.Request) {
	run, err := h.ssh(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	if out, err := run(`PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin" nginx -v 2>&1`); err == nil {
		writeJSON(w, DetectResult{ProxyType: "nginx", Version: strings.TrimPrefix(out, "nginx version: nginx/")}, http.StatusOK)
		return
	}
	if out, err := run(`PATH="$PATH:/usr/local/bin:/usr/bin:/bin" caddy version 2>/dev/null`); err == nil {
		writeJSON(w, DetectResult{ProxyType: "caddy", Version: strings.Split(out, " ")[0]}, http.StatusOK)
		return
	}
	writeJSON(w, DetectResult{ProxyType: "none"}, http.StatusOK)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var rules []models.ProxyRule
	h.db.Where("server_id = ?", chi.URLParam(r, "id")).Order("created_at desc").Find(&rules)
	if rules == nil {
		rules = []models.ProxyRule{}
	}
	writeJSON(w, rules, http.StatusOK)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	var body struct {
		Domain    string `json:"domain"`
		Target    string `json:"target"`
		ProxyType string `json:"proxyType"`
		SSL       bool   `json:"ssl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Domain == "" || body.Target == "" || body.ProxyType == "" {
		writeErr(w, "domain, target and proxyType are required", http.StatusBadRequest)
		return
	}
	if !validDomain(body.Domain) {
		writeErr(w, "invalid domain format", http.StatusBadRequest)
		return
	}
	if !validTarget(body.Target) {
		writeErr(w, "target must be host:port", http.StatusBadRequest)
		return
	}
	run, err := h.ssh(serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	ruleID := newID()
	switch body.ProxyType {
	case "nginx":
		if err := createNginxRule(run, ruleID, body.Domain, body.Target, body.SSL); err != nil {
			writeErr(w, "nginx: "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "caddy":
		if err := createCaddyRule(run, body.Domain, body.Target); err != nil {
			writeErr(w, "caddy: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		writeErr(w, "unsupported proxy type: "+body.ProxyType, http.StatusBadRequest)
		return
	}

	sslOK := false
	var sslOutput string
	if body.SSL {
		switch body.ProxyType {
		case "nginx":
			out, certErr := run(fmt.Sprintf(
				`PATH="$PATH:/usr/bin:/usr/local/bin" certbot --nginx -d %s --non-interactive --agree-tos --redirect -m %s 2>&1`,
				shellQuote(body.Domain), shellQuote("admin@"+body.Domain),
			))
			sslOutput = out
			sslOK = certErr == nil
		case "caddy":
			sslOK = true
			sslOutput = "Caddy manages SSL automatically — no action needed."
		}
	}

	rule := models.ProxyRule{
		ID: ruleID, ServerID: serverID,
		Domain: body.Domain, Target: body.Target,
		ProxyType: body.ProxyType, SSLEnabled: sslOK,
		CreatedAt: time.Now(),
	}
	if err := h.db.Create(&rule).Error; err != nil {
		writeErr(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if body.SSL && !sslOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"rule":    rule,
			"sslOK":   false,
			"output":  sslOutput,
			"warning": "proxy rule created, but SSL issuance failed — check DNS and try Enable SSL again",
		})
		return
	}

	writeJSON(w, rule, http.StatusCreated)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	ruleID := chi.URLParam(r, "ruleId")
	var rule models.ProxyRule
	if err := h.db.First(&rule, "id = ? AND server_id = ?", ruleID, serverID).Error; err != nil {
		writeErr(w, "rule not found", http.StatusNotFound)
		return
	}
	var body struct {
		Domain    string `json:"domain"`
		Target    string `json:"target"`
		ProxyType string `json:"proxyType"`
		SSL       bool   `json:"ssl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !validDomain(body.Domain) {
		writeErr(w, "invalid domain format", http.StatusBadRequest)
		return
	}
	if !validTarget(body.Target) {
		writeErr(w, "target must be host:port", http.StatusBadRequest)
		return
	}
	run, err := h.ssh(serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	switch rule.ProxyType {
	case "nginx":
		deleteNginxRule(run, rule.ID, rule.Domain)
	case "caddy":
		deleteCaddyRule(run, rule.Domain)
	}
	switch body.ProxyType {
	case "nginx":
		if err := createNginxRule(run, rule.ID, body.Domain, body.Target, body.SSL); err != nil {
			writeErr(w, "nginx: "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "caddy":
		if err := createCaddyRule(run, body.Domain, body.Target); err != nil {
			writeErr(w, "caddy: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	sslOK := rule.SSLEnabled
	if body.SSL && !rule.SSLEnabled {
		switch body.ProxyType {
		case "nginx":
			_, certErr := run(fmt.Sprintf(
				`PATH="$PATH:/usr/bin:/usr/local/bin" certbot --nginx -d %s --non-interactive --agree-tos --redirect -m %s 2>&1`,
				shellQuote(body.Domain), shellQuote("admin@"+body.Domain),
			))
			sslOK = certErr == nil
		case "caddy":
			sslOK = true
		}
	} else if !body.SSL {
		sslOK = false
	}

	h.db.Model(&rule).Updates(map[string]any{
		"domain": body.Domain, "target": body.Target,
		"proxy_type": body.ProxyType, "ssl_enabled": sslOK,
	})
	rule.Domain = body.Domain
	rule.Target = body.Target
	rule.ProxyType = body.ProxyType
	rule.SSLEnabled = sslOK
	writeJSON(w, rule, http.StatusOK)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	ruleID := chi.URLParam(r, "ruleId")
	var rule models.ProxyRule
	if err := h.db.First(&rule, "id = ? AND server_id = ?", ruleID, serverID).Error; err != nil {
		writeErr(w, "rule not found", http.StatusNotFound)
		return
	}
	run, err := h.ssh(serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	switch rule.ProxyType {
	case "nginx":
		deleteNginxRule(run, rule.ID, rule.Domain)
	case "caddy":
		deleteCaddyRule(run, rule.Domain)
	}
	h.db.Delete(&rule)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) EnableSSL(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	ruleID := chi.URLParam(r, "ruleId")
	var rule models.ProxyRule
	if err := h.db.First(&rule, "id = ? AND server_id = ?", ruleID, serverID).Error; err != nil {
		writeErr(w, "rule not found", http.StatusNotFound)
		return
	}
	var body struct {
		Email    string `json:"email"`
		Wildcard bool   `json:"wildcard"`
		CFToken  string `json:"cfToken"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Email == "" {
		body.Email = "admin@" + rule.Domain
	}
	if !emailRe.MatchString(body.Email) {
		writeErr(w, "invalid email format", http.StatusBadRequest)
		return
	}
	run, err := h.ssh(serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	var output string
	var sslErr error
	if body.Wildcard {
		if body.CFToken == "" {
			writeErr(w, "Cloudflare API token required for wildcard certificates", http.StatusBadRequest)
			return
		}
		output, sslErr = enableWildcardSSL(run, rule, body.Email, body.CFToken)
	} else {
		switch rule.ProxyType {
		case "nginx":
			output, sslErr = run(fmt.Sprintf(
				`PATH="$PATH:/usr/bin:/usr/local/bin" certbot --nginx -d %s --non-interactive --agree-tos --redirect -m %s 2>&1`,
				shellQuote(rule.Domain), shellQuote(body.Email),
			))
		case "caddy":
			output = "Caddy manages SSL automatically — no action needed."
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if sslErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": sslErr.Error(), "output": output})
		return
	}
	h.db.Model(&rule).Update("ssl_enabled", true)
	rule.SSLEnabled = true
	json.NewEncoder(w).Encode(map[string]any{"rule": rule, "output": output})
}

func nginxConfig(domain, target string) string {
	return fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location / {
        proxy_pass http://%s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600;
    }
}
`, domain, target)
}

func createNginxRule(run func(string) (string, error), id, domain, target string, ssl bool) error {
	confPath := fmt.Sprintf("/etc/nginx/sites-available/nexus-%s.conf", id)
	linkPath := fmt.Sprintf("/etc/nginx/sites-enabled/nexus-%s.conf", id)
	if _, err := run(fmt.Sprintf("cat > %s << 'NEXUS_EOF'\n%s\nNEXUS_EOF", confPath, nginxConfig(domain, target))); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if _, err := run(fmt.Sprintf("ln -sf %s %s", confPath, linkPath)); err != nil {
		return fmt.Errorf("enable site: %w", err)
	}
	if out, err := run(`PATH="$PATH:/usr/local/sbin:/usr/sbin" nginx -t 2>&1`); err != nil {
		run(fmt.Sprintf("rm -f %s %s", confPath, linkPath))
		return fmt.Errorf("config test failed: %s", out)
	}
	if _, err := run(`PATH="$PATH:/usr/bin:/bin:/usr/local/bin" systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || true`); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return nil
}

func deleteNginxRule(run func(string) (string, error), id, _ string) {
	confPath := fmt.Sprintf("/etc/nginx/sites-available/nexus-%s.conf", id)
	linkPath := fmt.Sprintf("/etc/nginx/sites-enabled/nexus-%s.conf", id)
	run(fmt.Sprintf("rm -f %s %s", confPath, linkPath))
	run(`PATH="$PATH:/usr/bin:/bin:/usr/local/bin" systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || true`)
}

func createCaddyRule(run func(string) (string, error), domain, target string) error {
	cmd := fmt.Sprintf("cat >> /etc/caddy/Caddyfile << 'NEXUS_EOF'\n%s {\n    reverse_proxy %s\n}\nNEXUS_EOF", domain, target)
	if _, err := run(cmd); err != nil {
		return fmt.Errorf("write caddyfile: %w", err)
	}
	if _, err := run(`PATH="$PATH:/usr/bin:/usr/local/bin" systemctl reload caddy 2>/dev/null || caddy reload --config /etc/caddy/Caddyfile 2>/dev/null || true`); err != nil {
		return fmt.Errorf("reload caddy: %w", err)
	}
	return nil
}

func deleteCaddyRule(run func(string) (string, error), domain string) {
	safe := strings.ReplaceAll(domain, ".", "\\.")
	run(fmt.Sprintf(
		`sed -i '/^%s {/,/^}/d' /etc/caddy/Caddyfile && systemctl reload caddy 2>/dev/null || true`,
		safe,
	))
}

func enableWildcardSSL(run func(string) (string, error), rule models.ProxyRule, email, cfToken string) (string, error) {
	var out strings.Builder
	installOut, _ := run(`PATH="$PATH:/usr/bin:/usr/local/bin" apt-get install -y python3-certbot-dns-cloudflare 2>&1 || pip3 install certbot-dns-cloudflare 2>&1`)
	out.WriteString(installOut + "\n")

	credPath := fmt.Sprintf("/tmp/nexus-cf-%s.ini", rule.ID)
	run(fmt.Sprintf("printf 'dns_cloudflare_api_token = %%s\\n' %s > %s && chmod 600 %s", shellQuote(cfToken), credPath, credPath))

	certOut, certErr := run(fmt.Sprintf(
		`PATH="$PATH:/usr/bin:/usr/local/bin" certbot certonly --dns-cloudflare --dns-cloudflare-credentials %s `+
			`-d %s -d %s --non-interactive --agree-tos -m %s 2>&1`,
		credPath, shellQuote("*."+rule.Domain), shellQuote(rule.Domain), shellQuote(email),
	))
	out.WriteString(certOut + "\n")
	run(fmt.Sprintf("rm -f %s", credPath))

	if certErr != nil {
		return out.String(), certErr
	}
	if rule.ProxyType == "nginx" {
		nginxOut, _ := run(fmt.Sprintf(
			`PATH="$PATH:/usr/local/sbin:/usr/sbin" certbot install --nginx -d %s --non-interactive 2>&1 || `+
				`certbot install --nginx -d %s --non-interactive 2>&1 || true`,
			shellQuote("*."+rule.Domain), shellQuote(rule.Domain),
		))
		out.WriteString(nginxOut + "\n")
	}
	return out.String(), nil
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, map[string]string{"error": msg}, status)
}
