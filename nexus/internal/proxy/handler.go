package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xmahdi1/nexus/internal/audit"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type Handler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
	acme   config.ACMEConfig
}

type DetectResult struct {
	ProxyType string `json:"proxyType"`
	Version   string `json:"version"`
}

func NewHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool, options ...config.ACMEConfig) *Handler {
	h := &Handler{db: db, encKey: encKey, pool: pool}
	if len(options) > 0 {
		h.acme = options[0]
	}
	return h
}

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
var domainWildcardRe = regexp.MustCompile(`^\*\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

var targetPortDigits = regexp.MustCompile(`^[0-9]{1,5}$`)
var hostnameLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validDomain(d string) bool {
	return len(d) <= 253 && (domainRe.MatchString(d) || domainWildcardRe.MatchString(d))
}

func validTarget(target string) bool {
	host, portText, err := net.SplitHostPort(target)
	port, parseErr := strconv.Atoi(portText)
	if err != nil || parseErr != nil || !targetPortDigits.MatchString(portText) || port < 1 || port > 65535 || host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (h *Handler) ssh(ctx context.Context, serverID string) (func(string) (string, error), error) {
	send, err := h.sshInput(ctx, serverID)
	if err != nil {
		return nil, err
	}
	return func(command string) (string, error) { return send(command, "") }, nil
}
func (h *Handler) sshInput(ctx context.Context, serverID string) (func(string, string) (string, error), error) {
	policy, err := acmeCommandPolicy(h.acme)
	if err != nil {
		return nil, err
	}
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	client, err := h.pool.GetContext(ctx, nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return func(cmd, input string) (string, error) {
		out, err := nexusssh.Run(ctx, client, policy(cmd), strings.NewReader(input), nexusssh.CommandTimeout)
		return strings.TrimSpace(out), err
	}, nil
}

func (h *Handler) Detect(w http.ResponseWriter, r *http.Request) {
	run, err := h.ssh(r.Context(), chi.URLParam(r, "id"))
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
	if body.ProxyType != "nginx" && body.ProxyType != "caddy" {
		writeErr(w, "Unsupported proxy type.", 400)
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
	run, err := h.ssh(r.Context(), serverID)
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
		audit.MarkFailed(r.Context())
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

	audit.MarkResource(r.Context(), "proxy_rule", rule.ID)
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
	if body.ProxyType != "nginx" && body.ProxyType != "caddy" {
		writeErr(w, "Unsupported proxy type.", 400)
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
	if body.ProxyType != rule.ProxyType {
		writeErr(w, "Create and verify a replacement route before removing the original when changing proxy implementations.", 409)
		return
	}
	if rule.ProxyType == "nginx" && rule.SSLEnabled && (body.Domain != rule.Domain || !body.SSL) {
		writeErr(w, "Create and verify a replacement route before changing the domain or disabling TLS on an existing certificate-managed route.", 409)
		return
	}
	run, err := h.ssh(r.Context(), serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	var updateErr error
	switch rule.ProxyType {
	case "nginx":
		if rule.SSLEnabled {
			updateErr = updateNginxTarget(run, rule.ID, body.Target)
		} else {
			updateErr = createNginxRule(run, rule.ID, body.Domain, body.Target, body.SSL)
		}
	case "caddy":
		updateErr = updateCaddyRule(run, rule.Domain, body.Domain, body.Target)
	}
	if updateErr != nil {
		writeErr(w, "Proxy update failed; inspect the previous route before retrying. "+updateErr.Error(), 502)
		return
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

	if err := h.db.Model(&rule).Updates(map[string]any{
		"domain": body.Domain, "target": body.Target,
		"proxy_type": body.ProxyType, "ssl_enabled": sslOK,
	}).Error; err != nil {
		writeErr(w, "Could not save the updated rule.", 500)
		return
	}
	if body.SSL && !sslOK {
		audit.MarkFailed(r.Context())
	}
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
	run, err := h.ssh(r.Context(), serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	switch rule.ProxyType {
	case "nginx":
		if err := deleteNginxRule(run, rule.ID, rule.Domain); err != nil {
			writeErr(w, "Could not remove the old nginx rule.", 502)
			return
		}
	case "caddy":
		if err := deleteCaddyRule(run, rule.Domain); err != nil {
			writeErr(w, "Could not remove the old Caddy rule.", 502)
			return
		}
	}
	if err := h.db.Delete(&rule).Error; err != nil {
		writeErr(w, "Could not remove the stored rule.", 500)
		return
	}
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
		Renew    bool   `json:"renew"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Renew && !rule.SSLEnabled {
		writeErr(w, "renewal requires an existing enabled certificate", http.StatusBadRequest)
		return
	}
	if body.Wildcard && rule.ProxyType != "nginx" {
		writeErr(w, "DNS certificate management requires nginx", http.StatusBadRequest)
		return
	}
	if rule.ProxyType != "nginx" && rule.ProxyType != "caddy" {
		writeErr(w, "unsupported proxy type", http.StatusBadRequest)
		return
	}
	if body.Wildcard && (body.CFToken == "" || len(body.CFToken) > 4096 || strings.ContainsAny(body.CFToken, "\r\n\x00")) {
		writeErr(w, "a valid Cloudflare API token is required for DNS certificates", http.StatusBadRequest)
		return
	}
	if body.Email == "" {
		body.Email = "admin@" + rule.Domain
	}
	if !emailRe.MatchString(body.Email) {
		writeErr(w, "invalid email format", http.StatusBadRequest)
		return
	}
	send, err := h.sshInput(r.Context(), serverID)
	if err != nil {
		writeErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	run := func(command string) (string, error) { return send(command, "") }
	var output string
	var sslErr error
	if body.Wildcard {
		output, sslErr = enableWildcardSSLWithRenewal(run, send, rule, body.Email, body.CFToken, body.Renew, func(command string) (string, error) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
			defer cancel()
			cleanup, err := h.ssh(ctx, serverID)
			if err != nil {
				return "", err
			}
			return cleanup(command)
		})
	} else {
		switch rule.ProxyType {
		case "nginx":
			if body.Renew {
				output, sslErr = run("PATH=\"$PATH:/usr/bin:/usr/local/bin\" certbot renew --cert-name " + shellQuote(strings.TrimPrefix(rule.Domain, "*.")) + " --force-renewal --no-random-sleep-on-renew --non-interactive 2>&1")
			} else {
				output, sslErr = run(fmt.Sprintf(
					`PATH="$PATH:/usr/bin:/usr/local/bin" certbot --nginx -d %s --non-interactive --agree-tos --redirect -m %s 2>&1`,
					shellQuote(rule.Domain), shellQuote(body.Email),
				))
			}
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
	if err := h.db.Model(&rule).Update("ssl_enabled", true).Error; err != nil {
		writeErr(w, "Could not save certificate status.", 500)
		return
	}
	rule.SSLEnabled = true
	response := map[string]any{"rule": rule, "output": output}
	if body.Wildcard {
		response["warning"] = "Automatic DNS certificate renewal is not configured. The token is removed after this request. Use Renew with a fresh token before expiry, or configure renewal separately on the server. Nexus has not independently verified DNS cleanup."
		response["dnsCleanupStatus"] = "unverified"
		if dnsCleanupReportedFailure(output) {
			audit.MarkFailed(r.Context())
			response["dnsCleanupStatus"] = "reported_failure"
			response["warning"] = "Certificate installed, but the DNS plugin reported a cleanup failure. Inspect and remove only this operation's challenge records at the provider. Automatic renewal is not configured."
		}
	}
	json.NewEncoder(w).Encode(response)
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

var managedProxyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

const nginxValidate = `nginx -t 2>&1`
const nginxReload = `nginx -s reload 2>&1`
const caddyValidate = `caddy validate --config /etc/caddy/Caddyfile 2>&1`
const caddyReload = `caddy reload --config /etc/caddy/Caddyfile 2>&1`

func nginxPaths(id string) (string, string, error) {
	if !managedProxyID.MatchString(id) {
		return "", "", fmt.Errorf("invalid managed proxy identity")
	}
	return "/etc/nginx/sites-available/nexus-" + id + ".conf", "/etc/nginx/sites-enabled/nexus-" + id + ".conf", nil
}
func createNginxRule(run func(string) (string, error), id, domain, target string, ssl bool) error {
	if !validDomain(domain) || !validTarget(target) {
		return fmt.Errorf("invalid proxy route")
	}
	conf, link, err := nginxPaths(id)
	if err != nil {
		return err
	}
	change := "[ ! -L " + shellQuote(conf) + " ] || exit 1\ncat > " + shellQuote(conf) + " << 'NEXUS_EOF' || exit 1\n" + nginxConfig(domain, target) + "\nNEXUS_EOF\nln -sf -- " + shellQuote(conf) + " " + shellQuote(link) + " || exit 1"
	return proxyTransaction(run, []string{conf, link}, change, nginxValidate, nginxReload)
}
func updateNginxTarget(run func(string) (string, error), id, target string) error {
	if !validTarget(target) {
		return fmt.Errorf("invalid proxy target")
	}
	conf, link, err := nginxPaths(id)
	if err != nil {
		return err
	}
	return proxyTransaction(run, []string{conf, link}, nginxTargetChange(conf, target), nginxValidate, nginxReload)
}
func nginxTargetChange(conf, target string) string {
	pattern := `s@^([[:space:]]*)proxy_pass http://[^;]*;@\1proxy_pass http://` + target + `;@`
	return "[ ! -L " + shellQuote(conf) + " ] || exit 1\n[ \"$(grep -c '^[[:space:]]*proxy_pass http://' " + shellQuote(conf) + ")\" = 1 ] || exit 1\nsed -i -E " + shellQuote(pattern) + " " + shellQuote(conf) + " || exit 1"
}

func deleteNginxRule(run func(string) (string, error), id, _ string) error {
	conf, link, err := nginxPaths(id)
	if err != nil {
		return err
	}
	return proxyTransaction(run, []string{conf, link}, "rm -f -- "+shellQuote(conf)+" "+shellQuote(link)+" || exit 1", nginxValidate, nginxReload)
}
func caddyBlock(domain, target string) string {
	return fmt.Sprintf("\n%s {\n    reverse_proxy %s\n}\n", domain, target)
}
func caddyEdit(run func(string) (string, error), change string) error {
	const file = "/etc/caddy/Caddyfile"
	return proxyTransaction(run, []string{file}, "[ ! -L "+shellQuote(file)+" ] || exit 1\n"+change, caddyValidate, caddyReload)
}
func createCaddyRule(run func(string) (string, error), domain, target string) error {
	if !validDomain(domain) || !validTarget(target) {
		return fmt.Errorf("invalid proxy route")
	}
	return caddyEdit(run, "cat >> /etc/caddy/Caddyfile << 'NEXUS_EOF' || exit 1\n"+caddyBlock(domain, target)+"NEXUS_EOF")
}
func deleteCaddyCommand(domain string) (string, error) {
	if !validDomain(domain) {
		return "", fmt.Errorf("invalid stored domain")
	}
	pattern := "/^" + regexp.QuoteMeta(domain) + " {/,/^}/d"
	return "sed -i " + shellQuote(pattern) + " /etc/caddy/Caddyfile || exit 1", nil
}
func deleteCaddyRule(run func(string) (string, error), domain string) error {
	change, err := deleteCaddyCommand(domain)
	if err != nil {
		return err
	}
	return caddyEdit(run, change)
}
func updateCaddyRule(run func(string) (string, error), oldDomain, domain, target string) error {
	if !validDomain(domain) || !validTarget(target) {
		return fmt.Errorf("invalid proxy route")
	}
	change, err := deleteCaddyCommand(oldDomain)
	if err != nil {
		return err
	}
	return caddyEdit(run, change+"\ncat >> /etc/caddy/Caddyfile << 'NEXUS_EOF' || exit 1\n"+caddyBlock(domain, target)+"NEXUS_EOF")
}

func enableWildcardSSL(run func(string) (string, error), send func(string, string) (string, error), rule models.ProxyRule, email, cfToken string, cleanup ...func(string) (string, error)) (output string, resultErr error) {
	return enableWildcardSSLWithRenewal(run, send, rule, email, cfToken, false, cleanup...)
}

func enableWildcardSSLWithRenewal(run func(string) (string, error), send func(string, string) (string, error), rule models.ProxyRule, email, cfToken string, renew bool, cleanup ...func(string) (string, error)) (output string, resultErr error) {
	if cfToken == "" || len(cfToken) > 4096 || strings.ContainsAny(cfToken, "\r\n\x00") {
		return "", fmt.Errorf("invalid DNS API token")
	}
	domain := strings.TrimPrefix(rule.Domain, "*.")
	if !domainRe.MatchString(domain) || len(domain) > 253 || !emailRe.MatchString(email) {
		return "", fmt.Errorf("invalid certificate domain or email")
	}
	defer func() {
		output = strings.ReplaceAll(output, cfToken, "[redacted]")
		if resultErr != nil && strings.Contains(resultErr.Error(), cfToken) {
			resultErr = errors.New(strings.ReplaceAll(resultErr.Error(), cfToken, "[redacted]"))
		}
	}()
	var out strings.Builder
	installOut, installErr := run(`PATH="$PATH:/usr/bin:/usr/local/bin" apt-get install -y python3-certbot-dns-cloudflare 2>&1 || pip3 install certbot-dns-cloudflare 2>&1`)
	out.WriteString(installOut + "\n")
	if installErr != nil {
		return out.String(), fmt.Errorf("could not prepare DNS certificate plugin")
	}

	credPath, err := run("umask 077; mktemp /tmp/nexus-cf.XXXXXXXXXX")
	if err != nil || !regexp.MustCompile(`^/tmp/nexus-cf\.[A-Za-z0-9]{10}$`).MatchString(credPath) {
		return out.String(), fmt.Errorf("could not create private certificate credentials")
	}
	defer func() {
		remove := run
		if len(cleanup) > 0 {
			remove = cleanup[0]
		}
		if _, err := remove("rm -f -- " + shellQuote(credPath)); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("certificate credential cleanup failed"))
		}
	}()
	if _, err := send("cat > "+shellQuote(credPath)+" && chmod 600 -- "+shellQuote(credPath), "dns_cloudflare_api_token = "+cfToken+"\n"); err != nil {
		return out.String(), fmt.Errorf("could not write private certificate credentials")
	}

	command := fmt.Sprintf(
		`PATH="$PATH:/usr/bin:/usr/local/bin" certbot certonly --dns-cloudflare --dns-cloudflare-credentials %s `+
			`--cert-name %s -d %s -d %s --non-interactive --agree-tos -m %s 2>&1`,
		shellQuote(credPath), shellQuote(domain), shellQuote("*."+domain), shellQuote(domain), shellQuote(email))
	if renew {
		command = "PATH=\"$PATH:/usr/bin:/usr/local/bin\" certbot renew --cert-name " + shellQuote(domain) + " --force-renewal --no-random-sleep-on-renew --dns-cloudflare --dns-cloudflare-credentials " + shellQuote(credPath) + " --non-interactive 2>&1"
	}
	certOut, certErr := run(command)
	out.WriteString(certOut + "\n")

	if certErr != nil {
		return out.String(), certErr
	}
	if rule.ProxyType == "nginx" {
		nginxOut, installErr := run("PATH=\"$PATH:/usr/local/sbin:/usr/sbin:/usr/bin:/usr/local/bin\" certbot install --nginx --cert-name " + shellQuote(domain) + " -d " + shellQuote(rule.Domain) + " --non-interactive 2>&1")
		out.WriteString(nginxOut + "\n")
		if installErr != nil {
			return out.String(), installErr
		}
	}
	return out.String(), nil
}

func dnsCleanupReportedFailure(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "error deleting txt record") || strings.Contains(output, "error during cleanup") || strings.Contains(output, "cleanup failed")
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
