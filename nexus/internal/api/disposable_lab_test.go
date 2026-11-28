package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDedicatedDisposableLinuxLab(t *testing.T) {
	address := os.Getenv("NEXUS_DISPOSABLE_SSH_ADDR")
	if address == "" {
		t.Skip("run scripts/ssh_lab.py for the isolated Linux target")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("loopback disposable target required")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := os.Getenv("NEXUS_DISPOSABLE_KEY_FILE")
	if !strings.HasPrefix(filepath.Clean(keyPath), "/tmp/nexus-ssh-lab-") {
		t.Fatal("temporary fixture key required")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(key); block == nil {
		t.Fatal("invalid fixture key")
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("NEXUS_DISPOSABLE_HOST_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	defer pool.Remove("fixture")
	pool.SetHostKeyCallback(func(id, fingerprint string) error {
		if id != "fixture" || fingerprint != ssh.FingerprintSHA256(public) {
			return fmt.Errorf("untrusted disposable host")
		}
		return nil
	})
	client, err := pool.Get(nexusssh.ServerConfig{ID: "fixture", Host: host, Port: port, User: "root", PrivKey: key})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	marker, err := session.Output("cat /nexus-disposable-fixture")
	session.Close()
	nonce := os.Getenv("NEXUS_DISPOSABLE_NONCE")
	if err != nil || len(nonce) != 32 || string(marker) != nonce {
		t.Fatal("target lacks disposable proof; refusing all mutations")
	}
	database, err := db.Init(filepath.Join(t.TempDir(), "lab.db"))
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	defer conn.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte("disposable fixture password"), bcrypt.MinCost)
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: bytes.Repeat([]byte{7}, 32), InventoryEnabled: true}
	encrypted, err := nexuscrypto.Encrypt(cfg.EncryptionKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.Server{ID: "fixture", Name: "Disposable", Host: host, Port: port, Username: "root", PrivateKeyEnc: encrypted}).Error; err != nil {
		t.Fatal(err)
	}
	login, err := auth.NewService(database, cfg).Login("", "disposable fixture password", "lab", host)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: auth.CookieName(), Value: login.Token}
	router := NewRouter(database, cfg, pool, nil)
	request := func(method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := policyRequest(router, cookie, method, path, body)
		if response.Code != status {
			t.Fatalf("%s %s: %d %s", method, path, response.Code, response.Body.String())
		}
		return response
	}
	prefix := "/api/servers/fixture"
	request("POST", prefix+"/files/mkdir", `{"path":"/tmp/nexus-disposable-files"}`, 200)
	var upload bytes.Buffer
	form := multipart.NewWriter(&upload)
	part, err := form.CreateFormFile("file", "upload.bin")
	if err != nil {
		t.Fatal(err)
	}
	uploadPayload := []byte("multipart fixture\n\x00\xff")
	if _, err := part.Write(uploadPayload); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	uploadRequest := secureTestRequest(http.MethodPost, prefix+"/files/upload?path=/tmp/nexus-disposable-files", bytes.NewReader(upload.Bytes()))
	uploadRequest.Header.Set("Content-Type", form.FormDataContentType())
	uploadRequest.AddCookie(cookie)
	uploadResponse := httptest.NewRecorder()
	router.ServeHTTP(uploadResponse, uploadRequest)
	if uploadResponse.Code != http.StatusOK {
		t.Fatalf("multipart SFTP upload failed: %d %s", uploadResponse.Code, uploadResponse.Body.String())
	}
	if got := request("GET", prefix+"/files/download?path=/tmp/nexus-disposable-files/upload.bin", "", 200).Body.Bytes(); !bytes.Equal(got, uploadPayload) {
		t.Fatal("multipart SFTP upload changed bytes")
	}
	request("PUT", prefix+"/files", `{"path":"/tmp/nexus-disposable-files/roundtrip.txt","content":"fixture roundtrip only"}`, 200)
	downloaded := request("GET", prefix+"/files/download?path=/tmp/nexus-disposable-files/roundtrip.txt", "", 200)
	if downloaded.Body.String() != "fixture roundtrip only" {
		t.Fatal("SFTP roundtrip changed bytes")
	}
	if _, err := nexusssh.Run(context.Background(), client, "ln -s /tmp/nexus-disposable-files /tmp/nexus-disposable-link", nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	request("DELETE", prefix+"/files?path=/tmp/nexus-disposable-link", "", 204)
	if result := request("GET", prefix+"/files/download?path=/tmp/nexus-disposable-files/roundtrip.txt", "", 200); result.Body.String() != "fixture roundtrip only" {
		t.Fatal("SFTP deletion followed directory symlink")
	}
	request("DELETE", prefix+"/files?path=/", "", 400)

	request("DELETE", prefix+"/files?path=/tmp/nexus-disposable-files", "", 204)
	request("POST", prefix+"/cron", `{"schedule":"0 0 1 1 *","command":"true # nexus-disposable-cron"}`, 200)
	jobs := request("GET", prefix+"/cron", "", 200)
	if !strings.Contains(jobs.Body.String(), "nexus-disposable-cron") {
		t.Fatal("crontab write not visible")
	}
	request("DELETE", prefix+"/cron", `{"raw":"0 0 1 1 * true # nexus-disposable-cron"}`, 200)
	created := request("POST", prefix+"/proxy", `{"proxyType":"nginx","domain":"nexus-lab.example.test","target":"127.0.0.1:8081","ssl":false}`, 201)
	var rule models.ProxyRule
	if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil || rule.ID == "" {
		t.Fatal("missing proxy record", err)
	}
	nginxConfigPath := "/etc/nginx/sites-available/nexus-" + rule.ID + ".conf"
	originalConfig, err := nexusssh.Run(context.Background(), client, "sha256sum -- "+nginxConfigPath, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"validation", "reload"} {
		script := "#!/bin/sh\n"
		if failure == "validation" {
			script += "if [ \"$1\" = -t ]; then echo 'fixture validation failure'; exit 42; fi\n"
		} else {
			script += "if [ \"$1\" = -s ] && [ \"$2\" = reload ] && [ ! -e /tmp/nexus-reload-attempted ]; then touch /tmp/nexus-reload-attempted; exit 42; fi\n"
		}
		script += "exec /usr/sbin/nginx \"$@\"\n"
		payload, _ := json.Marshal(map[string]string{"path": "/usr/local/bin/nginx", "content": script})
		request("PUT", prefix+"/files", string(payload), 200)
		if _, err := nexusssh.Run(context.Background(), client, "chmod 700 /usr/local/bin/nginx", nil, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		request("PUT", prefix+"/proxy/"+rule.ID, `{"proxyType":"nginx","domain":"nexus-lab.example.test","target":"127.0.0.1:8089","ssl":false}`, 502)
		after, err := nexusssh.Run(context.Background(), client, "sha256sum -- "+nginxConfigPath, nil, 5*time.Second)
		if err != nil || after != originalConfig {
			t.Fatal("failed proxy edit lost original configuration", failure, err)
		}
		var unchanged models.ProxyRule
		if err := database.First(&unchanged, "id=?", rule.ID).Error; err != nil || unchanged.Target != "127.0.0.1:8081" {
			t.Fatal("failed proxy edit changed stored route", err)
		}
		request("DELETE", prefix+"/files?path=/usr/local/bin/nginx", "", 204)
	}
	t.Log("Real nginx validation/reload failures restored the previous configuration and stored target")

	request("PUT", prefix+"/proxy/"+rule.ID, `{"proxyType":"nginx","domain":"nexus-lab.example.test","target":"127.0.0.1:8082","ssl":false}`, 200)
	// A private fixture certificate verifies TLS directives survive an upstream
	// edit. This never invokes a public issuer or changes host trust.
	certificateCommand := `umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=nexus-lab.example.test' -addext 'subjectAltName=DNS:nexus-lab.example.test' -keyout /tmp/nexus-nginx-fixture.key -out /etc/ssl/certs/nexus-nginx-fixture.crt >/dev/null 2>&1`
	if _, err := nexusssh.Run(context.Background(), client, certificateCommand, nil, 10*time.Second); err != nil {
		t.Fatal("fixture certificate setup failed", err)
	}
	tlsConfig := "server {\n listen 8444 ssl;\n server_name nexus-lab.example.test;\n ssl_certificate /etc/ssl/certs/nexus-nginx-fixture.crt;\n ssl_certificate_key /tmp/nexus-nginx-fixture.key;\n location / {\n  proxy_pass http://127.0.0.1:8082;\n }\n}\n"
	tlsBody, _ := json.Marshal(map[string]string{"path": nginxConfigPath, "content": tlsConfig})
	request("PUT", prefix+"/files", string(tlsBody), 200)
	if _, err := nexusssh.Run(context.Background(), client, "nginx -t && nginx -s reload", nil, 5*time.Second); err != nil {
		t.Fatal("fixture TLS reload failed", err)
	}
	if err := database.Model(&models.ProxyRule{}).Where("id=?", rule.ID).Update("ssl_enabled", true).Error; err != nil {
		t.Fatal(err)
	}
	request("PUT", prefix+"/proxy/"+rule.ID, `{"proxyType":"nginx","domain":"nexus-lab.example.test","target":"127.0.0.1:8083","ssl":true}`, 200)
	preserved, err := nexusssh.Run(context.Background(), client, "cat -- "+nginxConfigPath, nil, 5*time.Second)
	if err != nil || !strings.Contains(preserved, "listen 8444 ssl;") || !strings.Contains(preserved, "ssl_certificate /etc/ssl/certs/nexus-nginx-fixture.crt;") || !strings.Contains(preserved, "proxy_pass http://127.0.0.1:8083;") {
		t.Fatal("upstream edit lost TLS configuration", err)
	}
	statusCode, err := nexusssh.Run(context.Background(), client, `curl --silent --show-error --cacert /etc/ssl/certs/nexus-nginx-fixture.crt --noproxy '*' --resolve nexus-lab.example.test:8444:127.0.0.1 https://nexus-lab.example.test:8444 -o /dev/null -w '%{http_code}'`, nil, 5*time.Second)
	if err != nil || statusCode != "502" {
		t.Fatal("TLS listener not preserved after upstream edit", err)
	}
	t.Log("Real nginx upstream edit preserved a trusted private fixture certificate/TLS listener")

	nginxRuleID := rule.ID
	created = request("POST", prefix+"/proxy", `{"proxyType":"caddy","domain":"nexus-caddy.example.test","target":"127.0.0.1:80","ssl":false}`, 201)
	if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil || rule.ID == "" {
		t.Fatal("missing Caddy record", err)
	}
	response, err := nexusssh.Run(context.Background(), client, "curl --fail --silent --cacert /root/.local/share/caddy/pki/authorities/local/root.crt --noproxy '*' --retry 5 --retry-all-errors --retry-connrefused --retry-delay 1 --max-time 5 --resolve nexus-caddy.example.test:8443:127.0.0.1 https://nexus-caddy.example.test:8443", nil, 15*time.Second)
	if err != nil || !strings.Contains(response, "nginx") {
		t.Fatal("Caddy did not forward to real upstream", err)
	}
	request("POST", prefix+"/inventory/discover", `{}`, 200)
	report := request("GET", prefix+"/inventory/documentation", "", 200)
	var projection struct {
		Resources []struct {
			Kind    string `json:"kind"`
			Details struct {
				Engine      string   `json:"engine"`
				Host        string   `json:"host"`
				Port        int      `json:"port"`
				NameMatches bool     `json:"nameMatches"`
				Upstreams   []string `json:"upstreams"`
			} `json:"details"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(report.Body.Bytes(), &projection); err != nil {
		t.Fatal("proxy inventory report did not decode", err)
	}
	found := map[string]bool{}
	for _, item := range projection.Resources {
		details := item.Details
		switch {
		case details.Engine == "nginx" && details.Host == "nexus-lab.example.test" && details.Port == 8444:
			found["nginx-"+item.Kind] = details.NameMatches || len(details.Upstreams) == 1 && details.Upstreams[0] == "http://127.0.0.1:8083"
		case details.Engine == "caddy" && details.Host == "nexus-caddy.example.test" && details.Port == 8443:
			found["caddy-"+item.Kind] = details.NameMatches || len(details.Upstreams) == 1 && details.Upstreams[0] == "http://127.0.0.1:80"
		}
	}
	for _, fact := range []string{"nginx-proxy_route", "caddy-proxy_route", "nginx-tls_certificate", "caddy-tls_certificate"} {
		if !found[fact] {
			t.Fatalf("missing or incorrect proxy evidence %s", fact)
		}
	}
	if strings.Contains(report.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(report.Body.String(), "nexus-nginx-fixture.key") {
		t.Fatal("inventory report exposed raw certificate or key metadata")
	}
	t.Log("Real nginx and Caddy configurations and on-disk TLS certificates appeared in the scoped host report.")
	request("DELETE", prefix+"/proxy/"+nginxRuleID, "", 204)

	request("PUT", prefix+"/proxy/"+rule.ID, `{"proxyType":"caddy","domain":"nexus-caddy-updated.example.test","target":"127.0.0.1:80","ssl":false}`, 200)
	request("DELETE", prefix+"/proxy/"+rule.ID, "", 204)
	if os.Getenv("NEXUS_DISPOSABLE_FIREWALL") == "1" {
		request("POST", prefix+"/firewall/rules", `{"port":"22/tcp","action":"allow"}`, 200)
		request("POST", prefix+"/firewall/enable", `{}`, 200)
		request("POST", prefix+"/firewall/rules", `{"port":"54321/tcp","action":"deny","from":"127.0.0.1"}`, 200)
		status := request("GET", prefix+"/firewall", "", 200)
		if !strings.Contains(status.Body.String(), `"status":"active"`) || !strings.Contains(status.Body.String(), "54321") {
			t.Fatal("UFW rule not observed", status.Body.String())
		}
		request("DELETE", prefix+"/firewall/rules/2", "", 200)
		if os.Getenv("NEXUS_DISPOSABLE_IPV6") == "1" {
			request("POST", prefix+"/firewall/rules", `{"port":"54322/tcp","action":"deny","from":"::1"}`, 200)
			status = request("GET", prefix+"/firewall", "", 200)
			var observed struct {
				Rules []struct {
					Number int    `json:"number"`
					To     string `json:"to"`
					From   string `json:"from"`
				}
			}
			if err := json.Unmarshal(status.Body.Bytes(), &observed); err != nil {
				t.Fatal(err)
			}
			number := 0
			for _, rule := range observed.Rules {
				if strings.Contains(rule.To, "54322") && strings.Contains(rule.From, "::1") {
					number = rule.Number
					break
				}
			}
			if number == 0 {
				t.Fatal("IPv6 rule not observed", status.Body.String())
			}
			request("DELETE", fmt.Sprintf("%s/firewall/rules/%d", prefix, number), "", 200)
			t.Log("Real IPv6 UFW add/read/delete passed in the disposable network namespace")
		}

		request("POST", prefix+"/firewall/disable", `{}`, 200)
		t.Log("Real IPv4 UFW enable/add/read/delete/disable passed in the disposable network namespace")
	}

	scan := request("POST", prefix+"/inventory/discover", `{}`, 200)
	if !strings.Contains(scan.Body.String(), `"status":"partial"`) {
		t.Fatal("Docker-unavailable collector not partial", scan.Body.String())
	}
	snapshot := request("GET", prefix+"/inventory?limit=200", "", 200)
	if !strings.Contains(snapshot.Body.String(), `"kind":"host"`) || !strings.Contains(snapshot.Body.String(), `"exposure":"listener"`) {
		t.Fatal("Linux inventory incomplete")
	}
	for _, fact := range []string{`"kind":"interface"`, `"kind":"address"`, `"kind":"route"`, `"address":"127.0.0.1"`, `"kind":"mount"`, `"kind":"resolver"`} {
		if !strings.Contains(snapshot.Body.String(), fact) {
			t.Fatalf("Linux network inventory missing %s", fact)
		}
	}
	// Exercise the complete template API/storage path with a fixture-only Docker
	// executable. The separate Compose lab covers actual daemon lifecycle/data.
	fakeDocker := "#!/bin/sh\ncase \"$*\" in \"compose version\"|\"compose up -d\"|\"compose down\") printf 'fixture Docker result\\n'; exit 0;; *) exit 127;; esac\n"
	encoded, _ := json.Marshal(map[string]string{"path": "/usr/local/bin/docker", "content": fakeDocker})
	request("PUT", prefix+"/files", string(encoded), 200)
	if _, err := nexusssh.Run(context.Background(), client, "chmod 700 /usr/local/bin/docker", nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	template := request("POST", "/api/templates/custom", `{"name":"Encrypted fixture","compose":"services: {}","vars":[{"name":"PASSWORD","type":"password"}]}`, 201)
	var custom models.CustomTemplate
	if err := json.Unmarshal(template.Body.Bytes(), &custom); err != nil || custom.ID == "" {
		t.Fatal("missing template", err)
	}
	secret := "private-deployment-fixture-" + nonce
	payload, _ := json.Marshal(map[string]any{"templateId": custom.ID, "appName": "encrypted-fixture", "variables": map[string]string{"PASSWORD": secret}})
	deployed := request("POST", prefix+"/apps/deploy", string(payload), 201)
	if strings.Contains(deployed.Body.String(), secret) || strings.Contains(deployed.Body.String(), "varsEnc") {
		t.Fatal("deployment response exposed protected variables")
	}
	var envelope struct {
		App models.DeployedApp `json:"app"`
	}
	if err := json.Unmarshal(deployed.Body.Bytes(), &envelope); err != nil || envelope.App.ID == "" {
		t.Fatal("missing deployment", err)
	}
	var stored models.DeployedApp
	if err := database.First(&stored, "id=?", envelope.App.ID).Error; err != nil {
		t.Fatal(err)
	}
	protected, err := nexuscrypto.DecryptDeploymentVariables(cfg.EncryptionKey, stored.ID, stored.ServerID, stored.VarsEnc)
	if err != nil || !strings.Contains(string(protected), secret) {
		t.Fatal("stored deployment variables were not preserved encrypted", err)
	}
	clear(protected)
	mode, err := nexusssh.Run(context.Background(), client, "stat -c '%a' /opt/nexus-apps/encrypted-fixture /opt/nexus-apps/encrypted-fixture/docker-compose.yml", nil, 5*time.Second)
	if err != nil || strings.TrimSpace(mode) != "700\n600" {
		t.Fatal("remote deployment permissions are not private", err)
	}
	request("DELETE", prefix+"/apps/"+stored.ID, "", 200)
	request("GET", prefix+"/files/preview?path=/opt/nexus-apps/encrypted-fixture/docker-compose.yml", "", 200)
	request("DELETE", prefix+"/files?path=/usr/local/bin/docker", "", 204)
	var auditRows []map[string]any
	if err := database.Table("operation_events").Find(&auditRows).Error; err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(auditRows)
	if strings.Contains(string(metadata), secret) {
		t.Fatal("audit exposed deployment variables")
	}
	t.Log("Template API encrypted variables, private recipe, response/audit exclusion and data-preserving removal passed (fixture-only Docker command)")

	listener := httptest.NewTLSServer(router)
	defer listener.Close()
	target, _ := url.Parse(listener.URL)

	if err := database.Exec("INSERT INTO server_groups(id,name,created_at,require_mfa) VALUES('terminal-fixture','Terminal fixture',?,0)", time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO server_group_members(group_id,server_id) VALUES('terminal-fixture','fixture')").Error; err != nil {
		t.Fatal(err)
	}
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second}
	for index, cause := range []string{"absolute_expiry", "idle_expiry", "role_revoked", "protected", "logout"} {
		login, err = auth.NewService(database, cfg).Login("", "disposable fixture password", "lab", host)
		if err != nil {
			t.Fatal(err)
		}
		cookie = &http.Cookie{Name: auth.CookieName(), Value: login.Token}
		actor, err := auth.NewService(database, cfg).Authenticate(login.Token)
		if err != nil {
			t.Fatal(err)
		}
		headers := http.Header{"Origin": []string{listener.URL}, "Cookie": []string{auth.CookieName() + "=" + login.Token}}
		ws, _, err := dialer.Dial("wss://"+target.Host+"/ws/terminal/fixture", headers)
		if err != nil {
			t.Fatal(cause, err)
		}
		if err := ws.WriteJSON(map[string]string{"type": "input", "data": "printf 'NEXUS_TERMINAL_%s\\n' 'FIXTURE_OK'\n"}); err != nil {
			ws.Close()
			t.Fatal(err)
		}
		ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		var terminal strings.Builder
		for !strings.Contains(terminal.String(), "NEXUS_TERMINAL_FIXTURE_OK") {
			_, data, err := ws.ReadMessage()
			if err != nil {
				ws.Close()
				t.Fatal(cause, "terminal did not execute", err)
			}
			terminal.Write(data)
		}
		var grants []authorization.Grant
		switch cause {
		case "absolute_expiry", "idle_expiry":
			column := "expires_at"
			if cause == "idle_expiry" {
				column = "last_used_at"
			}
			if err := database.Model(&auth.Session{}).Where("id=?", actor.Session.ID).Update(column, time.Now().UTC().Add(-48*time.Hour)).Error; err != nil {
				t.Fatal(err)
			}
		case "role_revoked":
			if err := database.Where("principal_id=? AND role_id='host-control'", auth.LegacyPrincipal).Find(&grants).Error; err != nil || len(grants) == 0 {
				t.Fatal("missing fixture grant", err)
			}
			if err := database.Where("principal_id=? AND role_id='host-control'", auth.LegacyPrincipal).Delete(&authorization.Grant{}).Error; err != nil {
				t.Fatal(err)
			}
		case "protected":
			if err := database.Exec("UPDATE server_groups SET require_mfa=1 WHERE id='terminal-fixture'").Error; err != nil {
				t.Fatal(err)
			}
		case "logout":
			request("POST", "/api/auth/logout", `{}`, 200)
		}
		ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					ws.Close()
					t.Fatal("terminal survived", cause)
				}
				break
			}
		}
		ws.Close()
		deadline := time.Now().Add(3 * time.Second)
		var audited int64
		for time.Now().Before(deadline) {
			database.Table("operation_events").Where("source='websocket' AND action='GET /ws/terminal/{id}' AND outcome='stream_closed'").Count(&audited)
			if audited >= int64(index+1) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if audited < int64(index+1) {
			t.Fatal("terminal lacks completion audit", cause)
		}
		if len(grants) > 0 {
			if err := database.Create(&grants).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := database.Exec("UPDATE server_groups SET require_mfa=0 WHERE id='terminal-fixture'").Error; err != nil {
			t.Fatal(err)
		}
		t.Log("Real terminal closed and audited after", cause)
	}

	t.Log("Disposable Linux SFTP, crontab, nginx and private-CA Caddy create/update/delete, inventory and terminal revocation passed; no host Docker socket or real infrastructure used.")
}
