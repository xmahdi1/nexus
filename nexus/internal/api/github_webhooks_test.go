package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/githubactions"
)

func TestGitHubSignedIntakeAndManagementBoundaries(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	cfg := &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}
	router := NewRouter(database, cfg, nil, nil)
	conn := githubactions.Connection{ID: strings.Repeat("a", 32), ServerID: "dev", Owner: "fixture", Name: "repository", RepositoryID: 123, InstallationID: 42, CreatedBy: actor, CreatedAt: time.Now().UTC()}
	if err := database.Create(&conn).Error; err != nil {
		t.Fatal(err)
	}
	base := "/api/servers/dev/github/connections/" + conn.ID
	if response := policyRequest(router, cookie, "POST", base+"/webhook", ""); response.Code != 403 {
		t.Fatal("admin implicitly managed webhook", response.Code)
	}
	for _, role := range []string{"github-webhooks", "secret-reader"} {
		if err := database.Create(&authorization.Grant{ID: role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	result := policyRequest(router, cookie, "POST", base+"/webhook", "")
	var setup struct {
		Webhook githubactions.WebhookInfo `json:"webhook"`
		Secret  string                    `json:"secret"`
	}
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &setup) != nil || setup.Secret == "" {
		t.Fatal("setup failed", result.Code, result.Body.String())
	}
	read := policyRequest(router, cookie, "GET", base+"/webhook", "")
	if read.Code != 200 || strings.Contains(read.Body.String(), setup.Secret) {
		t.Fatal("metadata leaked secret")
	}
	body := `{"repository":{"id":123,"full_name":"fixture/repository"},"hook_id":8}`
	mac := hmac.New(sha256.New, []byte(setup.Secret))
	mac.Write([]byte(body))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	send := func(change func(*http.Request)) *httptest.ResponseRecorder {
		req := secureTestRequest("POST", setup.Webhook.Path, strings.NewReader(body))
		req.Header.Del("Origin")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "ping")
		req.Header.Set("X-GitHub-Delivery", "01020304-1234-1234-1234-0123456789ab")
		req.Header.Set("X-Hub-Signature-256", sig)
		if change != nil {
			change(req)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	var captured bytes.Buffer
	old := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(old)
	if response := send(nil); response.Code != 202 {
		t.Fatal("signed originless event rejected", response.Code, response.Body.String())
	}
	if strings.Contains(captured.String(), setup.Secret) || strings.Contains(captured.String(), setup.Webhook.Path) || !strings.Contains(captured.String(), "/api/hooks/github/{endpoint}") {
		t.Fatal("raw hook identity in logs", captured.String())
	}
	for _, tt := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"forged", func(r *http.Request) { r.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64)) }, 401},
		{"duplicate signature", func(r *http.Request) { r.Header.Add("X-Hub-Signature-256", sig) }, 400},
		{"cross origin", func(r *http.Request) { r.Header.Set("Origin", "https://other.test") }, 403},
		{"cleartext", func(r *http.Request) { r.TLS = nil; r.RemoteAddr = "192.0.2.99:12345" }, 400},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"wrong method", func(r *http.Request) { r.Method = "PUT"; r.Header.Set("Origin", "https://example.test") }, 401},
		{"trailing path", func(r *http.Request) { r.URL.Path += "/extra"; r.Header.Set("Origin", "https://example.test") }, 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if response := send(tt.change); response.Code != tt.status {
				t.Fatal(response.Code, response.Body.String())
			}
		})
	}
	req := secureTestRequest("POST", "/api/servers/dev/test", nil)
	req.Header.Del("Origin")
	req.AddCookie(cookie)
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, req)
	if denied.Code != 403 {
		t.Fatal("ordinary mutation lost origin requirement", denied.Code)
	}
	if response := policyRequest(router, cookie, "DELETE", base+"/webhook", ""); response.Code != 204 {
		t.Fatal("disable failed", response.Code)
	}
	if response := send(nil); response.Code != 401 {
		t.Fatal("disabled endpoint accepted", response.Code)
	}
}
