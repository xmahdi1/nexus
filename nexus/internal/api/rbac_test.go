package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	policy "github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func rbacFixture(t *testing.T, role, scope, scopeID string) (*gorm.DB, http.Handler, *http.Cookie, string) {
	t.Helper()
	database, err := db.Init(filepath.Join(t.TempDir(), "rbac-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	t.Cleanup(func() { c.Close() })
	hash, _ := bcrypt.GenerateFromPassword([]byte("RBAC fixture password"), bcrypt.MinCost)
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: bytes.Repeat([]byte{9}, 32)}
	owner, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"dev", "prod"} {
		if err := database.Create(&models.Server{ID: id, Name: "name-" + id, Host: map[string]string{"dev": "192.0.2.10", "prod": "192.0.2.20"}[id], Username: "fixture"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Direct fixture setup deliberately exercises the live HTTP owner under each
	// role without enabling additional-user login or bypassing session validation.
	if err := database.Where("principal_id=?", owner.User.ID).Delete(&policy.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&policy.Grant{ID: "fixture-role", PrincipalID: owner.User.ID, PrincipalKind: "user", RoleID: role, ScopeType: scope, ScopeID: scopeID, CreatedBy: "fixture", CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	login, err := auth.NewService(database, cfg).Login("owner", "RBAC fixture password", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return database, NewRouter(database, cfg, nil, nil), &http.Cookie{Name: auth.CookieName(), Value: login.Token}, owner.User.ID
}
func policyRequest(router http.Handler, cookie *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	request := secureTestRequest(method, path, strings.NewReader(body))
	request.AddCookie(cookie)
	if strings.HasPrefix(path, "/ws/") {
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)))
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
func concrete(path, server string) string {
	for key, value := range map[string]string{"{id}": server, "{cid}": strings.Repeat("a", 12), "{appId}": "child", "{ruleId}": "child", "{tid}": "child", "{n}": "1", "{gid}": "group", "{serverId}": server, "{grantId}": "grant"} {
		path = strings.ReplaceAll(path, key, value)
	}
	return path
}
func TestViewerDirectMutationAndCrossServerMatrix(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "viewer", "server", "dev")
	if err := chi.Walk(router.(chi.Routes), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if path == "/*" || path == "/health/live" || path == "/health/ready" || policy.Public(method, path) {
			return nil
		}
		entry, _, ok := policy.Resolve(method, path)
		if !ok || entry.Path != path {
			t.Errorf("route missing explicit policy: %s %s", method, path)
			return nil
		}
		if entry.Self {
			return nil
		}
		if method != "GET" {
			response := policyRequest(router, cookie, method, concrete(path, "dev"), `{"password":"MUST-NOT-APPEAR-IN-EVENTS"}`)
			if response.Code != 403 {
				t.Errorf("viewer mutation %s %s: %d", method, path, response.Code)
			}
		}
		if entry.Scope == "server" {
			response := policyRequest(router, cookie, method, concrete(path, "prod"), `{}`)
			if response.Code != 404 {
				t.Errorf("cross-server %s %s: %d", method, path, response.Code)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	list := policyRequest(router, cookie, "GET", "/api/servers", "")
	if list.Code != 200 || strings.Contains(list.Body.String(), "prod") || !strings.Contains(list.Body.String(), "name-dev") {
		t.Fatalf("unfiltered list: %d %s", list.Code, list.Body.String())
	}
	capabilities := policyRequest(router, cookie, "GET", "/api/auth/permissions", "")
	if capabilities.Code != 200 || strings.Contains(capabilities.Body.String(), "prod") {
		t.Fatal("capability endpoint leaked target")
	}
	var events []policy.Event
	database.Find(&events)
	serialized, _ := json.Marshal(events)
	if strings.Contains(string(serialized), "MUST-NOT-APPEAR") {
		t.Fatal("denial audit recorded secret body")
	}
	called := false
	router.(chi.Router).Post("/api/future/unsafe", func(w http.ResponseWriter, r *http.Request) { called = true })
	unknown := policyRequest(router, cookie, "POST", "/api/future/unsafe", `{}`)
	if unknown.Code != 403 || called {
		t.Fatal("future unregistered route bypassed central guard")
	}
}
func TestTaskParentScopeCannotBeConfused(t *testing.T) {
	database, router, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	for _, role := range []string{"host-control", "log-reader"} {
		if err := database.Create(&policy.Grant{ID: role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: "fixture", CreatedAt: time.Now()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	task := models.ScheduledTask{ID: "foreign", ServerID: "prod", ActorID: actor, Name: "private", Command: "untouched", Enabled: true}
	if err := database.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path string }{{"PUT", "/api/servers/dev/tasks/foreign"}, {"DELETE", "/api/servers/dev/tasks/foreign"}, {"POST", "/api/servers/dev/tasks/foreign/run"}} {
		response := policyRequest(router, cookie, tc.method, tc.path, `{"command":"changed"}`)
		if response.Code != 404 {
			t.Fatalf("IDOR %s returned %d", tc.method, response.Code)
		}
	}
	var preserved models.ScheduledTask
	database.First(&preserved, "id=?", task.ID)
	if preserved.Command != "untouched" || preserved.ServerID != "prod" {
		t.Fatal("foreign task changed")
	}
	response := policyRequest(router, cookie, "POST", "/api/servers/dev/tasks", `{"command":"fixture only","actorId":"forged","intervalMinutes":60}`)
	if response.Code != 201 {
		t.Fatalf("authorized scheduling failed %d %s", response.Code, response.Body.String())
	}
	var scheduled models.ScheduledTask
	if err := json.Unmarshal(response.Body.Bytes(), &scheduled); err != nil || scheduled.ActorID != actor || scheduled.CreatedBy != actor {
		t.Fatal("client forged execution identity")
	}
}
func TestAdminNeedsExplicitTerminalGrant(t *testing.T) {
	_, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	response := policyRequest(router, cookie, "GET", "/ws/terminal/dev", "")
	if response.Code != 403 {
		t.Fatalf("admin implicitly received raw terminal: %d", response.Code)
	}
}

func TestPolicyAdministrationRequiresProofAndProtectsLastAdmin(t *testing.T) {
	database, router, cookie, actor := rbacFixture(t, "admin", "global", "")
	bad := policyRequest(router, cookie, "POST", "/api/server-groups", `{"name":"Test","currentPassword":"wrong"}`)
	if bad.Code != 403 {
		t.Fatal("group created without credential proof")
	}
	created := policyRequest(router, cookie, "POST", "/api/server-groups", `{"name":"Development","currentPassword":"RBAC fixture password"}`)
	if created.Code != 201 {
		t.Fatalf("valid group rejected: %d %s", created.Code, created.Body.String())
	}
	var group policy.Group
	json.Unmarshal(created.Body.Bytes(), &group)
	assigned := policyRequest(router, cookie, "PUT", "/api/server-groups/"+group.ID+"/servers/dev", `{"currentPassword":"RBAC fixture password"}`)
	if assigned.Code != 200 {
		t.Fatal("valid membership failed")
	}
	revoked := policyRequest(router, cookie, "DELETE", "/api/grants/fixture-role", `{"currentPassword":"RBAC fixture password"}`)
	if revoked.Code != 409 {
		t.Fatalf("last admin removal returned %d", revoked.Code)
	}
	if !policy.New(database).Check(actor, "roles.manage", "") {
		t.Fatal("last admin role lost")
	}
}

func TestOperatorGroupCannotReadOrExecuteProduction(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "operator", "server", "dev")
	if err := database.Exec("INSERT INTO server_groups(id,name,created_at) VALUES('development','Development',?)", time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	database.Exec("INSERT INTO server_group_members(group_id,server_id) VALUES('development','dev')")
	database.Exec("UPDATE role_grants SET scope_type='server_group',scope_id='development' WHERE id='fixture-role'")
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/api/servers/dev", 200}, {"GET", "/api/servers/prod", 404}, {"POST", "/api/servers/prod/containers/" + strings.Repeat("a", 12) + "/start", 404}, {"GET", "/api/roles", 403}} {
		response := policyRequest(router, cookie, tc.method, tc.path, `{}`)
		if response.Code != tc.status {
			t.Fatalf("operator %s %s returned %d", tc.method, tc.path, response.Code)
		}
	}
	list := policyRequest(router, cookie, "GET", "/api/servers", "")
	if list.Code != 200 || strings.Contains(list.Body.String(), "prod") {
		t.Fatal("operator list leaked Production")
	}
}
