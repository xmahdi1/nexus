package api

import (
	"bytes"
	"encoding/json"
	"github.com/xmahdi1/nexus/internal/audit"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/vault"
)

func TestVaultConfigurationFeatureScopeAndNoTokenStorage(t *testing.T) {
	database, disabled, cookie, _ := rbacFixture(t, "admin", "server", "dev")
	if r := policyRequest(disabled, cookie, "GET", "/api/servers/dev/vault", ""); r.Code != 409 {
		t.Fatal("disabled feature accessible", r.Code)
	}
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), VaultEnabled: true}, nil, nil)
	profile := `{"port":8200,"tlsName":"vault.test","caPem":"","namespace":""}`
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		if r := policyRequest(router, cookie, method, "/api/servers/prod/vault", profile); r.Code != 404 {
			t.Fatal("cross-server connection accessible", method, r.Code)
		}
	}
	if r := policyRequest(router, cookie, "PUT", "/api/servers/dev/vault", profile); r.Code != 200 {
		t.Fatal("save failed", r.Code, r.Body.String())
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/dev/vault", ""); r.Code != 200 || !strings.Contains(r.Body.String(), "vault.test") || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing profile", r.Code)
	}
	if r := policyRequest(router, cookie, "PUT", "/api/servers/dev/vault", `{"port":8200,"tlsName":"vault.test","namespace":"team/"}`); r.Code != 400 {
		t.Fatal("unsupported namespace advertised", r.Code)
	}
	const token = "fixture-token-never-save"
	if r := policyRequest(router, cookie, "PUT", "/api/servers/dev/vault", `{"port":8200,"tlsName":"vault.test","token":"`+token+`"}`); r.Code != 400 {
		t.Fatal("credential accepted into settings", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/inspect", `{"token":"`+token+`"}`); r.Code != 502 || strings.Contains(r.Body.String(), token) {
		t.Fatal("unavailable transport leaked token", r.Code, r.Body.String())
	}
	var stored vault.Profile
	if err := database.First(&stored, "server_id=?", "dev").Error; err != nil || stored.TLSName != "vault.test" {
		t.Fatal("profile damaged", err)
	}
	var events []audit.Event
	if err := database.Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), token) {
		t.Fatal("token in audit")
	}

	// The connection belongs to the server and is removed with it.
	if err := database.Delete(&models.Server{}, "id=?", "dev").Error; err != nil {
		t.Fatal(err)
	}
	var count int64
	database.Model(&vault.Profile{}).Count(&count)
	if count != 0 {
		t.Fatal("orphaned connection after server removal")
	}
}

func TestVaultRequiresIntegrationAuthority(t *testing.T) {
	database, _, cookie, _ := rbacFixture(t, "viewer", "server", "dev")
	router := NewRouter(database, &config.Config{VaultEnabled: true}, nil, nil)
	for _, route := range []struct{ method, path string }{{"GET", "/vault"}, {"PUT", "/vault"}, {"DELETE", "/vault"}, {"POST", "/vault/inspect"}, {"POST", "/vault/access/auth"}, {"POST", "/vault/access/policies"}, {"POST", "/vault/access/policy"}, {"POST", "/vault/access/capabilities"}} {
		if r := policyRequest(router, cookie, route.method, "/api/servers/dev"+route.path, `{}`); r.Code != 403 {
			t.Fatal("viewer gained Vault access", route, r.Code)
		}
	}
}

func TestVaultPolicyInspectionRequiresScopedRoleAuthority(t *testing.T) {
	database, _, cookie, _ := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{VaultEnabled: true}, nil, nil)
	if r := policyRequest(router, cookie, "PUT", "/api/servers/dev/vault", `{"port":8200,"tlsName":"vault.test"}`); r.Code != 200 {
		t.Fatal("profile setup failed", r.Code)
	}
	if err := database.Exec("DELETE FROM role_permissions WHERE role_id='admin' AND permission_key='roles.manage'").Error; err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"policies", "policy"} {
		if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/access/"+action, `{"token":"fixture","name":"example"}`); r.Code != 403 {
			t.Fatal("policy source reachable without role authority", r.Code)
		}
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/access/auth", `{"token":"fixture"}`); r.Code != 502 {
		t.Fatal("metadata read incorrectly requires role authority", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/prod/vault/access/auth", `{"token":"fixture"}`); r.Code != 404 {
		t.Fatal("cross-server access revealed", r.Code)
	}
}
