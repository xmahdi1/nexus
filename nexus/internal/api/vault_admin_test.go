package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/vault"
)

func TestVaultAdminManifestScopesAndSensitiveAuthority(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), VaultEnabled: true}, nil, nil)
	manifest := func() map[string]bool {
		t.Helper()
		r := policyRequest(router, cookie, "GET", "/api/servers/dev/vault/admin/operations", "")
		if r.Code != 200 || r.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("manifest unavailable", r.Code)
		}
		var body struct {
			Operations []vault.AdminOperation `json:"operations"`
		}
		if json.Unmarshal(r.Body.Bytes(), &body) != nil {
			t.Fatal("invalid operation manifest")
		}
		seen := map[string]bool{}
		for _, op := range body.Operations {
			seen[op.ID] = true
		}
		return seen
	}
	seen := manifest()
	if seen["token-create"] || seen["pki-issue"] || seen["kv-version"] || seen["approle-secret-id"] {
		t.Fatal("admin implicitly granted credential reveal")
	}
	if !seen["policy-save"] || !seen["audit-enable"] || !seen["kv-destroy"] {
		t.Fatal("allowed admin actions missing")
	}
	for _, op := range vault.AdminOperations() {
		policy, _, ok := authorization.Resolve("POST", "/api/servers/dev/vault/admin/"+op.ID)
		if !ok || authorization.Risk(policy) != "high" {
			t.Fatal("unprotected admin route", op.ID)
		}
		for _, permission := range op.Permissions {
			if !authorization.Known(permission) {
				t.Fatal("unknown admin permission", op.ID, permission)
			}
		}
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/prod/vault/admin/operations", ""); r.Code != 404 {
		t.Fatal("cross-server manifest accessible", r.Code)
	}
	for _, id := range []string{"token-create", "pki-issue", "kv-version", "approle-secret-id"} {
		if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/"+id, `{}`); r.Code != 403 {
			t.Fatal("sensitive route not guarded", id, r.Code)
		}
	}
	if err := database.Create(&authorization.Grant{ID: "admin-reveal", PrincipalID: actor, PrincipalKind: "user", RoleID: "secret-reader", ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if !manifest()["token-create"] {
		t.Fatal("explicit reveal authority ignored")
	}
	if err := database.Exec("DELETE FROM role_permissions WHERE role_id='admin' AND permission_key='roles.manage'").Error; err != nil {
		t.Fatal(err)
	}
	seen = manifest()
	if seen["policy-save"] || seen["token-create"] || seen["approle-secret-id"] {
		t.Fatal("removed role authority remained available")
	}
	if !seen["pki-issue"] {
		t.Fatal("leaf issuance incorrectly requires policy authority")
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/policy-save", `{}`); r.Code != 403 {
		t.Fatal("policy mutation bypassed role authority", r.Code)
	}
}

func TestVaultAdminStrictBodiesAndFeatureGate(t *testing.T) {
	database, disabled, cookie, _ := rbacFixture(t, "admin", "server", "dev")
	if r := policyRequest(disabled, cookie, "GET", "/api/servers/dev/vault/admin/operations", ""); r.Code != 409 {
		t.Fatal("disabled feature exposed manifest", r.Code)
	}
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), VaultEnabled: true}, nil, nil)
	for _, body := range []string{
		`{"token":"fixture","params":{"name":"application"},"url":"https://other"}`,
		`{"token":"fixture","params":{"name":"application"}} {}`,
		`{"token":"fixture","params":{"name":"../root"}}`,
		`{"token":"fixture","params":{"name":"application","extra":"secret"}}`,
		`{"token":"fixture","params":{"name":"` + strings.Repeat("a", 129) + `"}}`,
	} {
		if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/policy-read", body); r.Code != 400 {
			t.Fatal("invalid management body accepted", r.Code)
		}
	}
}
