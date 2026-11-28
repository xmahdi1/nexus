package api

import (
	"bytes"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/githubactions"
	"strings"
	"testing"
	"time"
)

func TestGitHubConnectionsRequireExplicitScopesAndNeverRevealCredentials(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	base := "/api/servers/dev/github"
	if r := policyRequest(router, cookie, "GET", base+"/connections", ""); r.Code != 403 {
		t.Fatal("implicit connection read", r.Code)
	}
	grant := func(role string) {
		t.Helper()
		if err := database.Create(&authorization.Grant{ID: "github-http-" + role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	grant("github-actions-reader")
	row := githubactions.Connection{ID: strings.Repeat("a", 32), ServerID: "dev", Owner: "fixture", Name: "repository", RepositoryID: 123, ClientID: "Iv1.fixture", InstallationID: 42, ConfigEnc: "private-fixture-ciphertext", CreatedBy: actor, CreatedAt: time.Now().UTC()}
	if err := database.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	r := policyRequest(router, cookie, "GET", base+"/connections", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "repository") || strings.Contains(r.Body.String(), "private-fixture") || strings.Contains(r.Body.String(), "configEnc") {
		t.Fatal("connection metadata unsafe", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/prod/github/connections", ""); r.Code != 404 {
		t.Fatal("scope bypass", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", base+"/connections/"+row.ID+"/dispatch", `{"requestId":"`+strings.Repeat("b", 32)+`","workflowId":7,"ref":"main","inputs":{}}`); r.Code != 403 {
		t.Fatal("implicit workflow dispatch", r.Code)
	}
	grant("github-actions-dispatcher")
	if r := policyRequest(router, cookie, "POST", base+"/connections/"+row.ID+"/dispatch", `{"requestId":"private-value-not-an-id","workflowId":7,"ref":"main","inputs":{}}`); r.Code != 400 {
		t.Fatal("invalid request identity accepted", r.Code)
	}
	var count int64
	database.Table("operation_events").Where("resource_id=?", "private-value-not-an-id").Count(&count)
	if count != 0 {
		t.Fatal("invalid ID leaked into audit")
	}
	grant("github-connections")
	if r := policyRequest(router, cookie, "POST", base+"/connections", `{"owner":"fixture","name":"repository","repositoryId":123,"clientId":"Iv1.fixture","installationId":42,"privateKey":"not-a-private-key","apiUrl":"http://127.0.0.1"}`); r.Code != 400 || strings.Contains(r.Body.String(), "not-a-private-key") {
		t.Fatal("arbitrary provider URL accepted or secret reflected", r.Code)
	}
}

func TestGitHubSensitiveRunRoutesRequireSeparateRoles(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	for _, role := range []string{"github-actions-reader", "github-actions-dispatcher"} {
		if err := database.Create(&authorization.Grant{ID: role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/servers/dev/github/connections/" + strings.Repeat("a", 32) + "/runs/99"
	for _, suffix := range []string{"/cancel", "/jobs/101/logs", "/artifacts/5/download"} {
		result := policyRequest(router, cookie, "POST", base+suffix, `{}`)
		if result.Code != 403 {
			t.Fatal("separate run permission bypassed", suffix, result.Code)
		}
	}
}

func TestGitHubRepositoryChangesNeedNewRoles(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	for _, role := range []string{"github-actions-reader", "github-actions-dispatcher", "github-runners"} {
		if err := database.Create(&authorization.Grant{ID: role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/servers/dev/github/connections/" + strings.Repeat("a", 32)
	for _, suffix := range []string{"/provider-runners", "/provider-runners/remove", "/workflow-file", "/workflow-change"} {
		r := policyRequest(router, cookie, "POST", base+suffix, `{}`)
		if r.Code != 403 {
			t.Fatal("repository role bypassed", suffix, r.Code)
		}
	}
	grant := authorization.Grant{ID: "workflow-editor", PrincipalID: actor, PrincipalKind: "user", RoleID: "github-workflow-editor", ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}
	if err := database.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	r := policyRequest(router, cookie, "POST", base+"/workflow-change", `{"requestId":"private-not-an-id","content":"private fixture content"}`)
	if r.Code != 400 || strings.Contains(r.Body.String(), "private fixture") {
		t.Fatal("malformed repository request accepted/reflected", r.Code)
	}
	var count int64
	database.Table("operation_events").Where("resource_id=?", "private-not-an-id").Count(&count)
	if count != 0 {
		t.Fatal("malformed request entered audit")
	}
}
