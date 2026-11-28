package api

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestAnsibleExecutionHTTPRequiresExplicitRoleAndHidesPrivateContext(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true, OperationSupervisionEnabled: true}, nil, nil)
	base := "/api/servers/dev/ansible"
	if r := policyRequest(router, cookie, "POST", base+"/plans/fixture/run", `{"requestId":"`+strings.Repeat("a", 32)+`","vaultTokens":{}}`); r.Code != 403 {
		t.Fatal("implicit executor access", r.Code)
	}
	grant := func(role string) {
		t.Helper()
		if err := database.Create(&authorization.Grant{ID: "ansible-run-http-" + role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	grant("ansible-executor")
	if r := policyRequest(router, cookie, "POST", base+"/plans/fixture/run", `{"requestId":"fixture-token-in-wrong-field","vaultTokens":{}}`); r.Code != 400 {
		t.Fatal("invalid request ID accepted", r.Code)
	}
	var leaked int64
	if err := database.Table("operation_events").Where("resource_id=?", "fixture-token-in-wrong-field").Count(&leaked).Error; err != nil || leaked != 0 {
		t.Fatal("invalid identifier entered audit metadata", err)
	}
	if r := policyRequest(router, cookie, "POST", base+"/plans/fixture/run", `{"requestId":"`+strings.Repeat("a", 32)+`","vaultTokens":{},"command":"forbidden"}`); r.Code != 400 {
		t.Fatal("caller command accepted", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", base+"/plans/fixture/run", `{"requestId":"`+strings.Repeat("a", 32)+`","vaultTokens":{"dev":"fixture-token"}}`); r.Code != 403 || strings.Contains(r.Body.String(), "fixture-token") {
		t.Fatal("missing approval ignored or token reflected", r.Code)
	}
	run := models.SupervisedRun{ID: strings.Repeat("b", 32), Kind: "ansible", Action: "ansible-playbook", ServerID: "dev", ActorID: actor, SourceSessionID: "private-session", CommandHash: strings.Repeat("c", 64), OperationContext: "private-plan-binding", State: "prepared", CreatedAt: time.Now().UTC()}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	r := policyRequest(router, cookie, "GET", base+"/runs", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), run.ID) || strings.Contains(r.Body.String(), "private-session") || strings.Contains(r.Body.String(), "operationContext") || !strings.Contains(r.Body.String(), `"planId":"private-plan-binding"`) {
		t.Fatal("run metadata leaked private context", r.Code, r.Body.String())
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/prod/ansible/runs", ""); r.Code != 404 {
		t.Fatal("run scope escaped", r.Code)
	}
}
