package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/githubrunner"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestMarketplaceRunnerRequiresDedicatedFlowAndScopedAuthority(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	grant := func(role string) {
		t.Helper()
		if err := database.Create(&authorization.Grant{ID: "runner-http-" + role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	grant("host-control")
	path := "/api/servers/dev/operations/github/runner/start"
	setup := githubrunner.Setup{Profile: githubrunner.Profile{URL: "https://github.com/example/repository", Name: "fixture", Labels: []string{"trusted"}, LifetimeSeconds: 900}, RequestID: strings.Repeat("a", 32), RegistrationToken: strings.Repeat("T", 26)}
	data, _ := json.Marshal(setup)
	if r := policyRequest(router, cookie, "POST", path, string(data)); r.Code != 403 {
		t.Fatal("runner manage grant ignored", r.Code)
	}
	grant("github-runners")
	if r := policyRequest(router, cookie, "POST", path, string(data)); r.Code != 409 || strings.Contains(r.Body.String(), setup.RegistrationToken) {
		t.Fatal("disabled supervision admitted or reflected token", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/apps/deploy", `{"templateId":"github-runner","appName":"build","variables":{"TOKEN":"`+setup.RegistrationToken+`"}}`); r.Code != 400 {
		t.Fatal("runner token accepted by generic app deployment", r.Code, r.Body.String())
	}
	row := models.SupervisedRun{ID: setup.RequestID, Kind: "operation", Action: "github-runner", ServerID: "dev", ActorID: actor, State: "exited", TaskID: "", CommandHash: strings.Repeat("b", 64), CreatedAt: time.Now().UTC(), OperationContext: setup.PublicJSON()}
	if err := database.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	r := policyRequest(router, cookie, "GET", "/api/servers/dev/github/runners", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), setup.URL) || strings.Contains(r.Body.String(), setup.RegistrationToken) || strings.Contains(r.Body.String(), "operationContext") {
		t.Fatal("runner metadata missing or private data exposed", r.Code, r.Body.String())
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/prod/github/runners", ""); r.Code != 404 {
		t.Fatal("runner scope escaped", r.Code)
	}
	if err := database.Where("id='runner-http-github-runners'").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/dev/github/runners", ""); r.Code != 403 {
		t.Fatal("removed runner grant retained", r.Code)
	}
}
