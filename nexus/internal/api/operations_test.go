package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestInteractiveOperationFeatureScopeIdentityAndOutputGrants(t *testing.T) {
	database, disabled, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	for _, role := range []string{"host-control", "log-reader"} {
		if err := database.Create(&authorization.Grant{ID: "operation-" + role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	body := `{"requestId":"` + id + `","path":"/opt/fixture/compose.yml"}`
	path := "/api/servers/dev/operations/compose/up"
	if r := policyRequest(disabled, cookie, "POST", path, body); r.Code != 409 {
		t.Fatal("disabled supervisor admitted operation", r.Code)
	}
	key := bytes.Repeat([]byte{9}, 32)
	router := NewRouter(database, &config.Config{EncryptionKey: key, OperationSupervisionEnabled: true}, nil, nil)
	if r := policyRequest(router, cookie, "POST", "/api/servers/prod/operations/compose/up", body); r.Code != 404 {
		t.Fatal("cross-server operation admitted", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", path, `{"requestId":"`+id+`","path":"/opt/x","command":"reboot"}`); r.Code != 400 {
		t.Fatal("arbitrary command accepted", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", path, body); r.Code != 502 || !strings.Contains(r.Body.String(), id) {
		t.Fatal("unavailable submission lost its identity", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", path, body); r.Code != 202 {
		t.Fatal("identical request did not return its existing run", r.Code)
	}
	var count int64
	if err := database.Model(&models.SupervisedRun{}).Where("id=?", id).Count(&count).Error; err != nil || count != 1 {
		t.Fatal("duplicate request created extra runs", count, err)
	}
	for _, legacy := range []string{"/api/servers/dev/compose/up?path=/opt/fixture.yml", "/api/servers/dev/containers/abcdef123456/start"} {
		if r := policyRequest(router, cookie, "POST", legacy, "{}"); r.Code != 409 {
			t.Fatal("legacy mutation bypassed enabled supervision", legacy, r.Code)
		}
	}
	var run models.SupervisedRun
	database.First(&run, "id=?", id)
	code := 0
	if err := jobsupervisor.NewService(database, key, nil).Save(run, jobsupervisor.Snapshot{State: "exited", Verified: true, Empty: true, ExitCode: &code, Output: "private operation result", InvocationID: strings.Repeat("b", 32)}); err != nil {
		t.Fatal(err)
	}
	base := "/api/servers/dev/operations/runs/" + id
	if r := policyRequest(router, cookie, "GET", base, ""); r.Code != 200 || !strings.Contains(r.Body.String(), "private operation result") || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authorized result unavailable", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/dev/operations/runs", ""); r.Code != 200 || strings.Contains(r.Body.String(), "private operation result") || strings.Contains(r.Body.String(), "outputEnc") {
		t.Fatal("metadata list leaked output", r.Code)
	}
	if err := database.Where("id='operation-log-reader'").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if r := policyRequest(router, cookie, "POST", base+"/cancel", "{}"); r.Code != 200 || strings.Contains(r.Body.String(), "private operation result") {
		t.Fatal("cancellation granted output access", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", base, ""); r.Code != 403 {
		t.Fatal("removed log grant ignored", r.Code)
	}
	var events []audit.Event
	database.Find(&events)
	encoded, _ := json.Marshal(events)
	if bytes.Contains(encoded, []byte("private operation result")) || bytes.Contains(encoded, []byte("/opt/fixture/compose.yml")) {
		t.Fatal("operation details leaked into audit")
	}
}
