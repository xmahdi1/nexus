package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
)

func TestOperationAuditAttributionPaginationRedactionAndFailClosed(t *testing.T) {
	database, router, cookie, actor := rbacFixture(t, "admin", "global", "")
	for i := 0; i < 3; i++ {
		response := policyRequest(router, cookie, "PATCH", "/api/servers/dev/tags?private=NEVER-AUDIT-QUERY", `{"tags":"NEVER-AUDIT-BODY"}`)
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	var rows []audit.Event
	if err := database.Where("action=? AND source='http'", "PATCH /api/servers/{id}/tags").Order("id").Find(&rows).Error; err != nil || len(rows) != 6 {
		t.Fatal("missing lifecycle rows", len(rows), err)
	}
	for i := 0; i < len(rows); i += 2 {
		if rows[i].ActorID != actor || rows[i].SessionID == "" || rows[i].Outcome != "started" || rows[i+1].Outcome != "response_succeeded" || rows[i].OperationID != rows[i+1].OperationID || rows[i].ServerID != "dev" {
			t.Fatal("bad attribution", rows[i], rows[i+1])
		}
	}
	serialized, _ := json.Marshal(rows)
	if strings.Contains(string(serialized), "NEVER-AUDIT") {
		t.Fatal("audit captured secret")
	}
	first := policyRequest(router, cookie, "GET", "/api/audit/events?limit=2&action=PATCH%20%2Fapi%2Fservers%2F%7Bid%7D%2Ftags", "")
	var page audit.Page
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil || len(page.Items) != 2 || page.Next == "" {
		t.Fatal("pagination", first.Body.String())
	}
	second := policyRequest(router, cookie, "GET", "/api/audit/events?limit=2&before="+page.Next+"&action=PATCH%20%2Fapi%2Fservers%2F%7Bid%7D%2Ftags", "")
	var older audit.Page
	json.Unmarshal(second.Body.Bytes(), &older)
	if len(older.Items) != 2 || older.Items[0].ID >= page.Items[1].ID {
		t.Fatal("cursor duplicates")
	}
	for _, query := range []string{"limit=1000000", "before=bad", "limit=-1"} {
		if response := policyRequest(router, cookie, "GET", "/api/audit/events?"+query, ""); response.Code != 400 {
			t.Fatal("unbounded reader", response.Code)
		}
	}
	exported := policyRequest(router, cookie, "GET", "/api/audit/events?format=jsonl&limit=2", "")
	if exported.Code != 200 || !strings.Contains(exported.Header().Get("Content-Type"), "ndjson") {
		t.Fatal("export failed")
	}
	if err := database.Exec("UPDATE operation_events SET actor_id='attacker'").Error; err == nil {
		t.Fatal("audit rows mutable")
	}
	if err := database.Exec(`CREATE TRIGGER fail_intent BEFORE INSERT ON operation_events WHEN NEW.outcome='started' BEGIN SELECT RAISE(ABORT,'fixture'); END`).Error; err != nil {
		t.Fatal(err)
	}
	response := policyRequest(router, cookie, "PATCH", "/api/servers/dev/tags", `{"tags":"must-not-apply"}`)
	if response.Code != 503 {
		t.Fatal("audit outage did not block side effect", response.Code)
	}
	var tags string
	database.Table("servers").Where("id='dev'").Pluck("tags", &tags)
	if tags == "must-not-apply" {
		t.Fatal("side effect despite audit failure")
	}
}

func TestAuditDeniesViewerAndRecordsFailuresAndPanic(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "viewer", "server", "dev")
	if response := policyRequest(router, cookie, "GET", "/api/audit/events", ""); response.Code != 403 {
		t.Fatal("viewer read audit")
	}
	var denied int64
	database.Table("operation_events").Where("outcome='denied'").Count(&denied)
	if denied == 0 {
		t.Fatal("denial not audited")
	}
	// Add an explicit self fixture route: no transport and no new policy gap.
	authorization.Policies = append(authorization.Policies, authorization.Policy{Method: "POST", Path: "/api/fixture/panic", Self: true})
	t.Cleanup(func() { authorization.Policies = authorization.Policies[:len(authorization.Policies)-1] })
	router.(chi.Router).Post("/api/fixture/panic", func(http.ResponseWriter, *http.Request) { panic("fixture panic") })
	response := policyRequest(router, cookie, "POST", "/api/fixture/panic", `{}`)
	if response.Code != 500 {
		t.Fatal("panic did not recover", response.Code)
	}
	var events []audit.Event
	database.Where("action=?", "POST /api/fixture/panic").Find(&events)
	if len(events) != 2 || events[1].Outcome != "interrupted" {
		t.Fatal(fmt.Sprint(events))
	}
}

func TestFailedAuditCompletionLeavesUnpairedIntentWithoutReplayingMutation(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	if err := database.Exec(`CREATE TRIGGER fail_result BEFORE INSERT ON operation_events WHEN NEW.outcome='response_succeeded' BEGIN SELECT RAISE(ABORT,'fixture'); END`).Error; err != nil {
		t.Fatal(err)
	}
	response := policyRequest(router, cookie, "PATCH", "/api/servers/dev/tags", `{"tags":"completed-once"}`)
	if response.Code != 200 {
		t.Fatal("rewrote completed response", response.Code)
	}
	var events []audit.Event
	database.Where("operation_id=?", response.Header().Get("X-Operation-ID")).Find(&events)
	if len(events) != 1 || events[0].Outcome != "started" {
		t.Fatal("completion failure falsely reported success", events)
	}
	var tags string
	database.Table("servers").Where("id='dev'").Pluck("tags", &tags)
	if tags != "completed-once" {
		t.Fatal("operation unexpectedly undone")
	}
}

func TestCreatedResourceIdentityIsRecordedWithoutRequestContents(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	response := policyRequest(router, cookie, "POST", "/api/services", `{"name":"NEVER-AUDIT-SERVICE-NAME","url":"https://example.test/private-value"}`)
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	var created struct{ ID string }
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	var result audit.Event
	if err := database.Where("operation_id=? AND outcome='response_succeeded'", response.Header().Get("X-Operation-ID")).First(&result).Error; err != nil {
		t.Fatal(err)
	}
	if result.ResourceID != created.ID || result.ResourceType != "service" {
		t.Fatal("missing created resource identity", result)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "NEVER-AUDIT") || strings.Contains(string(raw), "private-value") {
		t.Fatal("captured request contents")
	}
}

func TestOperationalLogsExcludeRawQueryAndRequestContents(t *testing.T) {
	_, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	previous := log.Writer()
	var captured bytes.Buffer
	log.SetOutput(&captured)
	defer log.SetOutput(previous)
	response := policyRequest(router, cookie, "PATCH", "/api/servers/dev/tags?token=NEVER-LOG-QUERY", `{"tags":"NEVER-LOG-BODY"}`)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	if strings.Contains(captured.String(), "NEVER-LOG") || !strings.Contains(captured.String(), "route=/api/servers/{id}/tags") {
		t.Fatal("unsafe operational log", captured.String())
	}
	authorization.Policies = append(authorization.Policies, authorization.Policy{Method: "POST", Path: "/api/fixture/panic-log", Self: true})
	t.Cleanup(func() { authorization.Policies = authorization.Policies[:len(authorization.Policies)-1] })
	router.(chi.Router).Post("/api/fixture/panic-log", func(http.ResponseWriter, *http.Request) { panic("NEVER-LOG-PANIC-VALUE") })
	response = policyRequest(router, cookie, "POST", "/api/fixture/panic-log", `{}`)
	if response.Code != 500 || strings.Contains(captured.String(), "NEVER-LOG") {
		t.Fatal("panic value leaked or invalid recovery")
	}

}

func TestStorageMutationFailuresAreNotReportedAsSuccessful(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	created := policyRequest(router, cookie, "POST", "/api/services", `{"name":"fixture","url":"https://example.test"}`)
	var service struct{ ID string }
	json.Unmarshal(created.Body.Bytes(), &service)
	if service.ID == "" {
		t.Fatal("fixture create failed")
	}
	if err := database.Exec(`CREATE TRIGGER fail_service_delete BEFORE DELETE ON services BEGIN SELECT RAISE(ABORT,'fixture'); END;CREATE TRIGGER fail_monitor_update BEFORE UPDATE ON alert_configs BEGIN SELECT RAISE(ABORT,'fixture'); END;`).Error; err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path, body string }{
		{"DELETE", "/api/services/" + service.ID, ""},
		{"PUT", "/api/monitor/config", `{"telegramEnabled":false}`},
	} {
		response := policyRequest(router, cookie, test.method, test.path, test.body)
		if response.Code != 503 {
			t.Fatalf("failed mutation falsely succeeded: %s %d %s", test.path, response.Code, response.Body.String())
		}
		var event audit.Event
		if err := database.Where("operation_id=? AND outcome='response_failed'", response.Header().Get("X-Operation-ID")).First(&event).Error; err != nil {
			t.Fatal("failure not audited", err)
		}
	}
}

func TestUncertainOperationInspectionIsReadOnlyAndDoesNotAuthorizeRetry(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	authorization.Policies = append(authorization.Policies, authorization.Policy{Method: "POST", Path: "/api/fixture/uncertain", Self: true})
	t.Cleanup(func() { authorization.Policies = authorization.Policies[:len(authorization.Policies)-1] })
	calls := 0
	router.(chi.Router).Post("/api/fixture/uncertain", func(w http.ResponseWriter, r *http.Request) {
		calls++
		audit.MarkRemoteUnknown(r.Context())
		http.Error(w, "fixture interrupted result", http.StatusBadGateway)
	})
	response := policyRequest(router, cookie, "POST", "/api/fixture/uncertain", `{}`)
	id := response.Header().Get("X-Operation-ID")
	inspected := policyRequest(router, cookie, "GET", "/api/audit/operations/"+id, "")
	var operation audit.Operation
	if inspected.Code != 200 || json.Unmarshal(inspected.Body.Bytes(), &operation) != nil || operation.State != "remote_unknown" || operation.RemoteStateVerified || operation.AutomaticRetryAllowed || operation.CompletedAt == nil {
		t.Fatal("uncertain result misrepresented", inspected.Body.String())
	}
	if calls != 1 {
		t.Fatal("inspection replayed mutation")
	}
	var event audit.Event
	if err := database.Where("operation_id=? AND outcome='started'", id).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	event.OperationID = "pending-fixture"
	event.ID = 0
	if err := audit.Append(database, event); err != nil {
		t.Fatal(err)
	}
	pending := policyRequest(router, cookie, "GET", "/api/audit/operations/pending-fixture", "")
	if err := json.Unmarshal(pending.Body.Bytes(), &operation); err != nil || operation.State != "pending" || operation.CompletedAt != nil || operation.AutomaticRetryAllowed {
		t.Fatal("unpaired intent claimed completion", pending.Body.String())
	}
	if response := policyRequest(router, cookie, "GET", "/api/audit/operations/missing-fixture", ""); response.Code != 404 {
		t.Fatal("unknown operation not concealed")
	}
}
func TestOperationInspectionRequiresAuditPermission(t *testing.T) {
	_, router, cookie, _ := rbacFixture(t, "viewer", "server", "dev")
	if response := policyRequest(router, cookie, "GET", "/api/audit/operations/known-fixture", ""); response.Code != 403 {
		t.Fatal("viewer inspected global audit", response.Code)
	}
}

func TestProxyTLSAndImplementationChangesAreGuardedBeforeRemoteAccess(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	if err := database.Exec(`INSERT INTO proxy_rules(id,server_id,domain,target,proxy_type,ssl_enabled)VALUES('route','dev','example.test','127.0.0.1:80','nginx',1)`).Error; err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"proxyType":"caddy","domain":"example.test","target":"127.0.0.1:81","ssl":true}`,
		`{"proxyType":"nginx","domain":"changed.example.test","target":"127.0.0.1:81","ssl":true}`,
		`{"proxyType":"nginx","domain":"example.test","target":"127.0.0.1:81","ssl":false}`,
	} {
		response := policyRequest(router, cookie, "PUT", "/api/servers/dev/proxy/route", body)
		if response.Code != 409 {
			t.Fatal("destructive TLS/adapter replacement reached remote access", response.Code, response.Body.String())
		}
	}
	var target string
	database.Table("proxy_rules").Where("id='route'").Pluck("target", &target)
	if target != "127.0.0.1:80" {
		t.Fatal("guarded request changed stored route")
	}
}

func TestCertificateRenewalGuardsBeforeRemoteAccess(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	if err := database.Exec(`INSERT INTO proxy_rules(id,server_id,domain,target,proxy_type,ssl_enabled)VALUES('route','dev','example.test','127.0.0.1:80','nginx',0),('caddy','dev','caddy.example.test','127.0.0.1:80','caddy',1)`).Error; err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ rule, body string }{{"route", `{"renew":true}`}, {"route", `{"renew":`}, {"caddy", `{"wildcard":true,"cfToken":"fixture"}`}} {
		response := policyRequest(router, cookie, "POST", "/api/servers/dev/proxy/"+test.rule+"/ssl", test.body)
		if response.Code != 400 {
			t.Fatal("invalid renewal reached remote access", response.Code, response.Body.String())
		}
	}
}
