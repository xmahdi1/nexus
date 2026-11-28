package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/inventory"
)

func TestInventoryPolicyScopeValidationRevisionAndNoImplicitScan(t *testing.T) {
	database, disabled, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	enabled := NewRouter(database, &config.Config{InventoryEnabled: true}, nil, nil)
	const path = "/api/servers/dev/inventory/policy"
	const input = `{"enabled":true,"intervalMinutes":5,"freshnessMinutes":60,"retentionDays":0,"revision":0}`
	if response := policyRequest(disabled, cookie, "PUT", path, input); response.Code != 404 {
		t.Fatal(response.Code, response.Body.String())
	}
	for _, method := range []string{"GET", "PUT"} {
		if response := policyRequest(enabled, cookie, method, "/api/servers/prod/inventory/policy", input); response.Code != 404 {
			t.Fatal("scope", response.Code)
		}
	}
	response := policyRequest(enabled, cookie, "GET", path, "")
	var initial inventory.Policy
	if err := json.Unmarshal(response.Body.Bytes(), &initial); err != nil || response.Code != 200 || initial.Enabled || initial.Revision != 0 || initial.RetentionDays != 0 {
		t.Fatal(response.Code, initial, err)
	}
	for _, body := range []string{`{}`, strings.Replace(input, `"intervalMinutes":5`, `"intervalMinutes":1`, 1), strings.Replace(input, `"retentionDays":0`, `"retentionDays":3651`, 1), strings.Replace(input, `"freshnessMinutes":60`, `"freshnessMinutes":10081`, 1), strings.Replace(input, `"revision":0`, `"actorId":"other","revision":0`, 1), input + `{}`} {
		if response := policyRequest(enabled, cookie, "PUT", path, body); response.Code != 400 {
			t.Fatal("invalid accepted", body, response.Code, response.Body.String())
		}
	}
	response = policyRequest(enabled, cookie, "PUT", path, input)
	var saved inventory.Policy
	if err := json.Unmarshal(response.Body.Bytes(), &saved); err != nil || response.Code != 200 || saved.Revision != 1 || saved.ActorID != actor || time.Until(saved.NextRunAt) < 4*time.Minute {
		t.Fatal(response.Code, response.Body.String(), err)
	}
	if response := policyRequest(enabled, cookie, "PUT", path, input); response.Code != 409 {
		t.Fatal("stale revision", response.Code, response.Body.String())
	}
	if err := database.Exec("INSERT INTO server_groups(id,name,require_mfa,created_at)VALUES('protected','Protected',1,CURRENT_TIMESTAMP)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO server_group_members(group_id,server_id)VALUES('protected','dev')").Error; err != nil {
		t.Fatal(err)
	}
	if response := policyRequest(enabled, cookie, "PUT", path, strings.Replace(input, `"revision":0`, `"revision":1`, 1)); response.Code != 422 {
		t.Fatal("protected schedule enabled", response.Code, response.Body.String())
	}
	var count int64
	database.Model(&inventory.Run{}).Count(&count)
	if count != 0 {
		t.Fatal("save or GET opened collector")
	}
	// A stale tab cannot change the policy after its actor grant is revoked.
	if err := database.Exec("UPDATE role_grants SET role_id='viewer' WHERE principal_id=?", actor).Error; err != nil {
		t.Fatal(err)
	}
	if response := policyRequest(enabled, cookie, "PUT", path, strings.Replace(input, `"revision":0`, `"revision":1`, 1)); response.Code != 403 {
		t.Fatal("revoked policy save", response.Code)
	}
	if response := policyRequest(enabled, cookie, "GET", path, ""); response.Code != 200 {
		t.Fatal("reader cannot inspect settings", response.Code)
	}
}

func TestInventoryFeatureFlagScopeAndNoImplicitRemoteCollection(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "viewer", "server", "dev")
	if response := policyRequest(router, cookie, "GET", "/api/servers/dev/inventory", ""); response.Code != 404 {
		t.Fatal("preview enabled by default", response.Code)
	}
	enabled := NewRouter(database, &config.Config{InventoryEnabled: true}, nil, nil)
	if response := policyRequest(enabled, cookie, "GET", "/api/servers/dev/inventory", ""); response.Code != 200 {
		t.Fatal("scoped reader failed", response.Code, response.Body.String())
	}
	if response := policyRequest(enabled, cookie, "GET", "/api/servers/prod/inventory", ""); response.Code != 404 {
		t.Fatal("cross-scope inventory readable")
	}
	if response := policyRequest(enabled, cookie, "POST", "/api/servers/dev/inventory/discover", `{}`); response.Code != 403 {
		t.Fatal("Viewer collected remotely")
	}
	for _, method := range []string{"GET", "PUT"} {
		if response := policyRequest(enabled, cookie, method, "/api/servers/dev/inventory/documentation", ""); response.Code != 403 {
			t.Fatal("viewer accessed documentation without its specific permission", method, response.Code)
		}
	}
	if response := policyRequest(enabled, cookie, "GET", "/api/servers/dev/inventory?limit=10000", ""); response.Code != 400 {
		t.Fatal("unbounded page")
	}
	for _, path := range []string{"history", "relationships"} {
		if response := policyRequest(router, cookie, "GET", "/api/servers/dev/inventory/"+path, ""); response.Code != 404 {
			t.Fatal("feature flag bypass", path, response.Code)
		}
		if response := policyRequest(enabled, cookie, "GET", "/api/servers/dev/inventory/"+path, ""); response.Code != 200 {
			t.Fatal("reader denied", path, response.Code, response.Body.String())
		}
		if response := policyRequest(enabled, cookie, "GET", "/api/servers/prod/inventory/"+path, ""); response.Code != 404 {
			t.Fatal("cross-server data", path, response.Code)
		}
		if response := policyRequest(enabled, cookie, "GET", "/api/servers/dev/inventory/"+path+"?limit=10000", ""); response.Code != 400 {
			t.Fatal("unbounded page", path, response.Code)
		}
	}
	if response := policyRequest(enabled, cookie, "GET", "/api/servers/dev/inventory?after=bad", ""); response.Code != 400 {
		t.Fatal("invalid resource cursor accepted", response.Code)
	}
	for _, query := range []string{"history?before=-1", "history?resourceId=bad", "relationships?after=bad"} {
		if response := policyRequest(enabled, cookie, "GET", "/api/servers/dev/inventory/"+query, ""); response.Code != 400 {
			t.Fatal("invalid cursor accepted", query, response.Code)
		}
	}
	var count int64
	database.Model(&inventory.Run{}).Count(&count)
	if count != 0 {
		t.Fatal("GET triggered discovery")
	}
}

func TestInventoryDocumentationScopeRevisionAndSafeRegeneration(t *testing.T) {
	database, disabled, cookie, _ := rbacFixture(t, "admin", "server", "dev")
	enabled := NewRouter(database, &config.Config{InventoryEnabled: true}, nil, nil)
	const path = "/api/servers/dev/inventory/documentation"
	if response := policyRequest(disabled, cookie, "GET", path, ""); response.Code != 404 {
		t.Fatal("feature flag bypass", response.Code)
	}
	if response := policyRequest(enabled, cookie, "GET", "/api/servers/prod/inventory/documentation", ""); response.Code != 404 {
		t.Fatal("cross-server report disclosure", response.Code)
	}
	if response := policyRequest(enabled, cookie, "PUT", "/api/servers/prod/inventory/documentation", `{"notes":"other","revision":0}`); response.Code != 404 {
		t.Fatal("cross-server notes update", response.Code)
	}
	if response := policyRequest(enabled, cookie, "PUT", path, `{"revision":0}`); response.Code != 400 {
		t.Fatal("missing notes accepted", response.Code)
	}
	if err := database.Exec("UPDATE servers SET name=?, username=? WHERE id='dev'", "host\n![image](https://example.invalid/img)", "private-ssh-user").Error; err != nil {
		t.Fatal(err)
	}
	response := policyRequest(enabled, cookie, "PUT", path, `{"notes":"Restart after the maintenance window.","revision":0}`)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	if response := policyRequest(enabled, cookie, "PUT", path, `{"notes":"Stale tab overwrite","revision":0}`); response.Code != 409 {
		t.Fatal("stale edit accepted", response.Code)
	}
	read := func() inventory.Document {
		t.Helper()
		var report inventory.Document
		response := policyRequest(enabled, cookie, "GET", path, "")
		err := json.Unmarshal(response.Body.Bytes(), &report)
		if response.Code != 200 || err != nil {
			t.Fatal(response.Code, err, response.Body.String())
		}
		if report.Notes.Revision != 1 || report.Notes.Notes != "Restart after the maintenance window." ||
			!strings.Contains(report.Markdown, report.Notes.Notes) ||
			strings.Contains(report.Markdown, "![image]") ||
			strings.Contains(response.Body.String(), "private-ssh-user") {
			t.Fatal("wrong documentation content", report)
		}
		return report
	}
	before := read()
	if after := read(); after.Markdown != before.Markdown {
		t.Fatal("unchanged inputs generated different Markdown")
	}
	if err := database.Exec(`INSERT INTO inventory_resources(id,server_id,kind,natural_key,display_name,source,fingerprint,first_seen_at,last_seen_at,last_verified_at,data_state)
		VALUES('discovered-host','dev','host','registered-host','test-host','ssh','fingerprint',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fresh')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec(`INSERT INTO inventory_hosts(resource_id,hostname,os,kernel) VALUES('discovered-host','test-host','Linux','test-kernel')`).Error; err != nil {
		t.Fatal(err)
	}
	if after := read(); !strings.Contains(after.Markdown, "kernel test-kernel") || after.Markdown == before.Markdown || len(after.Resources) != 1 {
		t.Fatal("regenerated report missing observations", after)
	}
}
