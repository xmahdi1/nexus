package api

import (
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/inventory"
	"testing"
)

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
