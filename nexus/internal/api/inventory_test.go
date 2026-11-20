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
	var count int64
	database.Model(&inventory.Run{}).Count(&count)
	if count != 0 {
		t.Fatal("GET triggered discovery")
	}
}
