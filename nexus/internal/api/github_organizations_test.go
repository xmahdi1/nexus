package api

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/githubactions"
)

func TestOrganizationRolesDoNotGrantRepositoryActionsOrSecretReveal(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "viewer", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	id := strings.Repeat("a", 32)
	row := githubactions.OrganizationConnection{ID: id, ServerID: "dev", Login: "fixture-org", OrganizationID: 777, ClientID: "Iv1.fixture", InstallationID: 42, ConfigEnc: "private-config-fixture", CreatedBy: actor, CreatedAt: time.Now().UTC()}
	if err := database.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"github-org-runners-reader", "github-org-runners-enroller"} {
		if err := database.Create(&authorization.Grant{ID: role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	base := "/api/servers/dev/github"
	if response := policyRequest(router, cookie, "GET", base+"/organizations", ""); response.Code != 200 || !strings.Contains(response.Body.String(), "fixture-org") || strings.Contains(response.Body.String(), "private-config-fixture") {
		t.Fatal("unsafe organization metadata", response.Code)
	}
	for _, suffix := range []string{"/connections", "/dispatches", "/cancellations", "/changes"} {
		if response := policyRequest(router, cookie, "GET", base+suffix, ""); response.Code != 403 {
			t.Fatal("organization role gained repository authority", suffix, response.Code)
		}
	}
	if response := policyRequest(router, cookie, "POST", base+"/organizations/"+id+"/registration-token", `{"requestId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`); response.Code != 403 {
		t.Fatal("token issuer bypassed explicit reveal permission", response.Code)
	}
	if response := policyRequest(router, cookie, "GET", "/api/servers/prod/github/organizations", ""); response.Code != 404 {
		t.Fatal("organization metadata leaked across scope", response.Code)
	}
}
