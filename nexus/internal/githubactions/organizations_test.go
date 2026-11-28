package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
)

func organizationFixture(t *testing.T) (*Service, *auth.Access, OrganizationInput, *int) {
	t.Helper()
	s, a, connection, _ := serviceFixture(t)
	for _, role := range []string{"github-org-connections", "github-org-runners-manager", "github-org-runners-enroller", "secret-reader"} {
		if err := s.DB.Create(&authorization.Grant{ID: role, PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "build", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	s.Client.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Path == "/app/installations/42" && r.Method == "GET":
			return response(200, `{"id":42,"account":{"id":777,"login":"fixture-org","type":"Organization"},"suspended_at":null}`), nil
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			var input struct {
				Permissions map[string]string `json:"permissions"`
				IDs         []int64           `json:"repository_ids"`
			}
			if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.Permissions) != 1 || len(input.IDs) != 0 {
				t.Fatal("org credentials requested repository authority")
			}
			return response(201, fmt.Sprintf(`{"token":"ghs_fixture_org_runners_token","expires_at":%q,"permissions":{"organization_self_hosted_runners":%q}}`, s.Client.now().Add(time.Hour).Format(time.RFC3339), input.Permissions["organization_self_hosted_runners"])), nil
		case strings.HasSuffix(r.URL.Path, "/registration-token"):
			writes++
			return response(201, fmt.Sprintf(`{"token":"REGISTRATION_TOKEN_FIXTURE_ONLY","expires_at":%q}`, s.Client.now().Add(time.Hour).Format(time.RFC3339))), nil
		case r.Method == "DELETE":
			writes++
			return nil, errors.New("lost provider acknowledgement")
		case strings.Contains(r.URL.Path, "/orgs/fixture-org/actions/runners/"):
			return response(200, `{"id":9,"name":"retired","os":"linux","status":"offline","busy":false,"labels":[]}`), nil
		default:
			return response(200, `{"total_count":1,"runners":[{"id":9,"name":"retired","os":"linux","status":"offline","busy":false,"labels":[]}]}`), nil
		}
	})
	return s, a, OrganizationInput{Organization: Organization{Login: "fixture-org", ID: 777}, ClientID: connection.ClientID, InstallationID: connection.InstallationID, PrivateKey: connection.PrivateKey}, &writes
}
func TestOrganizationCredentialsRegistrationAndRemovalDoNotReplay(t *testing.T) {
	s, a, input, writes := organizationFixture(t)
	connection, err := s.CreateOrganization(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(connection)
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "configEnc") {
		t.Fatal("org key exposed")
	}
	if _, _, err := s.organizationConnection("other", connection.ID); err == nil {
		t.Fatal("cross-server connection")
	}
	page, err := s.OrganizationRunners(context.Background(), a, "build", connection.ID, 1)
	if err != nil || len(page.Runners) != 1 {
		t.Fatal("org runner listing failed", err)
	}
	id := strings.Repeat("a", 32)
	row, credential, err := s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, id, "registration", RemoveRunner{})
	if err != nil || row.State != "applied" || credential == nil || credential.Token == "" || *writes != 1 {
		t.Fatal("token issue failed", row.State, err)
	}
	encoded, _ = json.Marshal(row)
	if strings.Contains(string(encoded), credential.Token) {
		t.Fatal("credential in metadata")
	}
	row, credential, err = s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, id, "registration", RemoveRunner{})
	if err != nil || row.State != "applied" || credential != nil || *writes != 1 {
		t.Fatal("credential reissued on repeat", err)
	}
	removeID := strings.Repeat("b", 32)
	row, _, err = s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, removeID, "runner_remove", RemoveRunner{RunnerID: 9, Name: "retired"})
	if !errors.Is(err, ErrUnknown) || row.State != "unknown" || *writes != 2 {
		t.Fatal("lost ACK invented success", row.State, err)
	}
	if _, _, err := s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, removeID, "runner_remove", RemoveRunner{RunnerID: 9, Name: "retired"}); err != nil || *writes != 2 {
		t.Fatal("removal replayed", err)
	}
	if _, _, err := s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, removeID, "runner_remove", RemoveRunner{RunnerID: 10, Name: "retired"}); !errors.Is(err, ErrConflict) {
		t.Fatal("changed target reused request", err)
	}
	if err := s.DisableOrganization(a, "build", connection.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, strings.Repeat("c", 32), "registration", RemoveRunner{}); !errors.Is(err, ErrDenied) || *writes != 2 {
		t.Fatal("disabled organization issued credential", err)
	}
}
func TestOrganizationInstallationIdentityAndTokenPermissionChecks(t *testing.T) {
	for _, tt := range []struct{ name, account, permissions string }{
		{"wrong org", `{"id":778,"login":"fixture-org","type":"Organization"}`, `{"organization_self_hosted_runners":"read"}`},
		{"user installation", `{"id":777,"login":"fixture-org","type":"User"}`, `{"organization_self_hosted_runners":"read"}`},
		{"wrong login", `{"id":777,"login":"another","type":"Organization"}`, `{"organization_self_hosted_runners":"read"}`},
		{"broader token", `{"id":777,"login":"fixture-org","type":"Organization"}`, `{"organization_self_hosted_runners":"read","actions":"write"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, app, _, _ := fixture(t)
			writes := 0
			c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					return response(200, `{"id":42,"account":`+tt.account+`}`), nil
				}
				writes++
				return response(201, fmt.Sprintf(`{"token":"ghs_fixture_org_runners_token","expires_at":%q,"permissions":%s}`, c.now().Add(time.Hour).Format(time.RFC3339), tt.permissions)), nil
			})
			if token, err := c.OrganizationToken(context.Background(), app, Organization{Login: "fixture-org", ID: 777}, false); err == nil || token != nil {
				t.Fatal("invalid installation/authority accepted")
			}
			if tt.name != "broader token" && writes != 0 {
				t.Fatal("mint attempted for wrong installation identity")
			}
		})
	}
}
func TestOrganizationAuthorityLossSuppressesLateToken(t *testing.T) {
	s, a, input, writes := organizationFixture(t)
	connection, err := s.CreateOrganization(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	transport := s.Client.transport
	s.Client.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		result, err := transport.RoundTrip(r)
		if strings.HasSuffix(r.URL.Path, "/registration-token") {
			s.DB.Where("id=?", "github-org-runners-enroller").Delete(&authorization.Grant{})
		}
		return result, err
	})
	row, credential, err := s.ChangeOrganizationRunner(context.Background(), a, "build", connection.ID, strings.Repeat("d", 32), "registration", RemoveRunner{})
	if !errors.Is(err, ErrDenied) || credential != nil || row.State != "applied" || *writes != 1 {
		t.Fatal("late token escaped revoked authority", row.State, err)
	}
}
