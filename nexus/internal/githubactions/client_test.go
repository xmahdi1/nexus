package githubactions

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func fixture(t *testing.T) (*Client, App, Repository, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	return &Client{now: func() time.Time { return now }}, App{ClientID: "Iv1.fixture", InstallationID: 42, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})}, Repository{Owner: "fixture", Name: "repository", ID: 123}, key
}
func TestAppTokenScopeSignatureAndWorkflowIdentity(t *testing.T) {
	c, app, repo, key := fixture(t)
	calls := 0
	c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "api.github.com" || r.Header.Get("X-GitHub-Api-Version") != APIVersion {
			t.Fatal("provider destination/version changed")
		}
		switch calls {
		case 1:
			if r.Method != "POST" || r.URL.Path != "/app/installations/42/access_tokens" {
				t.Fatal("wrong token endpoint")
			}
			parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
			if len(parts) != 3 {
				t.Fatal("invalid JWT")
			}
			signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
			hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], signature) != nil {
				t.Fatal("invalid signature")
			}
			var claims struct {
				Iat int64  `json:"iat"`
				Exp int64  `json:"exp"`
				Iss string `json:"iss"`
			}
			body, _ := base64.RawURLEncoding.DecodeString(parts[1])
			json.Unmarshal(body, &claims)
			if claims.Iss != app.ClientID || claims.Iat != c.now().Add(-time.Minute).Unix() || claims.Exp > c.now().Add(10*time.Minute).Unix() {
				t.Fatal("invalid JWT lifetime/issuer")
			}
			var scope struct {
				IDs         []int64           `json:"repository_ids"`
				Permissions map[string]string `json:"permissions"`
			}
			if json.NewDecoder(r.Body).Decode(&scope) != nil || len(scope.IDs) != 1 || scope.IDs[0] != repo.ID || scope.Permissions["actions"] != "write" || len(scope.Permissions) != 3 {
				t.Fatal("token broadened repository/permissions")
			}
			return response(201, fmt.Sprintf(`{"token":"ghs_fixture_installation_token","expires_at":%q,"permissions":{"actions":"write","contents":"read","metadata":"read"},"repositories":[{"id":123}]}`, c.now().Add(time.Hour).Format(time.RFC3339))), nil
		case 2:
			return response(200, `{"id":123,"full_name":"fixture/repository"}`), nil
		case 3:
			if r.URL.Path != "/repos/fixture/repository/actions/workflows" || r.URL.RawQuery != "per_page=50&page=1" {
				t.Fatal("unbounded workflow endpoint")
			}
			return response(200, `{"total_count":1,"workflows":[{"id":7,"name":"Build","path":".github/workflows/build.yml","state":"active","ignored":"not forwarded"}]}`), nil
		case 4:
			if r.Method != "POST" || r.URL.Path != "/repos/fixture/repository/actions/workflows/7/dispatches" {
				t.Fatal("invalid dispatch endpoint")
			}
			return response(200, `{"workflow_run_id":99,"html_url":"https://attacker.invalid"}`), nil
		default:
			t.Fatal("request replayed")
			return nil, ErrUnavailable
		}
	})
	token, err := c.InstallationToken(context.Background(), app, repo, true)
	if err != nil {
		t.Fatal(err)
	}
	page, err := c.Workflows(context.Background(), repo, token, 1)
	if err != nil || len(page.Workflows) != 1 {
		t.Fatal("workflow list failed", err)
	}
	result, err := c.DispatchOnce(context.Background(), repo, token, Dispatch{WorkflowID: 7, Ref: "main", Inputs: map[string]any{"enabled": true}}, func() bool { return true })
	if err != nil || result.RunID != 99 || calls != 4 {
		t.Fatal("run identity not returned", err)
	}
	encoded, _ := json.Marshal(app)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("private key entered public JSON")
	}
	token.Clear()
	if _, err := c.Workflows(context.Background(), repo, token, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("cleared token retained access")
	}
}
func TestDispatchUnknownNeverFollowsRedirectOrRetries(t *testing.T) {
	for _, scenario := range []string{"lost-ack", "redirect", "malformed", "old-204", "denied"} {
		t.Run(scenario, func(t *testing.T) {
			c, _, repo, _ := fixture(t)
			calls := 0
			token := &Token{value: "ghs_fixture_private_token", ExpiresAt: c.now().Add(time.Hour), repository: repo, write: true}
			c.transport = roundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				switch scenario {
				case "lost-ack":
					return nil, errors.New("private provider response")
				case "redirect":
					r := response(302, "")
					r.Header.Set("Location", "https://attacker.invalid")
					return r, nil
				case "malformed":
					return response(200, `{"workflow_run_id":`), nil
				case "old-204":
					return response(204, ""), nil
				default:
					return response(403, "private provider response"), nil
				}
			})
			result, err := c.DispatchOnce(context.Background(), repo, token, Dispatch{WorkflowID: 7, Ref: "main"}, func() bool { return true })
			if !errors.Is(err, ErrUnknown) || result.RunID != 0 || calls != 1 || strings.Contains(err.Error(), "private provider response") {
				t.Fatal("unsafe dispatch outcome", result, err, calls)
			}
		})
	}
}
func TestLocalRevocationAndRepositoryBindingPreventDispatch(t *testing.T) {
	c, _, repo, _ := fixture(t)
	calls := 0
	c.transport = roundTrip(func(*http.Request) (*http.Response, error) { calls++; return nil, ErrUnavailable })
	token := &Token{value: "ghs_fixture_private_token", ExpiresAt: c.now().Add(time.Hour), repository: repo, write: true}
	if _, err := c.DispatchOnce(context.Background(), repo, token, Dispatch{WorkflowID: 7, Ref: "main"}, func() bool { return false }); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation ignored")
	}
	other := repo
	other.ID++
	if _, err := c.Workflows(context.Background(), other, token, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("token repository binding ignored")
	}
	if _, err := c.DispatchOnce(context.Background(), repo, token, Dispatch{WorkflowID: 7, Ref: "main", Inputs: map[string]any{"bad": map[string]string{"nested": "value"}}}, func() bool { return true }); !errors.Is(err, ErrInput) {
		t.Fatal("nested inputs accepted")
	}
	if calls != 0 {
		t.Fatal("local denial contacted provider")
	}
}

func TestProviderMetadataBoundsAndRunIdentity(t *testing.T) {
	c, _, repo, _ := fixture(t)
	token := &Token{value: "ghs_fixture_private_token", ExpiresAt: c.now().Add(time.Hour), repository: repo}
	tests := []struct {
		name, body string
		jobs       bool
		want       error
	}{
		{"valid-run", `{"total_count":1,"workflow_runs":[{"id":99,"workflow_id":7,"status":"completed","conclusion":"success","head_sha":"` + strings.Repeat("a", 40) + `","head_branch":"main","event":"workflow_dispatch"}]}`, false, nil},
		{"invalid-sha", `{"total_count":1,"workflow_runs":[{"id":99,"workflow_id":7,"head_sha":"not-a-sha"}]}`, false, ErrUnavailable},
		{"oversized-response", strings.Repeat(" ", 1048577), false, ErrUnavailable},
		{"valid-job", `{"total_count":1,"jobs":[{"id":101,"run_id":99,"name":"Build","status":"completed"}]}`, true, nil},
		{"different-run", `{"total_count":1,"jobs":[{"id":101,"run_id":100,"name":"Build"}]}`, true, ErrUnavailable},
		{"unsafe-id", `{"total_count":1,"jobs":[{"id":9007199254740992,"run_id":99}]}`, true, ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.RawQuery != "per_page=50&page=1" {
					t.Fatal("unbounded metadata request")
				}
				return response(200, test.body), nil
			})
			var err error
			if test.jobs {
				_, err = c.Jobs(context.Background(), repo, token, 99, 1)
			} else {
				_, err = c.Runs(context.Background(), repo, token, 1)
			}
			if !errors.Is(err, test.want) || calls != 1 {
				t.Fatal("unexpected metadata outcome", err, calls)
			}
		})
	}
	token.ExpiresAt = c.now()
	c.transport = roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("expired token contacted provider")
		return nil, ErrUnavailable
	})
	if _, err := c.Runs(context.Background(), repo, token, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("expired token accepted")
	}
}

func TestMintRejectsBroaderRepositoryOrPermissions(t *testing.T) {
	c, app, repo, _ := fixture(t)
	for _, test := range []struct{ name, permissions, repositories string }{
		{"extra-repository", `{"actions":"read","contents":"read","metadata":"read"}`, `[{"id":123},{"id":456}]`},
		{"extra-permission", `{"actions":"read","contents":"read","metadata":"read","administration":"write"}`, `[{"id":123}]`},
		{"broader-contents", `{"actions":"read","contents":"write","metadata":"read"}`, `[{"id":123}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			c.transport = roundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return response(201, fmt.Sprintf(`{"token":"ghs_fixture_installation_token","expires_at":%q,"permissions":%s,"repositories":%s}`, c.now().Add(time.Hour).Format(time.RFC3339), test.permissions, test.repositories)), nil
			})
			token, err := c.InstallationToken(context.Background(), app, repo, false)
			if token != nil || err == nil || calls != 1 {
				t.Fatal("broadened token accepted", err, calls)
			}
		})
	}
}
