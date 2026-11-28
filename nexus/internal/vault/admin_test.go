package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func adminFixtureInput(t *testing.T, id, token string, params map[string]any) AdminRequest {
	t.Helper()
	input := AdminRequest{Token: token, Params: map[string]json.RawMessage{}}
	op, ok := AdminOperationByID(id)
	if !ok {
		t.Fatal("unknown fixture operation", id)
	}
	if op.Mutation {
		input.Confirmation = id
	}
	for key, value := range params {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		input.Params[key] = raw
	}
	return input
}
func fixtureCSR(t *testing.T, name string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type adminTransport func(*http.Request) (*http.Response, error)

func (f adminTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func adminReply(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestAdminClosedSchemaAndProtectedResources(t *testing.T) {
	cases := []struct {
		id     string
		params map[string]any
	}{
		{"token-create", map[string]any{"policies": []string{"root"}, "ttl": 600, "display_name": "test"}},
		{"token-create", map[string]any{"policies": []string{"default"}, "ttl": 86401, "display_name": "test"}},
		{"policy-save", map[string]any{"name": "default", "revision": "missing", "policy": "deny"}},
		{"policy-delete", map[string]any{"name": "root", "revision": "missing"}},
		{"policy-read", map[string]any{"name": "../root"}},
		{"kv-delete", map[string]any{"mount": "secret", "path": "key", "versions": []int{1, 1}}},
		{"kv-delete", map[string]any{"mount": "secret", "path": "key", "versions": []int{0}}},
		{"kv-history", map[string]any{"mount": "secret%2f..", "path": "key"}},
		{"engine-enable", map[string]any{"mount": "test", "type": "arbitrary-plugin"}},
		{"auth-enable", map[string]any{"mount": "test", "type": "token"}},
		{"engine-tune", map[string]any{"mount": "test", "default_lease_ttl": 500, "max_lease_ttl": 100}},
		{"token-self", map[string]any{"url": "https://other/"}},
		{"pki-sign", map[string]any{"mount": "test", "name": "role", "common_name": "app.test", "ttl": 300, "csr": "-----BEGIN PRIVATE KEY-----"}},
		{"pki-issue", map[string]any{"mount": "test", "name": "role", "common_name": "*.app.test", "ttl": 300}},
		{"pki-certificate-read", map[string]any{"mount": "test", "serial_number": "../ca"}},
		{"token-renew", map[string]any{"accessor": "test", "increment": "300"}},
	}
	for _, tt := range cases {
		t.Run(tt.id, func(t *testing.T) {
			op, _ := AdminOperationByID(tt.id)
			if err := adminFixtureInput(t, tt.id, "fixture", tt.params).Validate(op); err == nil {
				t.Fatal("unsafe fields accepted")
			}
		})
	}
	input := adminFixtureInput(t, "token-create", "fixture", map[string]any{"policies": []string{"default"}, "ttl": 600, "display_name": "test"})
	op, _ := AdminOperationByID("token-create")
	input.Confirmation = ""
	if input.Validate(op) == nil {
		t.Fatal("unconfirmed mutation accepted")
	}
	if _, err := Admin(context.Background(), nil, Profile{}, "unregistered", AdminRequest{}, nil); !errors.Is(err, ErrInvalidAdmin) {
		t.Fatal("unknown operation accepted")
	}
}

func TestAdminGuardReceiptsAndSanitization(t *testing.T) {
	for _, scenario := range []string{"revoked", "lost", "invalid", "empty-issued", "denied", "renew", "reflected"} {
		t.Run(scenario, func(t *testing.T) {
			const token = `caller-"credential`
			id := "token-create"
			params := map[string]any{"policies": []string{"default"}, "ttl": 600, "display_name": "test"}
			if scenario == "renew" {
				id = "lease-renew"
				params = map[string]any{"lease_id": "nexus/creds/id", "increment": 300}
			}
			if scenario == "reflected" {
				id = "token-self"
				params = nil
			}
			calls := 0
			client := &http.Client{Transport: adminTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/v1/auth/token/lookup-self" && (calls == 0 || scenario == "reflected") {
					calls++
					if scenario == "reflected" && calls == 2 {
						body, _ := json.Marshal(map[string]any{"data": map[string]any{"display_name": token, "id": "must-not-return", "metadata": map[string]string{"password": "hidden"}, "ttl": 300}})
						return adminReply(200, string(body)), nil
					}
					return adminReply(200, `{"data":{"policies":["scoped"],"ttl":600}}`), nil
				}
				calls++
				if r.GetBody != nil || r.Body == nil {
					t.Error("mutation eligible for transport replay")
				}
				switch scenario {
				case "revoked":
					t.Error("revoked mutation dispatched")
				case "lost":
					return nil, errors.New("private upstream failure " + token)
				case "invalid":
					return adminReply(200, `{"auth":`), nil
				case "empty-issued":
					return adminReply(204, ""), nil
				case "denied":
					return adminReply(403, token), nil
				case "renew":
					return adminReply(200, `{"lease_id":"nexus/creds/id","lease_duration":300,"renewable":true,"data":null}`), nil
				}
				return adminReply(200, `{"auth":{"client_token":"new-child","accessor":"new-accessor","policies":["default"]}}`), nil
			})}
			result, err := Admin(context.Background(), client, Profile{TLSName: "vault.test"}, id, adminFixtureInput(t, id, token, params), func() bool { return scenario != "revoked" })
			if scenario == "revoked" || scenario == "denied" {
				if !errors.Is(err, ErrDenied) {
					t.Fatal("denial not preserved", err)
				}
			} else if scenario == "lost" || scenario == "invalid" || scenario == "empty-issued" {
				if !errors.Is(err, ErrRemoteUnknown) {
					t.Fatal("lost receipt misreported", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if scenario == "reflected" && (!result.Redacted || strings.Contains(result.DataJSON, "must-not-return") || strings.Contains(result.DataJSON, "hidden") || strings.Contains(result.DataJSON, "credential")) {
				t.Fatal("credential or unknown metadata leaked")
			}
			if scenario == "renew" && !strings.Contains(result.DataJSON, "lease_duration") {
				t.Fatal("lease renewal receipt lost")
			}
			if calls > 2 || (scenario == "revoked" && calls != 1) {
				t.Fatal("mutation retried or guard bypassed", calls)
			}
		})
	}
}

func TestPolicyRevisionConflictAndRedactedSource(t *testing.T) {
	for _, scenario := range []string{"stale", "redacted", "current"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: adminTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					return adminReply(200, `{"data":{"policies":["scoped"],"ttl":600}}`), nil
				}
				if r.Method == "GET" {
					source := "path test {}"
					if scenario == "redacted" {
						source += " # fixture-token"
					}
					body, _ := json.Marshal(map[string]any{"data": map[string]any{"policy": source}})
					return adminReply(200, string(body)), nil
				}
				calls++
				return adminReply(204, ""), nil
			})}
			p := Profile{TLSName: "vault.test"}
			read, err := Admin(context.Background(), client, p, "policy-read", adminFixtureInput(t, "policy-read", "fixture-token", map[string]any{"name": "application"}), nil)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "redacted" {
				if !read.Redacted || read.Revision != "" {
					t.Fatal("redacted policy remained editable")
				}
				return
			}
			revision := read.Revision
			if scenario == "stale" {
				revision = strings.Repeat("0", 64)
			}
			_, err = Admin(context.Background(), client, p, "policy-save", adminFixtureInput(t, "policy-save", "fixture-token", map[string]any{"name": "application", "revision": revision, "policy": "path changed {}"}), func() bool { return true })
			if scenario == "stale" {
				if !errors.Is(err, ErrConflict) || calls != 0 {
					t.Fatal("stale policy overwritten", err)
				}
			} else if err != nil || calls != 1 {
				t.Fatal("confirmed policy save failed", err)
			}
		})
	}
}

func TestMutatingGETRequiresGuardAndCannotReplay(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: adminTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.GetBody != nil || r.Body == nil {
			t.Fatal("mutating GET is replayable")
		}
		return nil, errors.New("lost connection")
	})}
	_, err := adminRPC(context.Background(), client, Profile{TLSName: "vault.test"}, "fixture", "GET", "/v1/pki/crl/rotate", nil, true, nil)
	if !errors.Is(err, ErrDenied) || calls != 0 {
		t.Fatal("unguarded mutating GET dispatched")
	}
	_, err = adminRPC(context.Background(), client, Profile{TLSName: "vault.test"}, "fixture", "GET", "/v1/pki/crl/rotate", nil, true, func() bool { return true })
	if !errors.Is(err, ErrRemoteUnknown) || calls != 1 {
		t.Fatal("mutating GET replayed or lost outcome hidden")
	}
}
