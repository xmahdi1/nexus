package vault

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessInspectionNeedsNoMountPermissionAndFiltersReplies(t *testing.T) {
	for _, scenario := range []string{"auth", "policies", "policies-legacy", "policy", "policy-legacy", "capabilities", "capabilities-legacy", "bad-nested-alias", "unknown-capability", "denied", "root", "missing-policies"} {
		t.Run(scenario, func(t *testing.T) {
			const token = "scoped-fixture-token"
			action := scenario
			if strings.Contains(scenario, "legacy") {
				action = strings.TrimSuffix(scenario, "-legacy")
			}
			if scenario == "bad-nested-alias" || scenario == "unknown-capability" {
				action = "capabilities"
			}
			if scenario == "denied" || scenario == "root" || scenario == "missing-policies" {
				action = "auth"
			}
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("X-Vault-Token") != token {
					t.Error("caller token not bound")
				}
				if r.URL.Path == "/v1/sys/mounts" {
					t.Error("unrelated mount privilege required")
					w.WriteHeader(403)
					return
				}
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					if scenario == "denied" {
						w.WriteHeader(403)
						w.Write([]byte(token))
						return
					}
					if scenario == "missing-policies" {
						w.Write([]byte(`{"data":{"ttl":1200}}`))
						return
					}
					policies := []string{"access"}
					if scenario == "root" {
						policies = []string{"root"}
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": policies, "ttl": 1200}})
					return
				}
				if action != "capabilities" && r.Method != "GET" {
					t.Error("inspection mutated upstream")
				}
				var value any
				switch action {
				case "auth":
					value = map[string]any{"data": map[string]any{"token/": map[string]any{"type": "token", "description": token, "config": map[string]any{"default_lease_ttl": 0, "client_secret": token}}}}
				case "policies":
					value = map[string]any{"keys": []string{"default", "example"}}
					if scenario == "policies" {
						value = map[string]any{"data": value}
					}
				case "policy":
					value = map[string]any{"policy": "# " + token + "\npath \"secret/*\" { capabilities = [\"read\"] }"}
					if scenario == "policy" {
						value = map[string]any{"data": value}
					}
				case "capabilities":
					if r.Method != "POST" || r.URL.Path != "/v1/sys/capabilities-self" {
						t.Error("capability endpoint escaped")
					}
					var body map[string][]string
					if json.NewDecoder(r.Body).Decode(&body) != nil || len(body["paths"]) != 1 || body["paths"][0] != "secret/data/key" {
						t.Error("capability query not bound")
					}
					values := map[string]any{"secret/data/key": []string{"read"}, "unrequested-private-path": []string{"root"}}
					if scenario == "unknown-capability" {
						values["secret/data/key"] = []string{token}
					}
					value = map[string]any{"data": values}
					if scenario == "capabilities-legacy" {
						value = values
					}
					if scenario == "bad-nested-alias" {
						value = map[string]any{"secret/data/key": []string{"read"}, "data": map[string]any{}}
					}
				}
				json.NewEncoder(w).Encode(value)
			}))
			defer server.Close()
			profile := Profile{Port: 8200, TLSName: "127.0.0.1", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
			client, err := NewClient(profile, func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			input := AccessRequest{Token: token}
			if action == "policy" {
				input.Name = "example"
			}
			if action == "capabilities" {
				input.Paths = []string{"secret/data/key"}
			}
			result, err := Access(context.Background(), client, profile, action, input)
			wantError := scenario == "denied" || scenario == "root" || scenario == "missing-policies" || scenario == "bad-nested-alias" || scenario == "unknown-capability"
			if (err != nil) != wantError {
				t.Fatal("unexpected access result", err)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "unrequested-private-path") || (err != nil && strings.Contains(err.Error(), token)) {
				t.Fatal("unselected data or credential reflected")
			}
			if action == "policy" && !wantError && (!result.Redacted || result.Policy == nil) {
				t.Fatal("policy source not protected")
			}
			if !wantError && calls != 2 {
				t.Fatal("inspection required unrelated permissions", calls)
			}
			if (scenario == "root" || scenario == "denied" || scenario == "missing-policies") && calls != 1 {
				t.Fatal("invalid token reached inspection endpoint")
			}
		})
	}
}

func TestAccessPathsAreBounded(t *testing.T) {
	for _, request := range []AccessRequest{{Token: "fixture", Paths: []string{"../sys"}}, {Token: "fixture", Paths: []string{strings.Repeat("x", 1025)}}, {Token: "fixture", Paths: make([]string, 33)}} {
		if request.Validate("capabilities") == nil {
			t.Fatal("unbounded query accepted")
		}
	}
	if (AccessRequest{Token: "fixture", Paths: []string{strings.Repeat("x", 1024)}}).Validate("capabilities") != nil {
		t.Fatal("documented path bound rejected")
	}
	if (AccessRequest{Token: "fixture", Name: "../root"}).Validate("policy") == nil {
		t.Fatal("policy path escaped")
	}
}
