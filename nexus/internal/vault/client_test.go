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

func TestVerifiedReadOnlyInspectionAndCredentialBoundaries(t *testing.T) {
	for _, scenario := range []string{"inventory", "health-only", "sealed", "uninitialized", "denied", "expired", "root", "unbounded-token", "redirect", "oversized", "invalid-health", "wrong-ca"} {
		t.Run(scenario, func(t *testing.T) {
			const token = "ephemeral-vault-fixture"
			calls := []string{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.Path)
				if r.Method != "GET" {
					t.Error("adapter mutated Vault")
				}
				if r.Header.Get("X-Vault-Namespace") != "team/" {
					t.Error("namespace not bound")
				}
				if r.URL.Path == "/v1/sys/health" {
					if r.Header.Get("X-Vault-Token") != "" {
						t.Error("health request disclosed token")
					}
					if scenario == "invalid-health" {
						w.Write([]byte(`{}`))
						return
					}
					if scenario == "oversized" {
						w.Write([]byte(strings.Repeat("x", 1048577)))
						return
					}
					code := 200
					if scenario == "sealed" {
						code = 503
					}
					if scenario == "uninitialized" {
						code = 501
					}
					w.WriteHeader(code)
					json.NewEncoder(w).Encode(map[string]bool{"initialized": scenario != "uninitialized", "sealed": scenario == "sealed" || scenario == "uninitialized", "standby": false})
					return
				}
				if r.Header.Get("X-Vault-Token") != token {
					t.Error("missing caller token")
				}
				if scenario == "expired" || (scenario == "denied" && r.URL.Path == "/v1/sys/mounts") {
					w.WriteHeader(403)
					w.Write([]byte(token + " reflected secret"))
					return
				}
				if scenario == "redirect" {
					http.Redirect(w, r, "https://untrusted.invalid/", 307)
					return
				}
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					policies := []string{"inventory"}
					ttl := 1200
					if scenario == "root" {
						policies = []string{"root"}
					}
					if scenario == "unbounded-token" {
						ttl = 0
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": policies, "ttl": ttl}})
					return
				}
				if r.URL.Path != "/v1/sys/mounts" {
					t.Error("unexpected endpoint", r.URL.Path)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"secret/": map[string]any{"type": "kv", "description": token, "options": map[string]string{"version": "2"}, "unrecognized_private_field": token}}})
			}))
			defer server.Close()
			p := Profile{Port: 8200, TLSName: "127.0.0.1", Namespace: "team/", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
			if scenario == "wrong-ca" {
				p.CAPEM = ""
			}
			client, err := NewClient(p, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "127.0.0.1:8200" || network != "tcp" {
					t.Error("destination escaped managed loopback", address)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			credential := token
			if scenario == "health-only" {
				credential = ""
			}
			result, err := Inspect(context.Background(), client, p, credential)
			wantError := scenario == "root" || scenario == "unbounded-token" || scenario == "redirect" || scenario == "oversized" || scenario == "invalid-health" || scenario == "wrong-ca"
			if (err != nil) != wantError {
				t.Fatal("unexpected inspection outcome", result, err)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), token) || (err != nil && strings.Contains(err.Error(), token)) {
				t.Fatal("token reflected")
			}
			if scenario == "inventory" && (result.MountsStatus != "ok" || len(result.Mounts) != 1 || result.Mounts[0].Version != "2") {
				t.Fatal("inventory missing", result)
			}
			if scenario == "denied" || scenario == "expired" {
				if result.MountsStatus != "permission_denied" {
					t.Fatal("permission loss hidden", result)
				}
			}
			if scenario == "health-only" || scenario == "sealed" || scenario == "uninitialized" {
				if len(calls) != 1 {
					t.Fatal("unnecessary credential request", calls)
				}
			}
			if scenario == "root" || scenario == "unbounded-token" || scenario == "redirect" {
				if len(calls) != 2 {
					t.Fatal("rejected token reached inventory or redirect followed", calls)
				}
			}
		})
	}
}

func TestProfileRejectsPrivateKeysAndUntrustedRouting(t *testing.T) {
	for _, p := range []Profile{{Port: 80, TLSName: "vault.test"}, {Port: 8200, TLSName: "vault.test/path"}, {Port: 8200, TLSName: "vault.test", Namespace: "../admin"}, {Port: 8200, TLSName: "vault.test", CAPEM: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}} {
		if p.Validate() == nil {
			t.Fatal("unsafe profile accepted", p)
		}
	}
}
