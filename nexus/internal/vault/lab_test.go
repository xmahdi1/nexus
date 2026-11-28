package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPersistentDisposableVault(t *testing.T) {
	id := os.Getenv("NEXUS_VAULT_LAB_CONTAINER")
	if id == "" {
		t.Skip("run scripts/vault_lab.py")
	}
	nonce := os.Getenv("NEXUS_VAULT_LAB_NONCE")
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(nonce) {
		t.Fatal("owned disposable container required")
	}
	docker := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command("docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...).Output()
		if err != nil {
			t.Fatal("owned fixture control failed")
		}
		return out
	}
	if strings.TrimSpace(string(docker("inspect", "--format", `{{index .Config.Labels "nexus.vault-lab"}}`, id))) != nonce {
		t.Fatal("fixture ownership mismatch")
	}
	address := os.Getenv("NEXUS_VAULT_LAB_ADDR")
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("loopback fixture required")
	}
	ca, err := os.ReadFile(os.Getenv("NEXUS_VAULT_LAB_CA"))
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Port: 8200, TLSName: "vault.fixture", CAPEM: string(ca)}
	client, err := NewClient(p, func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	// Operator initialization/restore are fixture setup, outside the read-only
	// adapter. They legitimately take longer than its bounded inspection calls.
	control := *client
	transport := client.Transport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 45 * time.Second
	control.Transport = transport
	control.Timeout = 60 * time.Second
	defer control.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	request := func(method, path, token string, body []byte) []byte {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, "https://vault.fixture/v1/"+path, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
			if path == "sys/storage/raft/snapshot-force" {
				req.Header.Set("Content-Type", "application/octet-stream")
			}
		}
		r, err := control.Do(req)
		if err != nil {
			t.Fatal("fixture HTTP control failed")
		}
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil || r.StatusCode < 200 || r.StatusCode > 299 {
			t.Fatal("fixture HTTP control rejected", path, r.StatusCode)
		}
		return data
	}
	observe := func(token string) Observation {
		t.Helper()
		result, err := Inspect(ctx, client, p, token)
		if err != nil {
			t.Fatal("inspection failed", err)
		}
		return result
	}
	if result := observe(""); result.Health.Initialized || result.Health.Status != 501 {
		t.Fatal("uninitialized state lost")
	}
	var initialized struct {
		Keys []string `json:"keys_base64"`
		Root string   `json:"root_token"`
	}
	if json.Unmarshal(request("POST", "sys/init", "", []byte(`{"secret_shares":1,"secret_threshold":1}`)), &initialized) != nil || len(initialized.Keys) != 1 || initialized.Root == "" {
		t.Fatal("fixture init failed")
	}
	unseal := func() {
		t.Helper()
		data, _ := json.Marshal(map[string]string{"key": initialized.Keys[0]})
		defer clear(data)
		request("POST", "sys/unseal", "", data)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			state, err := Inspect(ctx, client, p, "")
			if err == nil && !state.Health.Sealed && state.Health.Status == 200 {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("fixture did not become active")
	}
	if result := observe(""); !result.Health.Sealed || result.Health.Status != 503 {
		t.Fatal("sealed state lost")
	}
	unseal()
	if _, err := Inspect(ctx, client, p, initialized.Root); err == nil {
		t.Fatal("root token accepted for UI")
	}
	request("POST", "sys/mounts/fixture", initialized.Root, []byte(`{"type":"kv","options":{"version":"2"}}`))
	policy, _ := json.Marshal(map[string]string{"policy": `path "sys/mounts" { capabilities = ["read"] }
path "fixture/metadata/*" { capabilities = ["read", "list"] }
path "fixture/data/*" { capabilities = ["read", "create", "update"] }`})
	request("PUT", "sys/policies/acl/nexus-fixture", initialized.Root, policy)
	createToken := func(policies []string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"policies": policies, "ttl": "20m"})
		var value struct {
			Auth struct {
				Token string `json:"client_token"`
			} `json:"auth"`
		}
		if json.Unmarshal(request("POST", "auth/token/create", initialized.Root, body), &value) != nil || value.Auth.Token == "" {
			t.Fatal("fixture token creation failed")
		}
		return value.Auth.Token
	}
	token := createToken([]string{"nexus-fixture"})
	checkInventory := func() {
		t.Helper()
		result := observe(token)
		found := false
		for _, m := range result.Mounts {
			if m.Path == "fixture/" && m.Type == "kv" && m.Version == "2" {
				found = true
			}
		}
		if !found || result.MountsStatus != "ok" {
			t.Fatal("persistent engine missing")
		}
	}
	checkInventory()
	zero := 0
	managed := KVRequest{Token: token, Mount: "fixture", Path: "managed", Version: &zero, Data: json.RawMessage(`{"fixture":"created"}`)}
	written, err := KV(ctx, client, p, "write", managed, func() bool { return true })
	if err != nil || written.Metadata == nil || written.Metadata.Version != 1 {
		t.Fatal("KV create failed", err)
	}
	if _, err := KV(ctx, client, p, "write", managed, func() bool { return true }); !errors.Is(err, ErrConflict) {
		t.Fatal("stale CAS was accepted", err)
	}
	read := KVRequest{Token: token, Mount: "fixture", Path: "managed"}
	revealed, err := KV(ctx, client, p, "read", read, nil)
	if err != nil || !bytes.Contains(revealed.Data, []byte("created")) {
		t.Fatal("KV reveal failed", err)
	}
	metadata, err := KV(ctx, client, p, "metadata", read, nil)
	if err != nil || metadata.Metadata == nil || metadata.Metadata.Version != 1 || len(metadata.Data) != 0 {
		t.Fatal("KV metadata leaked values or lost version", err)
	}
	metadataJSON, _ := json.Marshal(metadata)
	if bytes.Contains(metadataJSON, []byte("destroyed")) {
		t.Fatal("metadata invented deletion state")
	}
	one := 1
	managed.Version = &one
	managed.Data = json.RawMessage(`{"fixture":"updated","large":9007199254740993,"decimal":0.1000000000000000001}`)
	if _, err := KV(ctx, client, p, "write", managed, func() bool { return true }); err == nil {
		t.Fatal("lossy numeric write was not rejected")
	}
	managed.Data = json.RawMessage(`{"fixture":"updated","large":"9007199254740993","decimal":"0.1000000000000000001"}`)
	if _, err := KV(ctx, client, p, "write", managed, func() bool { return false }); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked KV write proceeded", err)
	}
	written, err = KV(ctx, client, p, "write", managed, func() bool { return true })
	if err != nil || written.Metadata.Version != 2 {
		t.Fatal("KV update failed", err)
	}
	precise, err := KV(ctx, client, p, "read", read, nil)
	if err != nil || !bytes.Contains(precise.Data, []byte("9007199254740993")) || !bytes.Contains(precise.Data, []byte("0.1000000000000000001")) {
		t.Fatal("numeric JSON changed in Vault round trip", err)
	}
	listing, err := KV(ctx, client, p, "list", KVRequest{Token: token, Mount: "fixture"}, nil)
	if err != nil || len(listing.Keys) == 0 {
		t.Fatal("KV listing failed", err)
	}
	accessPolicy, _ := json.Marshal(map[string]string{"policy": `path "sys/auth" { capabilities = ["read"] }
path "sys/policies/acl" { capabilities = ["list"] }
path "sys/policies/acl/nexus-fixture" { capabilities = ["read"] }`})
	request("PUT", "sys/policies/acl/nexus-access", initialized.Root, accessPolicy)
	accessToken := createToken([]string{"nexus-access"})
	if state := observe(accessToken); state.MountsStatus != "permission_denied" {
		t.Fatal("access-only fixture unexpectedly has mount authority")
	}
	methods, err := Access(ctx, client, p, "auth", AccessRequest{Token: accessToken})
	if err != nil || len(methods.Methods) == 0 {
		t.Fatal("auth metadata requires unrelated mount authority", err)
	}
	policies, err := Access(ctx, client, p, "policies", AccessRequest{Token: accessToken})
	if err != nil || len(policies.Policies) == 0 {
		t.Fatal("policy listing failed", err)
	}
	source, err := Access(ctx, client, p, "policy", AccessRequest{Token: accessToken, Name: "nexus-fixture"})
	if err != nil || source.Policy == nil || !strings.Contains(*source.Policy, "sys/mounts") {
		t.Fatal("policy source missing", err)
	}
	capabilities, err := Access(ctx, client, p, "capabilities", AccessRequest{Token: accessToken, Paths: []string{"sys/auth", "fixture/data/managed"}})
	if err != nil || len(capabilities.Capabilities["sys/auth"]) == 0 || len(capabilities.Capabilities["fixture/data/managed"]) != 1 || capabilities.Capabilities["fixture/data/managed"][0] != "deny" {
		t.Fatal("caller capability scope incorrect", err)
	}
	denied := createToken([]string{"default"})
	if result := observe(denied); result.MountsStatus != "permission_denied" {
		t.Fatal("upstream ACL bypassed")
	}
	request("POST", "auth/token/revoke-self", denied, nil)
	if result := observe(denied); result.MountsStatus != "permission_denied" {
		t.Fatal("revoked token accepted")
	}
	testDisposableAdministration(t, ctx, client, p, initialized.Root, request, createToken)
	testDisposableDatabaseLease(t, ctx, client, p, initialized.Root, request, createToken)
	request("POST", "fixture/data/preserved", initialized.Root, []byte(`{"data":{"marker":"before-snapshot"}}`))
	snapshot := request("GET", "sys/storage/raft/snapshot", initialized.Root, nil)
	defer clear(snapshot)
	if len(snapshot) == 0 {
		t.Fatal("empty snapshot")
	}
	docker("restart", "--time", "10", id)
	address = strings.TrimSpace(string(docker("port", id, "8200/tcp")))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		state, err := Inspect(ctx, client, p, "")
		if err == nil && state.Health.Sealed {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	unseal()
	checkInventory()
	request("POST", "fixture/data/preserved", initialized.Root, []byte(`{"data":{"marker":"after-snapshot"}}`))
	request("POST", "sys/storage/raft/snapshot-force", initialized.Root, snapshot)
	// Restore may re-seal while replacing raft state. Reuse only the generated
	// original shares; never obtain or print real operator keys.
	time.Sleep(time.Second)
	state, err := Inspect(ctx, client, p, "")
	if err != nil || state.Health.Sealed {
		unseal()
	}
	value := request("GET", "fixture/data/preserved", initialized.Root, nil)
	if !bytes.Contains(value, []byte("before-snapshot")) || bytes.Contains(value, []byte("after-snapshot")) {
		t.Fatal("snapshot restore did not recover original value")
	}
	t.Log("Persistent non-dev Vault: TLS, initialized/sealed/active states, non-root ACLs, revocation, restart and raft snapshot restore passed.")
}
