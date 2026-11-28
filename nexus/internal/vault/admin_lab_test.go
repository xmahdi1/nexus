package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// This is called only after lab_test has verified disposable container ownership.
// Bootstrap root authority stays in fixture setup, never in an Admin request.
func testDisposableAdministration(t *testing.T, ctx context.Context, c *http.Client, p Profile, root string, request func(string, string, string, []byte) []byte, createToken func([]string) string) {
	t.Helper()
	policy, _ := json.Marshal(map[string]string{"policy": `path "sys/*" { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/leases/lookup" { capabilities = ["read","update","list","sudo"] }
path "auth/*" { capabilities = ["create","read","update","delete","list","sudo"] }
path "identity/*" { capabilities = ["create","read","update","delete","list"] }
path "nexus-*" { capabilities = ["create","read","update","delete","list","sudo"] }`})
	request("PUT", "sys/policies/acl/nexus-administration", root, policy)
	token := createToken([]string{"nexus-administration"})
	seen := map[string]bool{}
	call := func(id string, params map[string]any) AdminResult {
		t.Helper()
		input := adminFixtureInput(t, id, token, params)
		result, err := Admin(ctx, c, p, id, input, func() bool { return true })
		if err != nil {
			t.Fatal("disposable admin action failed", id, err)
		}
		seen[id] = true
		return result
	}
	decode := func(result AdminResult) map[string]json.RawMessage {
		t.Helper()
		var data map[string]json.RawMessage
		if json.Unmarshal([]byte(result.DataJSON), &data) != nil {
			t.Fatal("invalid selected admin result")
		}
		return data
	}
	str := func(result AdminResult, key string) string {
		t.Helper()
		var value string
		if json.Unmarshal(decode(result)[key], &value) != nil || value == "" {
			t.Fatal("missing admin result field", key)
		}
		return value
	}
	params := func(mount string) map[string]any { return map[string]any{"mount": mount} }
	call("token-self", nil)
	call("token-self-renew", map[string]any{"increment": 600})
	adminToken := token
	token = createToken([]string{"default"})
	call("token-self-revoke", nil)
	if allowed, err := checkToken(ctx, c, p, token); err != nil || allowed {
		t.Fatal("caller token revocation failed")
	}
	token = adminToken
	call("token-accessors", nil)
	created := call("token-create", map[string]any{"policies": []string{"default"}, "ttl": 600, "display_name": "nexus-child"})
	accessor := str(created, "accessor")
	child := str(created, "client_token")
	call("token-lookup", map[string]any{"accessor": accessor})
	call("token-renew", map[string]any{"accessor": accessor, "increment": 300})
	call("token-revoke", map[string]any{"accessor": accessor})
	if allowed, err := checkToken(ctx, c, p, child); err != nil || allowed {
		t.Fatal("revoked child token remained usable")
	}
	read := call("policy-read", map[string]any{"name": "nexus-created"})
	call("policy-save", map[string]any{"name": "nexus-created", "revision": read.Revision, "policy": `path "nexus-kv/data/*" { capabilities = ["read"] }`})
	read = call("policy-read", map[string]any{"name": "nexus-created"})
	call("policy-delete", map[string]any{"name": "nexus-created", "revision": read.Revision})
	call("engine-enable", map[string]any{"mount": "nexus-kv", "type": "kv"})
	call("kv-config-read", params("nexus-kv"))
	call("kv-configure", map[string]any{"mount": "nexus-kv", "max_versions": 10, "cas_required": true, "delete_version_after": 0})
	call("engine-tune-read", params("nexus-kv"))
	call("engine-tune", map[string]any{"mount": "nexus-kv", "default_lease_ttl": 600, "max_lease_ttl": 3600})
	zero := 0
	for i := 0; i < 2; i++ {
		_, err := KV(ctx, c, p, "write", KVRequest{Token: token, Mount: "nexus-kv", Path: "record", Version: &zero, Data: json.RawMessage(`{"value":"fixture"}`)}, func() bool { return true })
		if err != nil {
			t.Fatal("admin KV fixture write", err)
		}
		zero++
	}
	call("kv-history", map[string]any{"mount": "nexus-kv", "path": "record"})
	call("kv-version", map[string]any{"mount": "nexus-kv", "path": "record", "version": 1})
	versions := map[string]any{"mount": "nexus-kv", "path": "record", "versions": []int{1}}
	call("kv-delete", versions)
	if _, err := Admin(ctx, c, p, "kv-version", adminFixtureInput(t, "kv-version", token, map[string]any{"mount": "nexus-kv", "path": "record", "version": 1}), nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted version still readable", err)
	}
	call("kv-undelete", versions)
	call("kv-version", map[string]any{"mount": "nexus-kv", "path": "record", "version": 1})
	call("kv-destroy", versions)
	call("kv-delete-metadata", map[string]any{"mount": "nexus-kv", "path": "record"})
	entity := call("identity-entity-save", map[string]any{"name": "nexus-entity", "policies": []string{"default"}, "disabled": false})
	entityID := str(entity, "id")
	call("identity-entity-list", nil)
	call("identity-entity-read", map[string]any{"name": "nexus-entity"})
	call("identity-entity-save", map[string]any{"name": "nexus-entity", "disabled": false})
	call("identity-group-save", map[string]any{"name": "nexus-group", "member_entity_ids": []string{entityID}})
	call("identity-group-list", nil)
	call("identity-group-read", map[string]any{"name": "nexus-group"})
	for _, family := range []string{"userpass", "approle"} {
		mount := "nexus-" + family
		call("auth-enable", map[string]any{"mount": mount, "type": family})
		call("auth-tune-read", params(mount))
		call("auth-tune", map[string]any{"mount": mount, "default_lease_ttl": 600, "max_lease_ttl": 3600})
		account := map[string]any{"mount": mount, "name": "nexus-test", "policies": []string{"default"}, "ttl": 600}
		if family == "userpass" {
			account["password"] = "generated-disposable-password"
		}
		call(family+"-save", account)
		call(family+"-list", params(mount))
		call(family+"-read", map[string]any{"mount": mount, "name": "nexus-test"})
		if family == "userpass" {
			alias := call("identity-alias-save", map[string]any{"mount": mount, "name": "nexus-test", "canonical_id": entityID})
			aliasID := str(alias, "id")
			call("identity-alias-list", nil)
			call("identity-alias-read", map[string]any{"id": aliasID})
			call("identity-alias-delete", map[string]any{"id": aliasID})
		}
		if family == "approle" {
			call("approle-role-id", map[string]any{"mount": mount, "name": "nexus-test"})
			secret := call("approle-secret-id", map[string]any{"mount": mount, "name": "nexus-test"})
			call("approle-accessors", map[string]any{"mount": mount, "name": "nexus-test"})
			call("approle-revoke-secret-id", map[string]any{"mount": mount, "name": "nexus-test", "accessor": str(secret, "secret_id_accessor")})
		}
		call(family+"-delete", map[string]any{"mount": mount, "name": "nexus-test"})
		call("auth-disable", map[string]any{"mount": mount, "expected_type": family})
	}
	call("identity-group-delete", map[string]any{"name": "nexus-group"})
	call("identity-entity-delete", map[string]any{"name": "nexus-entity"})
	call("engine-enable", map[string]any{"mount": "nexus-transit", "type": "transit"})
	for _, typ := range []string{"aes256-gcm96", "ed25519", "rsa-2048"} {
		call("transit-key-create", map[string]any{"mount": "nexus-transit", "name": typ, "type": typ})
		call("transit-keys", params("nexus-transit"))
		call("transit-key-read", map[string]any{"mount": "nexus-transit", "name": typ})
		call("transit-key-rotate", map[string]any{"mount": "nexus-transit", "name": typ})
		call("transit-key-configure", map[string]any{"mount": "nexus-transit", "name": typ, "min_decryption_version": 1, "min_encryption_version": 0, "deletion_allowed": true})
		call("transit-key-delete", map[string]any{"mount": "nexus-transit", "name": typ})
	}
	call("engine-disable", map[string]any{"mount": "nexus-transit", "expected_type": "transit"})
	call("audit-list", nil)
	call("audit-enable", map[string]any{"name": "nexus-primary"})
	if _, err := Admin(ctx, c, p, "audit-disable", adminFixtureInput(t, "audit-disable", token, map[string]any{"name": "nexus-primary"}), func() bool { return true }); !errors.Is(err, ErrConflict) {
		t.Fatal("last audit device disabled", err)
	}
	call("audit-enable", map[string]any{"name": "nexus-secondary"})
	call("audit-disable", map[string]any{"name": "nexus-secondary"})
	call("engine-enable", map[string]any{"mount": "nexus-pki", "type": "pki"})
	call("engine-tune", map[string]any{"mount": "nexus-pki", "default_lease_ttl": 3600, "max_lease_ttl": 86400})
	ca := call("pki-root-generate", map[string]any{"mount": "nexus-pki", "common_name": "Nexus fixture CA", "issuer_name": "nexus-root", "ttl": 86400})
	_ = str(ca, "certificate")
	call("pki-issuers", params("nexus-pki"))
	call("pki-issuer-read", map[string]any{"mount": "nexus-pki", "issuer": "nexus-root"})
	role := map[string]any{"mount": "nexus-pki", "name": "fixture", "allowed_domains": []string{"fixture.test"}, "allow_subdomains": true, "allow_bare_domains": true, "server_flag": true, "client_flag": false, "ttl": 600}
	call("pki-role-save", role)
	call("pki-roles", params("nexus-pki"))
	call("pki-role-read", map[string]any{"mount": "nexus-pki", "name": "fixture"})
	certificate := call("pki-issue", map[string]any{"mount": "nexus-pki", "name": "fixture", "common_name": "app.fixture.test", "ttl": 300})
	_ = str(certificate, "private_key")
	serial := str(certificate, "serial_number")
	call("pki-certificates", params("nexus-pki"))
	call("pki-certificate-read", map[string]any{"mount": "nexus-pki", "serial_number": serial})
	call("pki-revoke", map[string]any{"mount": "nexus-pki", "serial_number": serial})
	call("pki-crl-rotate", params("nexus-pki"))
	call("engine-enable", map[string]any{"mount": "nexus-intermediate", "type": "pki"})
	csr := call("pki-intermediate-generate", map[string]any{"mount": "nexus-intermediate", "common_name": "Nexus fixture intermediate"})
	signed := call("pki-intermediate-sign", map[string]any{"mount": "nexus-pki", "csr": str(csr, "csr"), "common_name": "Nexus fixture intermediate", "ttl": 3600})
	call("pki-intermediate-import", map[string]any{"mount": "nexus-intermediate", "certificate": str(signed, "certificate")})
	leafCSR := fixtureCSR(t, "signed.fixture.test")
	call("pki-sign", map[string]any{"mount": "nexus-pki", "name": "fixture", "csr": leafCSR, "common_name": "signed.fixture.test", "ttl": 300})
	// PKI supports leases with generate_lease, but those leases are explicitly
	// nonrenewable. Validate lookup/revoke and a real renewal rejection; successful
	// renew receipts are separately covered by the transport contract tests.
	request("POST", "nexus-pki/roles/fixture", root, []byte(`{"allowed_domains":["fixture.test"],"allow_subdomains":true,"generate_lease":true,"max_ttl":600}`))
	var leased struct {
		LeaseID string `json:"lease_id"`
	}
	if json.Unmarshal(request("POST", "nexus-pki/issue/fixture", root, []byte(`{"common_name":"lease.fixture.test","ttl":300}`)), &leased) != nil || leased.LeaseID == "" {
		t.Fatal("missing disposable PKI lease")
	}
	call("lease-list", nil)
	call("lease-lookup", map[string]any{"lease_id": leased.LeaseID})
	_, err := Admin(ctx, c, p, "lease-renew", adminFixtureInput(t, "lease-renew", token, map[string]any{"lease_id": leased.LeaseID, "increment": 120}), func() bool { return true })
	if !errors.Is(err, ErrConflict) {
		t.Fatal("nonrenewable lease accepted", err)
	}
	seen["lease-renew"] = true
	call("lease-revoke", map[string]any{"lease_id": leased.LeaseID})
	call("pki-role-delete", map[string]any{"mount": "nexus-pki", "name": "fixture"})
	for _, m := range []struct{ name, typ string }{{"nexus-intermediate", "pki"}, {"nexus-pki", "pki"}, {"nexus-kv", "kv"}} {
		call("engine-disable", map[string]any{"mount": m.name, "expected_type": m.typ})
	}
	for _, op := range AdminOperations() {
		if !seen[op.ID] {
			t.Error("admin fixture does not cover registered action", op.ID)
		}
	}
	t.Logf("Community administration: all %d registered policy/KV/engine/local-auth/token/lease/PKI/audit/identity/transit operations exercised with non-root authority.", len(AdminOperations()))
}
