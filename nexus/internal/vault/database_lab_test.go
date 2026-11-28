package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// This helper runs only after the parent fixture verifies its Vault container,
// loopback listener and TLS CA. Database configuration is fixture bootstrap;
// the production UI still exposes only its supported finite operation catalog.
func testDisposableDatabaseLease(t *testing.T, ctx context.Context, c *http.Client, p Profile, root string, request func(string, string, string, []byte) []byte, createToken func([]string) string) {
	t.Helper()
	id := os.Getenv("NEXUS_VAULT_LAB_PG_CONTAINER")
	password := os.Getenv("NEXUS_VAULT_LAB_PG_PASSWORD")
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(password) {
		t.Fatal("owned PostgreSQL backend required")
	}
	label, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "inspect", "--format", `{{index .Config.Labels "nexus.vault-lab"}}`, id).Output()
	if err != nil || strings.TrimSpace(string(label)) != os.Getenv("NEXUS_VAULT_LAB_NONCE") {
		t.Fatal("database fixture ownership mismatch")
	}
	post := func(path string, body any) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal("invalid database setup")
		}
		defer clear(data)
		result := request("POST", path, root, data)
		clear(result)
	}
	post("sys/mounts/nexus-database", map[string]any{"type": "database"})
	defer func() { result := request("DELETE", "sys/mounts/nexus-database", root, nil); clear(result) }()
	post("nexus-database/config/fixture", map[string]any{
		"plugin_name": "postgresql-database-plugin", "allowed_roles": []string{"fixture"},
		"connection_url": "postgresql://{{username}}:{{password}}@postgres.fixture:5432/fixture?sslmode=verify-full&sslrootcert=/vault/tls/ca.pem",
		"username":       "fixture_admin", "password": password, "verify_connection": true,
	})
	post("nexus-database/roles/fixture", map[string]any{"db_name": "fixture", "default_ttl": 5, "max_ttl": 180, "creation_statements": []string{`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE fixture TO "{{name}}";`}})
	post("sys/policies/acl/nexus-database-test", map[string]string{"policy": `path "nexus-database/creds/fixture" { capabilities = ["read"] }
path "sys/leases/lookup" { capabilities = ["update"] }
path "sys/leases/lookup/nexus-database/creds/fixture" { capabilities = ["list","sudo"] }
path "sys/leases/renew" { capabilities = ["update"] }
path "sys/leases/revoke" { capabilities = ["update","sudo"] }`})
	token := createToken([]string{"nexus-database-test"})
	type credential struct {
		LeaseID       string `json:"lease_id"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		Data          struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	issue := func() credential {
		t.Helper()
		var value credential
		raw := request("GET", "nexus-database/creds/fixture", token, nil)
		err := json.Unmarshal(raw, &value)
		clear(raw)
		if err != nil || !value.Renewable || value.LeaseDuration != 5 || value.LeaseID == "" || value.Data.Username == "" || value.Data.Password == "" || strings.ContainsAny(value.Data.Username+value.Data.Password, "\r\n") {
			t.Fatal("renewable database credential was not issued")
		}
		return value
	}
	issued := issue()
	unrenewed := issue()
	originalExpiry := time.Now().Add(time.Duration(unrenewed.LeaseDuration)*time.Second + 2*time.Second)
	connect := func(username, password string) bool {
		// Neither password nor username goes on argv or into printed diagnostics.
		// A fresh connection is required: revocation does not retroactively undo
		// work or necessarily terminate an already established DB session.
		command := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "exec", "-i", id, "sh", "-c", `IFS= read -r PGUSER; IFS= read -r PGPASSWORD; export PGUSER PGPASSWORD PGHOST=postgres.fixture PGDATABASE=fixture PGSSLMODE=verify-full PGSSLROOTCERT=/tmp/tls/ca.pem PGCONNECT_TIMEOUT=3; exec psql -X -w -tAc 'SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl'`)
		credentials := []byte(username + "\n" + password + "\n")
		defer clear(credentials)
		command.Stdin = bytes.NewReader(credentials)
		output, err := command.Output()
		defer clear(output)
		return err == nil && strings.TrimSpace(string(output)) == "1"
	}
	if !connect(issued.Data.Username, issued.Data.Password) || !connect(unrenewed.Data.Username, unrenewed.Data.Password) {
		t.Fatal("issued credential could not open a verified TLS database connection")
	}
	admin := func(action string, params map[string]any) AdminResult {
		t.Helper()
		result, err := Admin(ctx, c, p, action, adminFixtureInput(t, action, token, params), func() bool { return true })
		if err != nil {
			t.Fatal("database lease action failed", action, err)
		}
		return result
	}
	lease := map[string]any{"lease_id": issued.LeaseID}
	listed := admin("lease-list", map[string]any{"prefix": "nexus-database/creds/fixture"})
	if !strings.Contains(listed.DataJSON, strings.TrimPrefix(issued.LeaseID, "nexus-database/creds/fixture/")) {
		t.Fatal("database lease listing omitted credential")
	}
	admin("lease-lookup", lease)
	renew := map[string]any{"lease_id": issued.LeaseID, "increment": 120}
	if _, err := Admin(ctx, c, p, "lease-renew", adminFixtureInput(t, "lease-renew", token, renew), func() bool { return false }); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked operation authority renewed lease", err)
	}
	receipt := admin("lease-renew", renew)
	var renewed struct {
		ID        string `json:"lease_id"`
		Duration  int    `json:"lease_duration"`
		Renewable bool   `json:"renewable"`
	}
	if json.Unmarshal([]byte(receipt.DataJSON), &renewed) != nil || renewed.ID != issued.LeaseID || renewed.Duration < 60 || !renewed.Renewable {
		t.Fatal("renewal receipt lost lease identity or duration")
	}
	timer := time.NewTimer(time.Until(originalExpiry))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("fixture deadline before original expiry")
	}
	if connect(unrenewed.Data.Username, unrenewed.Data.Password) {
		t.Fatal("unrenewed control credential remained usable past expiry")
	}
	if !connect(issued.Data.Username, issued.Data.Password) {
		t.Fatal("renewal did not extend backend credential beyond original expiry")
	}
	admin("lease-revoke", lease)
	if connect(issued.Data.Username, issued.Data.Password) {
		t.Fatal("revoked database credential still opened a new connection")
	}
	if !connect("fixture_admin", password) {
		t.Fatal("database control connection failed; credential rejection is inconclusive")
	}
	if _, err := Admin(ctx, c, p, "lease-lookup", adminFixtureInput(t, "lease-lookup", token, lease), nil); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked lease absence was not verified", err)
	}
	issued.Data.Password = ""
	issued.Data.Username = ""
	t.Log("Real PostgreSQL dynamic credential: non-root lease list/lookup/renew, verified TLS login after original expiry, synchronous revocation and fresh-login rejection passed.")
}
