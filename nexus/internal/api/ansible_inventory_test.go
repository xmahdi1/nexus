package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/automation"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestAnsibleInventoryRealAdapter(t *testing.T) {
	binary := os.Getenv("NEXUS_ANSIBLE_INVENTORY_BIN")
	if binary == "" {
		t.Skip("set NEXUS_ANSIBLE_INVENTORY_BIN to validate with real ansible-inventory")
	}
	database, _, cookie, _ := rbacFixture(t, "ansible-inventory", "server", "dev")
	for _, sql := range []string{"INSERT INTO server_groups(id,name,created_at) VALUES('automation','Build',CURRENT_TIMESTAMP)", "INSERT INTO server_group_members(group_id,server_id) VALUES('automation','dev')"} {
		if err := database.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	res := policyRequest(router, cookie, "POST", "/api/automation/ansible/tokens", `{"groupId":"automation","ttlSeconds":300}`)
	var row struct{ Token string }
	if res.Code != 201 || json.Unmarshal(res.Body.Bytes(), &row) != nil {
		t.Fatal("issue", res.Code)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(row.Token), 0600); err != nil {
		t.Fatal(err)
	}
	adapter, err := filepath.Abs("../../../integrations/ansible/nexus_inventory.py")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(binary, append([]string{"-i", adapter}, args...)...)
		cmd.Env = append(os.Environ(), "NEXUS_URL="+server.URL, "NEXUS_INVENTORY_TOKEN_FILE="+file, "ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED=true", "ANSIBLE_NOCOLOR=1")
		return cmd.CombinedOutput()
	}
	list, err := run("--list")
	if err != nil || !bytes.Contains(list, []byte("192.0.2.10")) || bytes.Contains(list, []byte("192.0.2.20")) {
		t.Fatalf("real inventory failed: %v %s", err, list)
	}
	graph, err := run("--graph")
	if err != nil || !bytes.Contains(graph, []byte(automation.Alias("host", "dev"))) {
		t.Fatalf("real graph failed: %v %s", err, graph)
	}
	if err := database.Model(&models.Server{}).Where("id='dev'").Update("host", "192.0.2.30").Error; err != nil {
		t.Fatal(err)
	}
	list, err = run("--list")
	if err != nil || !bytes.Contains(list, []byte("192.0.2.30")) || bytes.Contains(list, []byte("192.0.2.10")) {
		t.Fatal("adapter cached stale host", err)
	}
	if err := database.Exec("DELETE FROM role_grants WHERE id='fixture-role'").Error; err != nil {
		t.Fatal(err)
	}
	list, err = run("--list")
	if err == nil || bytes.Contains(list, []byte("192.0.2.30")) || bytes.Contains(list, []byte(row.Token)) {
		t.Fatal("real Ansible reused revoked inventory or leaked token")
	}
}

func TestAnsibleInventoryScopeRefreshAndCredentialSeparation(t *testing.T) {
	database, disabled, cookie, actor := rbacFixture(t, "ansible-inventory", "server", "dev")
	for _, sql := range []string{
		"INSERT INTO server_groups(id,name,created_at) VALUES('automation','Build hosts',CURRENT_TIMESTAMP)",
		"INSERT INTO server_group_members(group_id,server_id) VALUES('automation','dev'),('automation','prod')",
		"UPDATE servers SET tags='a-b,a_b,a-b' WHERE id='dev'",
	} {
		if err := database.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	if r := policyRequest(disabled, cookie, "GET", "/api/automation/ansible/preview?groupId=automation", ""); r.Code != 404 {
		t.Fatal("disabled feature", r.Code)
	}
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	preview := policyRequest(router, cookie, "GET", "/api/automation/ansible/preview?groupId=automation", "")
	if preview.Code != 200 {
		t.Fatal(preview.Code, preview.Body.String())
	}
	var p automation.Preview
	if json.Unmarshal(preview.Body.Bytes(), &p) != nil || len(p.Groups) != 3 {
		t.Fatal("collision or duplicate tags", preview.Body.String())
	}
	issue := policyRequest(router, cookie, "POST", "/api/automation/ansible/tokens", `{"groupId":"automation","ttlSeconds":900}`)
	var minted struct{ ID, Token string }
	if issue.Code != 201 || json.Unmarshal(issue.Body.Bytes(), &minted) != nil || minted.Token == "" {
		t.Fatal("issue", issue.Code, issue.Body.String())
	}
	request := func(path string) *httptest.ResponseRecorder {
		req := secureTestRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+minted.Token)
		r := httptest.NewRecorder()
		router.ServeHTTP(r, req)
		return r
	}
	base := "/api/automation/ansible/inventory"
	read := request(base)
	if read.Code != 200 || strings.Contains(read.Body.String(), "prod") || !strings.Contains(read.Body.String(), "192.0.2.10") {
		t.Fatal("cross-scope leak", read.Code, read.Body.String())
	}
	for _, bad := range []string{"privateKey", "knownHostKey", "password", "token", "ansible_connection", "Build hosts", "a-b"} {
		if strings.Contains(read.Body.String(), bad) {
			t.Fatal("unsafe metadata", bad)
		}
	}
	if r := request("/api/servers"); r.Code != 401 {
		t.Fatal("inventory token authenticated management API", r.Code)
	}
	if r := request(base + "?groupId=other"); r.Code != 400 {
		t.Fatal("token scope overridden", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", base, ""); r.Code != 401 {
		t.Fatal("login cookie exported machine inventory", r.Code)
	}
	var rows []automation.InventoryToken
	database.Find(&rows)
	if len(rows) != 1 || rows[0].TokenHash == minted.Token || strings.Contains(rows[0].TokenHash, minted.Token) {
		t.Fatal("plaintext credential persisted")
	}
	if r := policyRequest(router, cookie, "GET", "/api/automation/ansible/tokens", ""); strings.Contains(r.Body.String(), minted.Token) || strings.Contains(r.Body.String(), "tokenHash") {
		t.Fatal("token relisted")
	}
	if err := database.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"host": "2001:db8::10", "port": 2222}).Error; err != nil {
		t.Fatal(err)
	}
	if r := request(base); r.Code != 200 || !strings.Contains(r.Body.String(), "2001:db8::10") || !strings.Contains(r.Body.String(), "2222") {
		t.Fatal("stale address", r.Body.String())
	}
	if err := database.Create(&authorization.Grant{ID: "new", PrincipalID: actor, PrincipalKind: "user", RoleID: "ansible-inventory", ScopeType: "server", ScopeID: "prod", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if r := request(base); r.Code != 200 || !strings.Contains(r.Body.String(), "192.0.2.20") {
		t.Fatal("added authorized host missing")
	}
	if err := database.Where("id='new'").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if r := request(base); r.Code != 200 || strings.Contains(r.Body.String(), "192.0.2.20") {
		t.Fatal("revoked host cached")
	}
	for _, change := range []map[string]any{{"host": "{{lookup('pipe','id')}}"}, {"username": "-oProxyCommand=id"}, {"tags": "{{lookup('pipe','id')}}"}, {"port": 65536}} {
		if err := database.Model(&models.Server{}).Where("id='dev'").Updates(change).Error; err != nil {
			t.Fatal(err)
		}
		if r := request(base); r.Code != 422 {
			t.Fatal("malicious metadata accepted", change, r.Code)
		}
		if err := database.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"host": "192.0.2.10", "username": "fixture", "tags": "", "port": 22}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if r := policyRequest(router, cookie, "DELETE", "/api/automation/ansible/tokens/"+minted.ID, ""); r.Code != 204 {
		t.Fatal("revoke", r.Code)
	}
	if r := request(base); r.Code != 401 {
		t.Fatal("revoked credential usable", r.Code)
	}
}

func TestAnsibleInventoryExpiryLogoutAndMembershipFailClosed(t *testing.T) {
	for _, reason := range []string{"expiry", "logout", "grant", "membership", "server"} {
		t.Run(reason, func(t *testing.T) {
			database, _, cookie, _ := rbacFixture(t, "ansible-inventory", "server", "dev")
			for _, sql := range []string{"INSERT INTO server_groups(id,name,created_at) VALUES('automation','Build',CURRENT_TIMESTAMP)", "INSERT INTO server_group_members(group_id,server_id) VALUES('automation','dev')"} {
				if err := database.Exec(sql).Error; err != nil {
					t.Fatal(err)
				}
			}
			router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
			r := policyRequest(router, cookie, "POST", "/api/automation/ansible/tokens", `{"groupId":"automation","ttlSeconds":60}`)
			var row struct{ Token string }
			if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &row) != nil {
				t.Fatal("issue", r.Code)
			}
			switch reason {
			case "expiry":
				database.Model(&automation.InventoryToken{}).Where("1=1").Update("expires_at", time.Now().UTC().Add(-time.Second))
			case "logout":
				if r := policyRequest(router, cookie, "POST", "/api/auth/logout", ""); r.Code != 200 {
					t.Fatal("logout", r.Code)
				}
			case "grant":
				database.Exec("DELETE FROM role_grants WHERE id='fixture-role'")
			case "membership":
				database.Exec("DELETE FROM server_group_members WHERE server_id='dev'")
			case "server":
				database.Delete(&models.Server{}, "id='dev'")
			}
			req := secureTestRequest(http.MethodGet, "/api/automation/ansible/inventory", nil)
			req.Header.Set("Authorization", "Bearer "+row.Token)
			res := httptest.NewRecorder()
			router.ServeHTTP(res, req)
			if res.Code != 401 && res.Code != 403 {
				t.Fatal("authority loss ignored", reason, res.Code)
			}
		})
	}
}
