package api

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/ansible"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
)

func TestAnsibleProjectHTTPScopesImmutableRevisionsAndExplicitReveal(t *testing.T) {
	database, disabled, cookie, actor := rbacFixture(t, "ansible-projects", "server", "dev")
	if r := policyRequest(disabled, cookie, "GET", "/api/servers/dev/ansible/projects", ""); r.Code != 409 {
		t.Fatal("disabled feature", r.Code)
	}
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), AutomationEnabled: true}, nil, nil)
	base := "/api/servers/dev/ansible/projects"
	response := policyRequest(router, cookie, "POST", base, `{"name":"Reviewed project"}`)
	var project ansible.Project
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &project) != nil {
		t.Fatal(response.Code, response.Body.String())
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/prod/ansible/projects", ""); r.Code != 404 {
		t.Fatal("scope ignored", r.Code)
	}
	revisions := base + "/" + project.ID + "/revisions"
	const body = `{"main":"main.yml","files":{"main.yml":"- hosts: all\n  tasks: []\n# private-code-fixture"},"variables":[]}`
	if r := policyRequest(router, cookie, "POST", revisions, body); r.Code != 404 {
		t.Fatal("missing secret-create grant ignored", r.Code)
	}
	grant := func(role string) {
		t.Helper()
		if err := database.Create(&authorization.Grant{ID: "ansible-http-" + role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	grant("admin")
	response = policyRequest(router, cookie, "POST", revisions, body)
	var revision ansible.Revision
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &revision) != nil {
		t.Fatal(response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("private-code-fixture")) || bytes.Contains(response.Body.Bytes(), []byte("bundleEnc")) {
		t.Fatal("revision metadata leaked content")
	}
	content := revisions + "/" + revision.ID + "/content"
	if r := policyRequest(router, cookie, "POST", content, "{}"); r.Code != 403 {
		t.Fatal("implicit code reveal", r.Code)
	}
	grant("secret-reader")
	if r := policyRequest(router, cookie, "POST", content, "{}"); r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte("private-code-fixture")) {
		t.Fatal("explicit reveal unavailable", r.Code)
	}
	if r := policyRequest(router, cookie, "PUT", revisions+"/"+revision.ID, body); r.Code != 403 {
		t.Fatal("revision overwrite admitted", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", base+"/"+project.ID+"/archive", "{}"); r.Code != 204 {
		t.Fatal("archive failed", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", revisions, body); r.Code != 409 {
		t.Fatal("archived project edited", r.Code)
	}
}
