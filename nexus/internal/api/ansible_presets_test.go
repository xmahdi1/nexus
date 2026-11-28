package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/ansible"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestAnsiblePresetHTTPUsesFreshInputsAndExplicitReveal(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	key := bytes.Repeat([]byte{9}, 32)
	cfg := &config.Config{EncryptionKey: key, AutomationEnabled: true, OperationSupervisionEnabled: true}
	router := NewRouter(database, cfg, nil, nil)
	base := "/api/servers/dev/ansible/presets"
	if r := policyRequest(router, cookie, "GET", base, ""); r.Code != 403 {
		t.Fatal("implicit preset role", r.Code)
	}
	for _, role := range []string{"admin", "log-reader", "ansible-projects", "ansible-executor", "ansible-inventory", "ansible-environment", "secret-reader"} {
		if err := database.Create(&authorization.Grant{ID: "preset-http-" + role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "global", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range []string{"dev", "prod"} {
		sealed, err := nexuscrypto.Encrypt(key, []byte("fixture-key-"+id))
		if err != nil {
			t.Fatal(err)
		}
		if err := database.Model(&models.Server{}).Where("id=?", id).Updates(map[string]any{"port": 22, "username": "root", "private_key_enc": sealed, "known_host_key": "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32))}).Error; err != nil {
			t.Fatal(err)
		}
	}
	database.Exec("INSERT INTO server_groups(id,name,created_at)VALUES('targets','Targets',CURRENT_TIMESTAMP);INSERT INTO server_group_members(group_id,server_id)VALUES('targets','prod')")
	sessions := auth.NewService(database, cfg)
	a, err := sessions.Authenticate(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	service := &ansible.Service{DB: database, Key: key, Sessions: sessions, Enabled: true}
	project, err := service.CreateProject(a, "dev", "HTTP preset")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := service.CreateRevision(a, "dev", project.ID, ansible.Bundle{Main: "main.yml", Files: map[string]string{"main.yml": "- hosts: all\n  tasks: []"}, Variables: []ansible.Variable{{Name: "message", Kind: "string", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.Prepare(a, "dev", project.ID, ansible.PlanRequest{RevisionID: revision.ID, RevisionDigest: revision.Digest, GroupID: "targets", ServerIDs: []string{"prod"}, Variables: map[string]any{"message": "private-old-value"}, Options: ansible.Options{Mode: "check", TimeoutSeconds: 60}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"name": "Repeat checks", "planId": plan.ID})
	response := policyRequest(router, cookie, "POST", base, string(body))
	var preset ansible.Preset
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &preset) != nil {
		t.Fatal(response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "private-old-value") || strings.Contains(response.Body.String(), "configEnc") {
		t.Fatal("values leaked")
	}
	if r := policyRequest(router, cookie, "POST", base+"/"+preset.ID+"/prepare", `{"variables":{}}`); r.Code != 400 {
		t.Fatal("saved variable reused", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", base+"/"+preset.ID+"/prepare", `{"variables":{"message":"fresh"},"approvedBy":"owner"}`); r.Code != 400 {
		t.Fatal("caller authority accepted", r.Code)
	}
	response = policyRequest(router, cookie, "POST", base+"/"+preset.ID+"/prepare", `{"variables":{"message":"fresh"}}`)
	var fresh ansible.PlanView
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &fresh) != nil || fresh.PresetID != preset.ID || fresh.State != "prepared" || fresh.ApprovedBy != "" {
		t.Fatal(response.Code, response.Body.String())
	}
	queueBase := "/api/servers/dev/ansible"
	if q := policyRequest(router, cookie, "POST", queueBase+"/plans/"+fresh.ID+"/queue", `{"requestId":"`+strings.Repeat("d", 32)+`"}`); q.Code != 403 {
		t.Fatal("unapproved plan queued", q.Code)
	}
	invite, err := sessions.CreateInvitation(a, auth.InviteOptions{Username: "queue-reviewer", RoleID: "ansible-approver", ScopeType: "global"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.AcceptInvitation(invite.Token, "Queue reviewer password"); err != nil {
		t.Fatal(err)
	}
	login, err := sessions.Login("queue-reviewer", "Queue reviewer password", "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := sessions.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"viewer", "secret-reader"} {
		if err := database.Create(&authorization.Grant{ID: "queue-reviewer-" + role, PrincipalID: reviewer.User.ID, PrincipalKind: "user", RoleID: role, ScopeType: "global", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, err = service.Approve(reviewer, "dev", fresh.ID, fresh.Digest, revision.Digest); err != nil {
		t.Fatal(err)
	}
	queueID := strings.Repeat("d", 32)
	for i := 0; i < 2; i++ {
		if q := policyRequest(router, cookie, "POST", queueBase+"/plans/"+fresh.ID+"/queue", `{"requestId":"`+queueID+`"}`); q.Code != 202 {
			t.Fatal("queue create/repeated identity", q.Code, q.Body.String())
		}
	}
	if q := policyRequest(router, cookie, "POST", queueBase+"/plans/"+fresh.ID+"/run", `{"requestId":"`+strings.Repeat("e", 32)+`","vaultTokens":{}}`); q.Code != 409 {
		t.Fatal("manual execution bypassed queue", q.Code)
	}
	if q := policyRequest(router, cookie, "POST", queueBase+"/queue/"+queueID+"/cancel", ""); q.Code != 204 {
		t.Fatal("queue cancellation failed", q.Code)
	}
	scheduleBody := `{"name":"Daily review","planId":"` + fresh.ID + `","intervalMinutes":1440}`
	if q := policyRequest(router, cookie, "POST", queueBase+"/schedules", scheduleBody); q.Code != 403 {
		t.Fatal("implicit scheduling authority", q.Code)
	}
	if err := database.Create(&authorization.Grant{ID: "queue-http-scheduler", PrincipalID: actor, PrincipalKind: "user", RoleID: "ansible-scheduler", ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	q := policyRequest(router, cookie, "POST", queueBase+"/schedules", scheduleBody)
	if q.Code != 201 || strings.Contains(q.Body.String(), "configEnc") || strings.Contains(q.Body.String(), "sourceSessionId") {
		t.Fatal("schedule failed or leaked context", q.Code, q.Body.String())
	}
	now := time.Now().UTC()
	output := `{"state":"playbook_exited","version":"2.22.0","exitCode":0,"hosts":{"prod":{"ok":1,"changed":0,"failures":0,"unreachable":0,"skipped":0,"rescued":0,"ignored":0}},"tasks":[{"task":1,"serverId":"prod","status":"ok","startedMs":0,"durationMs":12}],"tasksTruncated":false}`
	runID := strings.Repeat("c", 32)
	protected, err := nexuscrypto.EncryptJobOutput(key, runID, "dev", []byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.SupervisedRun{ID: runID, ServerID: "dev", ActorID: actor, Kind: "ansible", Action: "ansible-playbook", OperationContext: fresh.ID, State: "exited", OutputEnc: protected, CreatedAt: now, FinishedAt: &now, VerifiedAt: &now, ArtifactsRemoved: true}).Error; err != nil {
		t.Fatal(err)
	}
	inspect := "/api/servers/dev/ansible/runs/" + runID + "/inspect"
	response = policyRequest(router, cookie, "POST", inspect, "")
	var inspected struct {
		Result      *ansible.ExecutionResult `json:"result"`
		Observation struct {
			Output string `json:"output"`
		} `json:"observation"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &inspected) != nil || inspected.Result == nil || len(inspected.Result.Tasks) != 1 || inspected.Observation.Output != "" {
		t.Fatal("retained numeric history unavailable", response.Code, response.Body.String())
	}
	database.Where("id=?", "preset-http-secret-reader").Delete(&authorization.Grant{})
	if r := policyRequest(router, cookie, "POST", base+"/"+preset.ID+"/content", ""); r.Code != 403 {
		t.Fatal("implicit reveal", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", base, ""); r.Code != 200 || strings.Contains(r.Body.String(), "private-old-value") {
		t.Fatal("metadata unavailable or leaked", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", base+"/"+preset.ID+"/archive", ""); r.Code != 204 {
		t.Fatal("archive failed", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", base+"/"+preset.ID+"/prepare", `{"variables":{"message":"fresh"}}`); r.Code != 404 {
		t.Fatal("archived preset reused", r.Code)
	}
	if err := database.Where("id=?", "preset-http-admin").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Model(&authorization.Grant{}).Where("principal_id=? AND scope_type='global'", actor).Updates(map[string]any{"scope_type": "server", "scope_id": "dev"}).Error; err != nil {
		t.Fatal(err)
	}
	if r := policyRequest(router, cookie, "POST", inspect, ""); r.Code != 403 {
		t.Fatal("history survived target access revocation", r.Code)
	}

}
