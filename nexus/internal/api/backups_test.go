package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/backups"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestBackupHTTPScopesPrivateMetadataAndStructuredHistory(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	key := bytes.Repeat([]byte{9}, 32)
	cfg := &config.Config{EncryptionKey: key, BackupsEnabled: true, OperationSupervisionEnabled: true}
	router := NewRouter(database, cfg, nil, nil)
	serverBase := "/api/servers/dev/backups"
	localBase := "/api/backups/nexus"
	if r := policyRequest(router, cookie, "GET", serverBase+"/policies", ""); r.Code != 403 {
		t.Fatal("implicit admin backup permission", r.Code)
	}
	grant := func(id, role, scope, scopeID string) {
		t.Helper()
		if err := database.Create(&authorization.Grant{ID: id, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: scope, ScopeID: scopeID, CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	grant("backup-http-scoped", "backup-administrator", "server", "dev")
	if r := policyRequest(router, cookie, "GET", serverBase+"/policies", ""); r.Code != 200 {
		t.Fatal("scoped backup list", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", "/api/servers/prod/backups/policies", ""); r.Code != 404 {
		t.Fatal("cross-server backup disclosure", r.Code)
	}
	grant("backup-http-wrong-scope", "nexus-backup-administrator", "server", "dev")
	if r := policyRequest(router, cookie, "GET", localBase+"/policies", ""); r.Code != 403 {
		t.Fatal("server-scoped role accessed Nexus recovery", r.Code)
	}
	grant("backup-http-global", "nexus-backup-administrator", "global", "")
	input := map[string]any{"requestId": strings.Repeat("a", 32), "definition": backups.Definition{Name: "Nexus recovery", Repository: backups.Repository{Kind: "local", Location: "/owned-fixture-repository", Password: "private-fixture-repository-password"}, Sources: []backups.Source{{Kind: "nexus", Label: "Nexus recovery data"}}, Timing: backups.Timing{Mode: "manual"}, RuntimeSeconds: 60}}
	body, _ := json.Marshal(input)
	response := policyRequest(router, cookie, "POST", localBase+"/policies", string(body))
	var policy backups.PolicyView
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &policy) != nil {
		t.Fatal(response.Code, response.Body.String())
	}
	settingsPath := localBase + "/policies/" + policy.ID + "/settings"
	if r := policyRequest(router, cookie, "PUT", settingsPath, `{"keepLast":3,"maxAgeMinutes":60,"verifyAfterDays":14}`); r.Code != 204 {
		t.Fatal("backup settings save", r.Code, r.Body.String())
	}
	if r := policyRequest(router, cookie, "PUT", settingsPath, `{"keepLast":0,"maxAgeMinutes":60,"verifyAfterDays":14}`); r.Code != 400 {
		t.Fatal("zero-retention accepted", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", localBase+"/health", ""); r.Code != 200 || strings.Contains(r.Body.String(), "private-fixture-repository-password") {
		t.Fatal("health missing or leaked credentials", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", localBase+"/coverage", `{"path":"","watchGaps":true}`); r.Code != 200 {
		t.Fatal("local coverage missing", r.Code, r.Body.String())
	}
	if r := policyRequest(router, cookie, "POST", localBase+"/policies/"+policy.ID+"/runs", `{"requestId":"`+strings.Repeat("d", 32)+`","action":"retention-apply","previewRunId":"`+strings.Repeat("e", 32)+`"}`); r.Code != 403 {
		t.Fatal("backup admin implicitly received deletion permission", r.Code)
	}
	if strings.Contains(response.Body.String(), "private-fixture") || strings.Contains(response.Body.String(), "configEnc") || strings.Contains(response.Body.String(), `"password"`) {
		t.Fatal("policy metadata leaked credentials")
	}
	if r := policyRequest(router, cookie, "POST", localBase+"/policies/"+policy.ID+"/runs", `{"requestId":"`+strings.Repeat("b", 32)+`","action":"backup","command":"forbidden"}`); r.Code != 400 {
		t.Fatal("caller command accepted", r.Code)
	}
	now := time.Now().UTC()
	id := strings.Repeat("c", 32)
	code := 0
	output := `{"state":"completed","snapshotId":"` + strings.Repeat("f", 64) + `","files":2,"bytes":321,"verified":false}`
	encrypted, err := nexuscrypto.EncryptJobOutput(key, id, backups.LocalHost, []byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.SupervisedRun{ID: id, TaskID: policy.ID, ServerID: backups.LocalHost, ActorID: actor, Kind: "scheduled", Action: "backup:backup", State: "exited", OutputEnc: encrypted, ExitCode: &code, CreatedAt: now, FinishedAt: &now, VerifiedAt: &now, ArtifactsRemoved: true}).Error; err != nil {
		t.Fatal(err)
	}
	database.Exec("INSERT INTO backup_run_cleanup(run_id,cleaned)VALUES(?,1)", id)
	response = policyRequest(router, cookie, "POST", localBase+"/runs/"+id+"/inspect", "")
	var observed struct {
		Result      *backups.Result `json:"result"`
		Observation struct {
			Output string `json:"output"`
		} `json:"observation"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &observed) != nil || observed.Result == nil || observed.Result.Files != 2 || observed.Observation.Output != "" {
		t.Fatal("structured history unavailable", response.Code, response.Body.String())
	}
	if r := policyRequest(router, cookie, "GET", localBase+"/runs", ""); r.Code != 200 || strings.Contains(r.Body.String(), "outputEnc") || strings.Contains(r.Body.String(), "commandHash") {
		t.Fatal("run metadata unavailable or leaked", r.Code)
	}
	database.Where("id=?", "backup-http-global").Delete(&authorization.Grant{})
	if r := policyRequest(router, cookie, "POST", localBase+"/runs/"+id+"/inspect", ""); r.Code != 403 {
		t.Fatal("history survived global-role revocation", r.Code)
	}
}

func TestBackupReaderCanSeeHealthWithoutJobOrMutationPermissions(t *testing.T) {
	database, _, cookie, _ := rbacFixture(t, "backup-reader", "server", "dev")
	router := NewRouter(database, &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32), BackupsEnabled: true}, nil, nil)
	if r := policyRequest(router, cookie, "GET", "/api/servers/dev/backups/health", ""); r.Code != 200 {
		t.Fatal("reader could not see health", r.Code)
	}
	if r := policyRequest(router, cookie, "PUT", "/api/servers/dev/backups/policies/"+strings.Repeat("a", 32)+"/settings", `{"keepLast":7,"maxAgeMinutes":60,"verifyAfterDays":30}`); r.Code != 403 {
		t.Fatal("reader changed settings", r.Code)
	}
	if r := policyRequest(router, cookie, "GET", "/api/backups/nexus/health", ""); r.Code != 403 {
		t.Fatal("server reader accessed local recovery health", r.Code)
	}
}
