package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestSupervisedRunOutputScopeAuditAndCancellationSeparation(t *testing.T) {
	database, router, cookie, actor := rbacFixture(t, "admin", "global", "")
	for _, role := range []string{"host-control", "log-reader"} {
		if err := database.Create(&authorization.Grant{ID: role, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: "global", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	task := models.ScheduledTask{ID: "task", ServerID: "dev", ActorID: actor, Command: "fixture", Supervised: true, Enabled: true, LastStatus: "pending"}
	if err := database.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	run := models.SupervisedRun{ID: strings.Repeat("a", 32), ServerID: "dev", TaskID: task.ID, ActorID: actor, CommandHash: jobsupervisor.Digest("fixture"), State: "prepared", CreatedAt: time.Now().UTC()}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	service := jobsupervisor.NewService(database, key, nil)
	code := 0
	const output = "private supervised output fixture"
	if err := service.Save(run, jobsupervisor.Snapshot{State: "exited", Verified: true, Empty: true, ExitCode: &code, Output: output, InvocationID: strings.Repeat("b", 32)}); err != nil {
		t.Fatal(err)
	}
	prefix := "/api/servers/dev/tasks/task/runs/" + run.ID
	list := policyRequest(router, cookie, "GET", "/api/servers/dev/tasks/task/runs", "")
	if list.Code != 200 || strings.Contains(list.Body.String(), output) || strings.Contains(list.Body.String(), "outputEnc") {
		t.Fatal("run metadata leaked output", list.Code, list.Body.String())
	}
	read := policyRequest(router, cookie, "GET", prefix, "")
	if read.Code != 200 || !strings.Contains(read.Body.String(), output) || read.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authorized output unavailable", read.Code, read.Body.String())
	}
	var stored models.SupervisedRun
	database.First(&stored, "id=?", run.ID)
	if stored.OutputEnc == "" || strings.Contains(stored.OutputEnc, output) {
		t.Fatal("output not encrypted")
	}
	if _, err := nexuscrypto.DecryptJobOutput(key, run.ID, "prod", stored.OutputEnc); err == nil {
		t.Fatal("output not bound to server")
	}
	for _, path := range []string{strings.Replace(prefix, "/dev/", "/prod/", 1), strings.Replace(prefix, "/task/", "/missing/", 1)} {
		if response := policyRequest(router, cookie, "GET", path, ""); response.Code != 404 {
			t.Fatal("cross-resource run lookup", response.Code, response.Body.String())
		}
	}
	if err := database.Where("id=?", "log-reader").Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	if response := policyRequest(router, cookie, "GET", prefix, ""); response.Code != 403 {
		t.Fatal("output permission not enforced")
	}
	cancelled := policyRequest(router, cookie, "POST", prefix+"/cancel", `{}`)
	if cancelled.Code != 200 || strings.Contains(cancelled.Body.String(), output) {
		t.Fatal("cancel authority leaked logs", cancelled.Code, cancelled.Body.String())
	}
	var body struct {
		AutomaticRetryAllowed bool `json:"automaticRetryAllowed"`
	}
	if json.Unmarshal(cancelled.Body.Bytes(), &body) != nil || body.AutomaticRetryAllowed {
		t.Fatal("inspection authorized command replay")
	}
	database.First(&task, "id=?", task.ID)
	if !task.Enabled {
		t.Fatal("cancel of historical terminal run paused unrelated schedule")
	}
	var events []audit.Event
	database.Find(&events)
	foundRun := false
	for _, event := range events {
		if event.ResourceType == "job_run" && event.ResourceID == run.ID {
			foundRun = true
		}
	}
	if !foundRun {
		t.Fatal("run resource identity missing from audit")
	}
	encoded, _ := json.Marshal(events)
	if bytes.Contains(encoded, []byte(output)) {
		t.Fatal("output leaked into audit")
	}
}

func TestUnresolvedSupervisedRunsBlockReplayAndRemoval(t *testing.T) {
	database, router, cookie, actor := rbacFixture(t, "admin", "global", "")
	if err := database.Create(&authorization.Grant{ID: "host", PrincipalID: actor, PrincipalKind: "user", RoleID: "host-control", ScopeType: "global", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	task := models.ScheduledTask{ID: "task", ServerID: "dev", ActorID: actor, Command: "fixture", Supervised: true, RunID: strings.Repeat("a", 32), LastStatus: "remote_unknown"}
	if err := database.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.SupervisedRun{ID: task.RunID, ServerID: "dev", TaskID: task.ID, ActorID: actor, CommandHash: jobsupervisor.Digest(task.Command), State: "unknown", CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, path, body string }{{"POST", "/api/servers/dev/tasks/task/run", `{}`}, {"DELETE", "/api/servers/dev/tasks/task", ``}, {"PUT", "/api/servers/dev/tasks/task", `{"enabled":true}`}, {"DELETE", "/api/servers/dev", ``}} {
		response := policyRequest(router, cookie, request.method, request.path, request.body)
		if response.Code != 409 {
			t.Fatal("unresolved run bypassed guard", request.path, response.Code, response.Body.String())
		}
	}
	response := policyRequest(router, cookie, "POST", "/api/servers/dev/tasks", `{"command":"fixture","supervised":true}`)
	if response.Code != 409 {
		t.Fatal("disabled feature accepted supervised launch", response.Code, response.Body.String())
	}
}
