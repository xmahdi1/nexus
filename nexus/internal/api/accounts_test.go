package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/auth"
)

func TestInvitedAccountHTTPIsolationAndDisablement(t *testing.T) {
	_, router, admin, _ := rbacFixture(t, "admin", "global", "")
	invite := policyRequest(router, admin, "POST", "/api/users/invitations", `{"username":"viewer","roleId":"viewer","scopeType":"server","scopeId":"dev","currentPassword":"RBAC fixture password"}`)
	if invite.Code != 201 {
		t.Fatalf("invite: %d %s", invite.Code, invite.Body.String())
	}
	var issued auth.InviteResult
	if err := json.Unmarshal(invite.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	// The invitation is the sole authority for identity, role and scope.
	accept := policyRequest(router, &http.Cookie{}, "POST", "/api/auth/invitations/accept", fmt.Sprintf(`{"token":%q,"password":"invited fixture password","username":"owner","roleId":"admin","scopeType":"global"}`, issued.Token))
	if accept.Code != 200 {
		t.Fatalf("accept: %d %s", accept.Code, accept.Body.String())
	}
	login := policyRequest(router, &http.Cookie{}, "POST", "/api/auth/login", `{"username":"viewer","password":"invited fixture password"}`)
	if login.Code != 200 {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session")
	}
	viewer := cookies[0]
	me := policyRequest(router, viewer, "GET", "/api/auth/me", "")
	if me.Code != 200 || !strings.Contains(me.Body.String(), issued.Invitation.UserID) || strings.Contains(me.Body.String(), "passwordHash") {
		t.Fatal("wrong or unsafe identity", me.Body.String())
	}
	list := policyRequest(router, viewer, "GET", "/api/servers", "")
	if list.Code != 200 || strings.Contains(list.Body.String(), "prod") || !strings.Contains(list.Body.String(), "name-dev") {
		t.Fatal("scope lost", list.Body.String())
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/api/servers/dev/containers/aaaaaaaaaaaa/start", 403},
		{"POST", "/api/servers/prod/containers/aaaaaaaaaaaa/start", 404},
		{"POST", "/api/users/invitations", 403},
		{"GET", "/api/users", 403},
		{"GET", "/api/auth/mfa/status", 200},
	} {
		response := policyRequest(router, viewer, tc.method, tc.path, `{}`)
		if response.Code != tc.status {
			t.Errorf("%s %s: %d", tc.method, tc.path, response.Code)
		}
	}
	var devices []auth.Session
	response := policyRequest(router, admin, "GET", "/api/auth/sessions", "")
	if err := json.Unmarshal(response.Body.Bytes(), &devices); err != nil || len(devices) != 1 {
		t.Fatal("admin devices", err)
	}
	denial := policyRequest(router, viewer, "DELETE", "/api/auth/sessions/"+devices[0].ID, "")
	if denial.Code == 200 || denial.Code == 204 {
		t.Fatal("viewer revoked owner session")
	}
	if response := policyRequest(router, admin, "GET", "/api/auth/me", ""); response.Code != 200 {
		t.Fatal("owner session affected")
	}
	disabled := policyRequest(router, admin, "PATCH", "/api/users/"+issued.Invitation.UserID, `{"status":"disabled","currentPassword":"RBAC fixture password"}`)
	if disabled.Code != 200 {
		t.Fatal("disable", disabled.Code, disabled.Body.String())
	}
	if response := policyRequest(router, viewer, "GET", "/api/auth/me", ""); response.Code != 401 {
		t.Fatal("disabled session survived", response.Code)
	}
	login = policyRequest(router, &http.Cookie{}, "POST", "/api/auth/login", `{"username":"viewer","password":"invited fixture password"}`)
	if login.Code != 401 {
		t.Fatal("disabled account logged in", login.Code)
	}
}
