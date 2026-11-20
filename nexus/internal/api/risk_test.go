package api

import (
	"bytes"
	"github.com/pquerna/otp/totp"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProtectedGroupRequiresFreshMFAAndCannotBeRemovedToBypass(t *testing.T) {
	database, router, cookie, _ := rbacFixture(t, "admin", "global", "")
	if err := database.Exec(`INSERT INTO server_groups(id,name,require_mfa,created_at) VALUES('protected','Production',1,CURRENT_TIMESTAMP);INSERT INTO server_group_members(group_id,server_id)VALUES('protected','dev')`).Error; err != nil {
		t.Fatal(err)
	}
	response := policyRequest(router, cookie, "DELETE", "/api/servers/dev", "")
	if response.Code != 403 || !strings.Contains(response.Body.String(), "step_up_required") {
		t.Fatal("no-factor deletion not blocked", response.Code, response.Body.String())
	}
	response = policyRequest(router, cookie, "DELETE", "/api/server-groups/protected/servers/dev", `{"currentPassword":"RBAC fixture password"}`)
	if response.Code != 403 {
		t.Fatal("membership bypass", response.Code)
	}
	if response := policyRequest(router, cookie, "GET", "/api/servers/dev", ""); response.Code != 200 {
		t.Fatal("read blocked")
	}
	cfg := &config.Config{EncryptionKey: bytes.Repeat([]byte{9}, 32)}
	service := auth.NewService(database, cfg)
	access, err := service.Authenticate(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.SetupMFA(access, "RBAC fixture password")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enrollment.Secret, time.Now())
	codes, err := service.EnableMFA(access, enrollment.SetupToken, code)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.Login("owner", "RBAC fixture password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.VerifyRecovery(pending.PendingToken, codes[0], "", "")
	if err != nil {
		t.Fatal(err)
	}
	cookie = &http.Cookie{Name: auth.CookieName(), Value: login.Token}
	access, err = service.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Model(&auth.Session{}).Where("id=?", access.Session.ID).Update("mfa_at", time.Now().Add(-6*time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	response = policyRequest(router, cookie, "PUT", "/api/server-groups/protected/policy", `{"requireMfa":false,"currentPassword":"RBAC fixture password"}`)
	if response.Code != 403 {
		t.Fatal("stale proof changed policy", response.Code)
	}
	response = policyRequest(router, cookie, "POST", "/api/auth/step-up", `{"currentPassword":"RBAC fixture password","code":"`+codes[1]+`"}`)
	if response.Code != 200 {
		t.Fatal("stepup failed", response.Code, response.Body.String())
	}
	response = policyRequest(router, cookie, "PUT", "/api/server-groups/protected/policy", `{"currentPassword":"RBAC fixture password"}`)
	if response.Code != 400 {
		t.Fatal("missing policy value silently changed protection", response.Code)
	}
	response = policyRequest(router, cookie, "PUT", "/api/server-groups/protected/policy", `{"requireMfa":false,"currentPassword":"RBAC fixture password"}`)
	if response.Code != 200 {
		t.Fatal("fresh proof not accepted", response.Code, response.Body.String())
	}
}
