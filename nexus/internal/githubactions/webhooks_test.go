package githubactions

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
)

func hookFixture(t *testing.T) (*Service, *auth.Access, Connection, WebhookInfo, string) {
	t.Helper()
	s, a, input, _ := serviceFixture(t)
	for _, role := range []string{"github-webhooks", "secret-reader"} {
		if err := s.DB.Create(&authorization.Grant{ID: "hook-" + role, PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "build", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	conn, err := s.Create(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	info, secret, err := s.RotateWebhook(a, "build", conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 || !info.Configured || info.Disabled {
		t.Fatal("missing one-time configuration")
	}
	return s, a, conn, info, secret
}
func hookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
func runBody(at time.Time, action, status string, attempt int) []byte {
	conclusion := "null"
	if action == "completed" {
		conclusion = `"success"`
	}
	return []byte(fmt.Sprintf(`{"action":%q,"repository":{"id":123,"full_name":"fixture/repository"},"installation":{"id":42},"workflow_run":{"id":71,"workflow_id":7,"run_attempt":%d,"head_sha":%q,"status":%q,"conclusion":%s,"updated_at":%q},"unneeded":{"token":"discard-fixture"}}`, action, attempt, strings.Repeat("a", 40), status, conclusion, at.Format(time.RFC3339Nano)))
}
func TestWebhookSignatureReplayAndMonotonicRunState(t *testing.T) {
	s, _, conn, info, secret := hookFixture(t)
	endpoint := strings.TrimPrefix(info.Path, "/api/hooks/github/")
	now := time.Now().UTC()
	complete := runBody(now, "completed", "completed", 1)
	send := func(body []byte, delivery string) (bool, error) {
		return s.ReceiveWebhook(context.Background(), endpoint, "workflow_run", delivery, hookSignature(secret, body), body)
	}
	delivery := "01020304-1234-1234-1234-0123456789ab"
	if dup, err := send(complete, delivery); err != nil || dup {
		t.Fatal("valid event rejected", dup, err)
	}
	for _, id := range []string{delivery, "01020304-1234-1234-1234-0123456789ac"} {
		if dup, err := send(complete, id); err != nil || !dup {
			t.Fatal("header swap bypassed body dedup", dup, err)
		}
	}
	if dup, err := send(runBody(now.Add(time.Second), "in_progress", "in_progress", 2), delivery); err != nil || !dup {
		t.Fatal("delivery replay admitted", dup, err)
	}
	if _, err := send(runBody(now.Add(time.Second), "in_progress", "in_progress", 1), "01020304-1234-1234-1234-0123456789ad"); err != nil {
		t.Fatal(err)
	}
	var rows []RunObservation
	if err := s.DB.Find(&rows).Error; err != nil || len(rows) != 1 || rows[0].Status != "completed" {
		t.Fatal("out-of-order event regressed state", rows, err)
	}
	newer := runBody(now.Add(time.Second), "in_progress", "in_progress", 2)
	if _, err := send(newer, "01020304-1234-1234-1234-0123456789ae"); err != nil {
		t.Fatal(err)
	}
	s.DB.Find(&rows)
	if len(rows) != 1 || rows[0].RunAttempt != 2 || rows[0].Status != "in_progress" {
		t.Fatal("rerun did not update", rows)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "discard-fixture") {
		t.Fatal("payload leaked")
	}
	var count int64
	s.DB.Model(&webhookReceipt{}).Count(&count)
	if count != 3 {
		t.Fatal("duplicate receipt persisted", count)
	}
	s.DB.Model(&Connection{}).Where("id=?", conn.ID).Update("disabled", true)
	if _, err := send(newer, "01020304-1234-1234-1234-0123456789af"); !errors.Is(err, ErrDenied) {
		t.Fatal("disabled connection received event", err)
	}
}
func TestWebhookRejectsForgedStaleWrongScopeAndHeaderConfusion(t *testing.T) {
	s, _, _, info, secret := hookFixture(t)
	endpoint := strings.TrimPrefix(info.Path, "/api/hooks/github/")
	now := time.Now().UTC()
	body := runBody(now, "completed", "completed", 1)
	tests := []struct {
		name, event, signature string
		body                   []byte
	}{
		{"forged", "workflow_run", hookSignature("wrong", body), body},
		{"missing signature", "workflow_run", "", body},
		{"sha1", "workflow_run", "sha1=abc", body},
		{"ping header swap", "ping", hookSignature(secret, body), body},
		{"unsupported event", "push", hookSignature(secret, body), body},
	}
	for _, change := range []struct {
		name string
		body []byte
	}{
		{"stale", runBody(now.Add(-16*time.Minute), "completed", "completed", 1)},
		{"future", runBody(now.Add(3*time.Minute), "completed", "completed", 1)},
		{"wrong repository", []byte(strings.Replace(string(body), `"id":123`, `"id":124`, 1))},
		{"wrong installation", []byte(strings.Replace(string(body), `"id":42`, `"id":43`, 1))},
		{"wrong action", runBody(now, "completed", "in_progress", 1)},
		{"invalid attempt", runBody(now, "completed", "completed", 0)},
		{"extra document", append(append([]byte{}, body...), []byte(` {}`)...)},
	} {
		tests = append(tests, struct {
			name, event, signature string
			body                   []byte
		}{change.name, "workflow_run", hookSignature(secret, change.body), change.body})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.ReceiveWebhook(context.Background(), endpoint, tt.event, "01020304-1234-1234-1234-0123456789ab", tt.signature, tt.body); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	var count int64
	s.DB.Model(&RunObservation{}).Count(&count)
	if count != 0 {
		t.Fatal("rejected event changed state")
	}
}
func TestWebhookRotationScopeDisclosureAndPingDedup(t *testing.T) {
	s, a, conn, info, secret := hookFixture(t)
	read, err := s.Webhook(a, "build", conn.ID)
	if err != nil || read.Path != info.Path {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(read)
	if strings.Contains(string(encoded), secret) {
		t.Fatal("secret readable again")
	}
	if _, err := s.Webhook(a, "other", conn.ID); err == nil {
		t.Fatal("cross-server read")
	}
	body := []byte(`{"repository":{"id":123,"full_name":"fixture/repository"},"hook_id":8,"zen":"discard"}`)
	endpoint := strings.TrimPrefix(info.Path, "/api/hooks/github/")
	for i := 0; i < 2; i++ {
		dup, err := s.ReceiveWebhook(context.Background(), endpoint, "ping", fmt.Sprintf("01020304-1234-1234-1234-%012d", i), hookSignature(secret, body), body)
		if err != nil || dup != (i == 1) {
			t.Fatal("ping handling", dup, err)
		}
	}
	next, key, err := s.RotateWebhook(a, "build", conn.ID)
	if err != nil || next.Path == info.Path || key == secret {
		t.Fatal("reused authority", err)
	}
	if _, err := s.ReceiveWebhook(context.Background(), endpoint, "ping", "01020304-1234-1234-1234-0123456789ab", hookSignature(secret, body), body); !errors.Is(err, ErrDenied) {
		t.Fatal("old endpoint accepted", err)
	}
	if err := s.DisableWebhook(a, "build", conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReceiveWebhook(context.Background(), strings.TrimPrefix(next.Path, "/api/hooks/github/"), "ping", "01020304-1234-1234-1234-0123456789ab", hookSignature(key, body), body); !errors.Is(err, ErrDenied) {
		t.Fatal("disabled hook accepted", err)
	}
}
