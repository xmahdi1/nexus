package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
)

func sessionFixture(t *testing.T) (*Service, *config.Config) {
	t.Helper()
	database, err := db.Init(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	t.Cleanup(func() { conn.Close() })
	hash, err := bcrypt.GenerateFromPassword([]byte("current legacy password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: bytes.Repeat([]byte{3}, 32)}
	s := NewService(database, cfg)
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, cfg
}
func mustLogin(t *testing.T, s *Service, username, password string) string {
	t.Helper()
	result, err := s.Login(username, password, "Fixture device", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if result.Token == "" {
		t.Fatal("expected session")
	}
	return result.Token
}

func TestAuthorizedNowRejectsRevocationWithoutWaitingForWatcher(t *testing.T) {
	service, _ := sessionFixture(t)
	access := mustAccess(t, service, mustLogin(t, service, "", "current legacy password"))
	if !access.AuthorizedNow() {
		t.Fatal("live session rejected")
	}
	access.CheckAuthorization = func() bool { return false }
	if access.AuthorizedNow() {
		t.Fatal("revoked permissions accepted")
	}
	access.CheckAuthorization = func() bool { return true }
	if err := service.Revoke(access, access.Session.ID, false); err != nil {
		t.Fatal(err)
	}
	if access.AuthorizedNow() {
		t.Fatal("revoked session accepted before watcher tick")
	}
}

func TestWorkerSessionLookupNeverRefreshesIdleAuthority(t *testing.T) {
	s, _ := sessionFixture(t)
	access := mustAccess(t, s, mustLogin(t, s, "", "current legacy password"))
	before := access.Session.LastUsedAt
	if _, err := s.AccessForSession(access.Session.ID, "another-principal"); err == nil {
		t.Fatal("session rebound to another principal")
	}
	if _, err := s.AccessForSession(access.Session.ID, access.User.ID); err != nil {
		t.Fatal(err)
	}
	var stored Session
	s.DB.First(&stored, "id=?", access.Session.ID)
	if !stored.LastUsedAt.Equal(before) {
		t.Fatal("worker extended idle authority")
	}
	s.now = func() time.Time { return before.Add(s.IdleTTL + time.Second) }
	if _, err := s.AccessForSession(access.Session.ID, access.User.ID); err == nil {
		t.Fatal("expired worker session remained authorized")
	}
}
func mustAccess(t *testing.T, s *Service, token string) *Access {
	t.Helper()
	a, err := s.Authenticate(token)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func activateFixture(t *testing.T, s *Service, cfg *config.Config) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("obsolete dormant password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.BootstrapOwner(s.DB, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if err := ActivateOwner(s.DB, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
}
func TestSessionStorageAndDeviceRevocation(t *testing.T) {
	s, _ := sessionFixture(t)
	first := mustLogin(t, s, "", "current legacy password")
	second := mustLogin(t, s, "", "current legacy password")
	a := mustAccess(t, s, first)
	var saved Session
	if err := s.DB.First(&saved, "id=?", a.Session.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.TokenHash == first || len(saved.TokenHash) != 64 || strings.Contains(saved.CredentialEpoch, "password") {
		t.Fatal("stored token/credential plaintext")
	}
	devices, err := s.Sessions(a)
	if err != nil || len(devices) != 2 {
		t.Fatalf("devices: %d %v", len(devices), err)
	}
	if err := s.Revoke(a, saved.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(first); err == nil {
		t.Fatal("revoked session accepted")
	}
	b := mustAccess(t, s, second)
	if err := s.Revoke(b, "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(second); err == nil {
		t.Fatal("logout-all retained token")
	}
	// No arbitrary bearer/JWT-shaped values are accepted.
	for _, token := range []string{"", "eyJhbGciOiJIUzI1NiJ9.payload.signature", strings.Repeat("f", 64)} {
		if _, err := s.Authenticate(token); err == nil {
			t.Fatal("forged session accepted")
		}
	}
}
func TestIdleAndAbsoluteExpiry(t *testing.T) {
	for _, expiry := range []string{"idle", "absolute"} {
		t.Run(expiry, func(t *testing.T) {
			s, _ := sessionFixture(t)
			now := s.now()
			s.now = func() time.Time { return now }
			s.IdleTTL = 10 * time.Minute
			s.AbsoluteTTL = time.Hour
			token := mustLogin(t, s, "", "current legacy password")
			if expiry == "idle" {
				now = now.Add(10 * time.Minute)
			} else {
				for i := 0; i < 11; i++ {
					now = now.Add(5 * time.Minute)
					mustAccess(t, s, token)
				}
				now = now.Add(5 * time.Minute)
			}
			if _, err := s.Authenticate(token); err == nil {
				t.Fatal("expired session accepted")
			}
		})
	}
}
func TestLegacyCredentialChangeInvalidatesTokens(t *testing.T) {
	s, cfg := sessionFixture(t)
	token := mustLogin(t, s, "", "current legacy password")
	copied := &config.Config{PasswordHash: cfg.PasswordHash, EncryptionKey: cfg.EncryptionKey, TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP"}
	restarted := NewService(s.DB, copied)
	restarted.now = s.now
	if _, err := restarted.Authenticate(token); err == nil {
		t.Fatal("changed legacy MFA retained old token")
	}
}
func TestActivationReconcilesCredentialsAndGatesAccounts(t *testing.T) {
	s, cfg := sessionFixture(t)
	legacy := mustLogin(t, s, "", "current legacy password")
	activateFixture(t, s, cfg)
	if _, err := s.Authenticate(legacy); err == nil {
		t.Fatal("activation retained legacy session")
	}
	for _, test := range []struct{ name, password string }{{"owner", "obsolete dormant password"}, {"", "current legacy password"}, {"other", "current legacy password"}} {
		if _, err := s.Login(test.name, test.password, "", ""); err == nil {
			t.Fatal("obsolete or wrong account authenticated")
		}
	}
	token := mustLogin(t, s, "OWNER", "current legacy password")
	a := mustAccess(t, s, token)
	if a.Mode != "owner" || a.User.ID == LegacyPrincipal {
		t.Fatal("activation did not bind identity")
	}
	if err := s.ChangePassword(a, "current legacy password", "new owner password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(token); err == nil {
		t.Fatal("password change retained session")
	}
	if err := ActivateOwner(s.DB, cfg, "owner"); err == nil {
		t.Fatal("repeat activation overwrote account")
	}
	token = mustLogin(t, s, "owner", "new owner password")
	a = mustAccess(t, s, token)
	if err := s.DB.Model(&models.User{}).Where("id=?", a.User.ID).Update("status", "disabled").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(token); err == nil {
		t.Fatal("disabled owner retained session")
	}
	if _, err := s.Login("", "current legacy password", "", ""); err == nil {
		t.Fatal("disabled owner fell back to .env")
	}
}
func TestActivationFailureRollsBack(t *testing.T) {
	s, cfg := sessionFixture(t)
	token := mustLogin(t, s, "", "current legacy password")
	if _, err := identity.BootstrapOwner(s.DB, identity.BootstrapOptions{Username: "owner", PasswordHash: cfg.PasswordHash}); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Exec(`CREATE TRIGGER fail_activation BEFORE UPDATE ON auth_state BEGIN SELECT RAISE(ABORT,'injected'); END`).Error; err != nil {
		t.Fatal(err)
	}
	if err := ActivateOwner(s.DB, cfg, "owner"); err == nil {
		t.Fatal("activation failure ignored")
	}
	mustAccess(t, s, token)
	var count int64
	s.DB.Model(&Credentials{}).Count(&count)
	if count != 0 {
		t.Fatal("partial credential import retained")
	}
	s.DB.Exec("DROP TRIGGER fail_activation")
	if err := ActivateOwner(s.DB, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
}
func TestMFAMigrationChallengesAndReplay(t *testing.T) {
	s, cfg := sessionFixture(t)
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "JBSWY3DPEHPK3PXP"
	activateFixture(t, s, cfg)
	var credential Credentials
	s.DB.First(&credential)
	if credential.TotpSecretEnc == cfg.TOTPSecret || credential.TotpSecretEnc == "" {
		t.Fatal("MFA secret not encrypted")
	}
	result, err := s.Login("owner", "current legacy password", "", "")
	if err != nil || !result.MFARequired || result.Token != "" {
		t.Fatal("MFA bypassed")
	}
	if _, err := s.VerifyMFA(result.PendingToken, "bad", "", ""); err == nil {
		t.Fatal("bad MFA accepted")
	}
	code, err := totp.GenerateCode(cfg.TOTPSecret, s.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyMFA(result.PendingToken, code, "", ""); err == nil {
		t.Fatal("consumed challenge replayed")
	}
	result, err = s.Login("owner", "current legacy password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := s.VerifyMFA(result.PendingToken, code, "", "")
	if err != nil {
		t.Fatal(err)
	}
	a := mustAccess(t, s, verified.Token)
	if a.Session.MFAAt == nil {
		t.Fatal("MFA freshness missing")
	}
	replay, _ := s.Login("owner", "current legacy password", "", "")
	if _, err := s.VerifyMFA(replay.PendingToken, code, "", ""); err == nil {
		t.Fatal("TOTP counter replayed")
	}
	if _, err := s.SetupMFA(a, "current legacy password"); err == nil {
		t.Fatal("enabled MFA replaced without old code")
	}
	now := s.now().Add(6 * time.Minute)
	s.now = func() time.Time { return now }
	if err := s.ChangePassword(a, "current legacy password", "new owner password"); !errors.Is(err, ErrStepUp) {
		t.Fatalf("stale MFA accepted: %v", err)
	}
}
func TestMFAEnrollmentBoundToSessionAndRevokesDevices(t *testing.T) {
	s, cfg := sessionFixture(t)
	activateFixture(t, s, cfg)
	first := mustLogin(t, s, "owner", "current legacy password")
	second := mustLogin(t, s, "owner", "current legacy password")
	a, b := mustAccess(t, s, first), mustAccess(t, s, second)
	if _, err := s.SetupMFA(a, "wrong"); err == nil {
		t.Fatal("MFA setup without password proof")
	}
	enrollment, err := s.SetupMFA(a, "current legacy password")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(enrollment.Secret, s.now())
	if _, err := s.EnableMFA(b, enrollment.SetupToken, code); err == nil {
		t.Fatal("enrollment crossed session")
	}
	if _, err := s.EnableMFA(a, enrollment.SetupToken, code); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first, second} {
		if _, err := s.Authenticate(token); err == nil {
			t.Fatal("MFA change left a device signed in")
		}
	}
}
func TestStreamWatchClosesOnRevocation(t *testing.T) {
	s, _ := sessionFixture(t)
	token := mustLogin(t, s, "", "current legacy password")
	a := mustAccess(t, s, token)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := WithAccess(httptest.NewRequest("GET", "https://example.test/ws", nil).WithContext(ctx), a)
	closed := make(chan struct{}, 1)
	stop := WatchAccess(request, func() { closed <- struct{}{} })
	defer stop()
	if err := s.Revoke(a, a.Session.ID, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked stream stayed open")
	}
}
