package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"golang.org/x/crypto/bcrypt"
)

func TestHTTPSOriginSessionAndLogoutLifecycle(t *testing.T) {
	database, err := db.Init(filepath.Join(t.TempDir(), "api-session.db"))
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	defer conn.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-session-password"), bcrypt.MinCost)
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: bytes.Repeat([]byte{7}, 32)}
	router := NewRouter(database, cfg, nil, nil)
	login := httptest.NewRecorder()
	router.ServeHTTP(login, secureTestRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"fixture-session-password"}`)))
	if login.Code != 200 {
		t.Fatalf("login %d %s", login.Code, login.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == auth.CookieName() {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe or missing session cookie")
	}
	me := httptest.NewRecorder()
	r := secureTestRequest("GET", "/api/auth/me", nil)
	r.AddCookie(cookie)
	router.ServeHTTP(me, r)
	if me.Code != 200 || strings.Contains(me.Body.String(), cookie.Value) || strings.Contains(me.Body.String(), string(hash)) {
		t.Fatal("me failed or exposed secret")
	}
	var body struct {
		Session struct {
			ID string `json:"id"`
		}
	}
	if err := json.Unmarshal(me.Body.Bytes(), &body); err != nil || body.Session.ID == "" {
		t.Fatal("missing server-derived session")
	}
	for _, path := range []string{"/api/servers", "/ws/terminal/missing", "/ws/logs/missing/id", "/ws/metrics/missing"} {
		for _, origin := range []string{"", "http://example.test", "https://attacker.test", "null"} {
			method := "POST"
			if strings.HasPrefix(path, "/ws/") {
				method = "GET"
			}
			r := secureTestRequest(method, path, nil)
			r.Header.Set("Origin", origin)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("unsafe origin %q %s returned %d", origin, path, w.Code)
			}
		}
	}
	// A same-origin request with an invalid handshake still cannot reach SSH.
	invalidHandshake := secureTestRequest("GET", "/ws/terminal/missing", nil)
	invalidHandshake.AddCookie(cookie)
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, invalidHandshake)
	if denied.Code != 400 {
		t.Fatal("invalid upgrade reached remote handler")
	}
	// Old cookies and correctly signed obsolete JWTs never authenticate.
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{}).SignedString(cfg.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nexus_token", auth.CookieName()} {
		r := secureTestRequest("GET", "/api/servers", nil)
		r.AddCookie(&http.Cookie{Name: name, Value: token})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("obsolete JWT accepted")
		}
	}
	// Untrusted forwarding cannot turn public HTTP into a secure deployment.
	clear := httptest.NewRequest("POST", "http://example.test/api/auth/login", strings.NewReader(`{}`))
	clear.Header.Set("Origin", "https://example.test")
	clear.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, clear)
	if w.Code != 400 {
		t.Fatal("trusted arbitrary forwarded proto")
	}
	cfg.TrustProxy = true
	trusted := httptest.NewRequest("POST", "http://example.test/api/auth/login", strings.NewReader(`{"password":"fixture-session-password"}`))
	trusted.Header.Set("Origin", "https://example.test")
	trusted.Header.Set("X-Forwarded-Proto", "https")
	proxyLogin := httptest.NewRecorder()
	router.ServeHTTP(proxyLogin, trusted)
	if proxyLogin.Code != 200 {
		t.Fatalf("TLS termination login failed: %d", proxyLogin.Code)
	}
	cfg.TrustProxy = false
	// Read session metadata, revoke current device, then attempt replay.
	list := httptest.NewRecorder()
	r = secureTestRequest("GET", "/api/auth/sessions", nil)
	r.AddCookie(cookie)
	router.ServeHTTP(list, r)
	if list.Code != 200 || strings.Contains(list.Body.String(), cookie.Value) {
		t.Fatal("session list exposed token")
	}
	revoke := httptest.NewRecorder()
	r = secureTestRequest("DELETE", "/api/auth/sessions/"+body.Session.ID, nil)
	r.AddCookie(cookie)
	router.ServeHTTP(revoke, r)
	if revoke.Code != 204 {
		t.Fatal("device revocation failed")
	}
	replay := httptest.NewRecorder()
	r = secureTestRequest("GET", "/api/auth/me", nil)
	r.AddCookie(cookie)
	router.ServeHTTP(replay, r)
	if replay.Code != 401 || replay.Header().Get("Content-Type") != "application/json" || replay.Header().Get("X-Request-ID") == "" {
		t.Fatal("revoked token did not receive consistent auth error")
	}
}
func TestActivatedOwnerLoginAndPasswordRevocation(t *testing.T) {
	database, err := db.Init(filepath.Join(t.TempDir(), "owner-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	defer conn.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte("owner fixture password"), bcrypt.MinCost)
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: bytes.Repeat([]byte{4}, 32)}
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(database, cfg, nil, nil)
	result, err := auth.NewService(database, cfg).Login("owner", "owner fixture password", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: auth.CookieName(), Value: result.Token}
	r := secureTestRequest("POST", "/api/auth/password", strings.NewReader(`{"currentPassword":"owner fixture password","newPassword":"new owner fixture password"}`))
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("password change failed: %d %s", w.Code, w.Body.String())
	}
	r = secureTestRequest("GET", "/api/servers", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("password change did not revoke HTTP session")
	}
	// A different account's session ID cannot be revoked by this identity.
	service := auth.NewService(database, cfg)
	newLogin, err := service.Login("owner", "new owner fixture password", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	foreign := auth.Session{ID: strings.Repeat("a", 64), PrincipalID: "unrelated", TokenHash: strings.Repeat("b", 64), CredentialEpoch: "1"}
	if err := database.Create(&foreign).Error; err != nil {
		t.Fatal(err)
	}
	r = secureTestRequest("DELETE", "/api/auth/sessions/"+foreign.ID, nil)
	r.AddCookie(&http.Cookie{Name: auth.CookieName(), Value: newLogin.Token})
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("cross-account device revoke allowed")
	}
}
