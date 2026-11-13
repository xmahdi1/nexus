package api

import (
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
)

func TestRouterBaseline(t *testing.T) {
	database, err := db.Init(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := database.DB()
	defer sqlDB.Close()
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: []byte("01234567890123456789012345678901")}
	// No workers or SSH pool: these requests must never reach a remote transport.
	router := NewRouter(database, cfg, nil, nil)
	for _, path := range []string{"/health/live", "/health/ready"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, secureTestRequest("GET", path, nil))
		if w.Code != 200 || w.Body.String() != `{"status":"ok"}` {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	// Walk every registered management method, including WebSocket handshakes.
	err = chi.Walk(router.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route == "/*" || route == "/health/live" || route == "/health/ready" || authorization.Public(method, route) {
			return nil
		}
		for _, token := range []string{"", "invalid"} {
			r := secureTestRequest(method, route, nil)
			if token != "" {
				r.AddCookie(&http.Cookie{Name: auth.CookieName(), Value: token})
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s token %q: %d", method, route, token, w.Code)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	login, err := auth.NewService(database, cfg).Login("", "fixture-password", "test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r := secureTestRequest("GET", "/api/servers", nil)
	r.AddCookie(&http.Cookie{Name: auth.CookieName(), Value: login.Token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("authenticated server listing: %d", w.Code)
	}
	sqlDB.Close()
	for _, test := range []struct {
		path   string
		status int
		body   string
	}{
		{"/health/ready", 503, `{"status":"unavailable"}`},
		{"/health/live", 200, `{"status":"ok"}`},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, secureTestRequest("GET", test.path, nil))
		if w.Code != test.status || w.Body.String() != test.body {
			t.Fatalf("closed DB %s: %d %s", test.path, w.Code, w.Body.String())
		}
	}
}
