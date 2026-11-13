package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"golang.org/x/crypto/bcrypt"
)

func TestDatabaseOwnerDoesNotEnableHTTPAccountLogin(t *testing.T) {
	database, err := db.Init(filepath.Join(t.TempDir(), "identity-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	ownerHash, err := bcrypt.GenerateFromPassword([]byte("future owner password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(ownerHash)}); err != nil {
		t.Fatal(err)
	}
	legacyHash, err := bcrypt.GenerateFromPassword([]byte("legacy admin password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(database, &config.Config{PasswordHash: string(legacyHash), EncryptionKey: []byte("01234567890123456789012345678901")}, nil, nil)
	for _, tc := range []struct {
		password string
		status   int
	}{{"future owner password", 401}, {"legacy admin password", 200}} {
		request := secureTestRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"`+tc.password+`"}`))
		request.RemoteAddr = "192.0.2.200:5000"
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatalf("login transition status: %d expected %d", response.Code, tc.status)
		}
	}
}

func TestBootstrapDoesNotBypassLegacyMFA(t *testing.T) {
	database, err := db.Init(filepath.Join(t.TempDir(), "identity-mfa.db"))
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy MFA password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	router := NewRouter(database, &config.Config{PasswordHash: string(hash), EncryptionKey: []byte("01234567890123456789012345678901"), TOTPEnabled: true, TOTPSecret: "fixture-secret"}, nil, nil)
	request := secureTestRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"legacy MFA password"}`))
	request.RemoteAddr = "192.0.2.201:5000"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var body struct {
		MFARequired bool `json:"mfaRequired"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || !body.MFARequired || len(response.Result().Cookies()) != 0 {
		t.Fatal("owner bootstrap bypassed legacy MFA")
	}
}

func secureTestRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, "https://example.test"+path, body)
	r.Header.Set("Origin", "https://example.test")
	return r
}
