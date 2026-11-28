package static

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAFallbackPreservesHistoryRouteWithoutIndexRedirect(t *testing.T) {
	handler := spaHandler(fstest.MapFS{"index.html": {Data: []byte("<html>fixture application</html>")}, "assets/app.js": {Data: []byte("fixtureJS")}})
	for _, path := range []string{"/login", "/join", "/recover", "/servers/dev", "/settings"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 || response.Header().Get("Location") != "" || !strings.Contains(response.Body.String(), "fixture application") {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/assets/app.js", nil))
	if response.Code != 200 || response.Body.String() != "fixtureJS" {
		t.Fatal("static asset broken")
	}
	for _, path := range []string{"/.env", "/.git/config", "/nexus.db", "/backup.db", "/data.sqlite3", "/private.pem", "/server.key"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 404 {
			t.Fatal("private path served", path)
		}
	}
}
