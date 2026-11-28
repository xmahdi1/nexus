package middleware

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
)

func authError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message, "message": message, "code": code, "request_id": w.Header().Get("X-Request-ID")})
}
func SecureRequest(r *http.Request, trustProxy bool) bool {
	return r.TLS != nil || (trustProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}
func localRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	hostname := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		hostname = h
	}
	if hostname == "localhost" {
		return true
	}
	target := net.ParseIP(strings.Trim(hostname, "[]"))
	return target != nil && target.IsLoopback()
}

// Security validates origins before any authentication or remote side effect.
// A missing Origin is accepted only for read-only HTTP requests. Browser WS
// upgrades and every mutation require a complete matching scheme+host origin.
func Security(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", middleware.GetReqID(r.Context()))
			if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			secure := SecureRequest(r, cfg.TrustProxy)
			if !secure && !localRequest(r) {
				authError(w, 400, "https_required", "Use HTTPS through a correctly configured trusted reverse proxy.")
				return
			}
			origin := r.Header.Get("Origin")
			providerEvent := authorization.GitHubWebhook(r.Method, r.URL.Path) && r.URL.RawPath == ""
			required := (r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS") || strings.HasPrefix(r.URL.Path, "/ws/")
			if origin != "" || (required && !providerEvent) {
				parsed, err := url.Parse(origin)
				scheme := "http"
				if secure {
					scheme = "https"
				}
				if err != nil || origin == "" || parsed.Scheme != scheme || !strings.EqualFold(parsed.Host, r.Host) || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
					authError(w, 403, "invalid_origin", "A matching same-origin request is required.")
					return
				}
			}
			maxBytes := int64(2 << 20)
			if strings.HasSuffix(r.URL.Path, "/files/upload") {
				maxBytes = 65 << 20
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
func RequireSession(service *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(auth.CookieName())
			if err != nil {
				authError(w, 401, "missing_session", "Sign in to continue.")
				return
			}
			access, err := service.Authenticate(cookie.Value)
			if err != nil {
				authError(w, 401, "invalid_session", "Session expired or revoked. Sign in again.")
				return
			}
			if strings.HasPrefix(r.URL.Path, "/ws/") {
				key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
				if !websocket.IsWebSocketUpgrade(r) || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(key) != 16 {
					authError(w, 400, "websocket_upgrade_required", "A valid WebSocket upgrade is required.")
					return
				}
			}
			next.ServeHTTP(w, auth.WithAccess(r, access))
		})
	}
}
