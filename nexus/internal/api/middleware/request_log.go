package middleware

import (
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
	"log"
	"net/http"
	"time"
)

// Operational logs use the same route templates as authorization; never log
// raw URLs, queries, request bodies, cookies, headers or remote error text.
func RequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			method = "OTHER"
		}
		route := "static"
		if p, _, ok := authorization.Resolve(r.Method, r.URL.Path); ok {
			route = p.Path
		} else if authorization.Public(r.Method, r.URL.Path) {
			route = r.URL.Path
		}
		wrapped := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		started := time.Now()
		defer func() {
			log.Printf("http method=%s route=%s status=%d request_id=%s duration_ms=%d", method, route, wrapped.Status(), audit.RequestIdentifier(chimw.GetReqID(r.Context())), time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(wrapped, r)
	})
}
