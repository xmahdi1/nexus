package middleware

import (
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/xmahdi1/nexus/internal/audit"
	"log"
	"net/http"
)

// Recover without logging panic values/arguments, which can contain credentials
// or remote output. The operation layer has already recorded interruption during
// stack unwinding. Never write another HTTP response after an upgrade/response.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		tracker := &auditWriter{WrapResponseWriter: wrapped}
		defer func() {
			if value := recover(); value != nil {
				if value == http.ErrAbortHandler {
					panic(value)
				}
				log.Printf("request interrupted request_id=%s", audit.RequestIdentifier(chimw.GetReqID(r.Context())))
				if !tracker.upgraded && wrapped.Status() == 0 {
					authError(wrapped, 500, "internal", "Request could not be completed.")
				}
			}
		}()
		next.ServeHTTP(tracker, r)
	})
}
