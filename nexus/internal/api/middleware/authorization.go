package middleware

import (
	"errors"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
	"net/http"
	"strings"
)

func Authorize(service *authorization.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			access, ok := auth.FromContext(r.Context())
			if !ok {
				authError(w, 401, "missing_session", "Sign in again.")
				return
			}
			policy, params, registered := authorization.Resolve(r.Method, r.URL.Path)
			server := params["id"]
			if policy.Scope != "server" {
				server = ""
			}
			if !registered || !service.Allowed(access.User.ID, policy, server) {
				action := "unregistered"
				if registered {
					action = policy.Method + " " + policy.Path
				}
				if err := service.Record(access.User.ID, action, server, "denied", w.Header().Get("X-Request-ID")); err != nil {
					authError(w, 503, "authorization_unavailable", "Authorization unavailable.")
					return
				}
				// Conceal the existence of inaccessible/missing server targets.
				status := 403
				if registered && policy.Scope == "server" && !service.Check(access.User.ID, "servers.read", server) {
					status = 404
				}
				authError(w, status, "permission_denied", "Access denied.")
				return
			}
			// High-risk operations in protected groups require a recently verified factor.
			protected, err := service.Protected(server)
			if err != nil {
				authError(w, 503, "policy_unavailable", "Risk policy unavailable.")
				return
			}
			groupChange := params["gid"] != "" && r.Method != "GET"
			if groupChange {
				var group authorization.Group
				err := service.DB.First(&group, "id=?", params["gid"]).Error
				if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					authError(w, 503, "policy_unavailable", "Risk policy unavailable.")
					return
				}
				if err == nil && group.RequireMFA {
					protected = true
				}
			}
			if (protected && (authorization.Risk(policy) != "low" || groupChange)) && !access.RecentMFA() {
				if err := service.Record(access.User.ID, policy.Method+" "+policy.Path, server, "step_up_required", w.Header().Get("X-Request-ID")); err != nil {
					authError(w, 503, "audit_unavailable", "Audit unavailable.")
					return
				}
				authError(w, 403, "step_up_required", "Verify MFA in Security settings before this protected operation.")
				return
			}
			// Audit access decisions before remote side effects; fail closed if recording
			// fails. These are authorization decisions, not claims of operation success.
			if !policy.Self {
				if err := service.Record(access.User.ID, policy.Method+" "+policy.Path, server, "allowed", w.Header().Get("X-Request-ID")); err != nil {
					authError(w, 503, "authorization_unavailable", "Authorization unavailable.")
					return
				}
			}
			access.CheckAuthorization = func() bool {
				protected, err := service.Protected(server)
				return err == nil && (!protected || authorization.Risk(policy) == "low" || access.RecentMFA()) && service.Allowed(access.User.ID, policy, server)
			}
			bound := authorization.Bind(r, service, access.User.ID)
			if audited(policy) {
				serveAudited(service.DB, w, bound, next, operationEvent(r, access, policy, params))
				return
			}
			next.ServeHTTP(w, bound)
		})
	}
}

// Management guards the entire management URL surface, including future routes
// accidentally registered outside the protected group. Only the two explicit
// login endpoints are public; unknown actions never reach a handler.
func Management(sessions *auth.Service, policy *authorization.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		protected := RequireSession(sessions)(Authorize(policy)(next))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			public := authorization.Public(r.Method, r.URL.Path)
			if public || (!strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/ws/")) {
				next.ServeHTTP(w, r)
				return
			}
			protected.ServeHTTP(w, r)
		})
	}
}
