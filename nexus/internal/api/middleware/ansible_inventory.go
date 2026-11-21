package middleware

import (
	"net/http"
	"strings"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/automation"
)

// InventorySession is only installed for the exact read-only inventory route.
// Inventory credentials are never accepted as general management API sessions.
func InventorySession(service *automation.InventoryService, enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				authError(w, 401, "invalid_inventory_credential", "An inventory credential is required.")
				return
			}
			a, group, err := service.Authenticate(strings.TrimPrefix(header, "Bearer "))
			if err != nil {
				authError(w, 401, "invalid_inventory_credential", "Inventory credential expired or revoked.")
				return
			}
			if !enabled {
				authError(w, 404, "feature_disabled", "Automation is disabled.")
				return
			}
			r = r.WithContext(automation.WithInventoryGroup(r.Context(), group))
			next.ServeHTTP(w, auth.WithAccess(r, a))
		})
	}
}
