package middleware

import (
	"net/http"

	"github.com/xmahdi1/nexus/internal/auth"
)

func Require(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(auth.CookieName())
			if err != nil {
				http.Error(w, `{"error":"unauthorized","code":"missing_token"}`, http.StatusUnauthorized)
				return
			}

			if _, err := auth.ValidateToken(cookie.Value, secret); err != nil {
				http.Error(w, `{"error":"unauthorized","code":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
