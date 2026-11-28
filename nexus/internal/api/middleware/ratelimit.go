package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/httpx"
)

var trustProxy bool

func SetTrustProxy(v bool) { trustProxy = v }

type bucket struct {
	attempts []time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		window:  window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{}
		rl.buckets[key] = b
	}

	cutoff := time.Now().Add(-rl.window)
	recent := b.attempts[:0]
	for _, t := range b.attempts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	b.attempts = recent

	if len(b.attempts) >= rl.limit {
		return false
	}
	b.attempts = append(b.attempts, time.Now())
	return true
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for key, b := range rl.buckets {
			var recent []time.Time
			for _, t := range b.attempts {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(rl.buckets, key)
			} else {
				b.attempts = recent
			}
		}
		rl.mu.Unlock()
	}
}

var loginLimiter = newRateLimiter(30, 15*time.Minute)

func LoginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loginLimiter.allow(httpx.ClientIP(r, trustProxy)) {
			authError(w, 429, "rate_limited", "Too many login attempts. Try again in 15 minutes.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

var credentialLimiter = newRateLimiter(5, time.Minute)

// Browsing Vault is more frequent than changing Nexus credentials. Keep its
// budget separate so inventory/metadata reads cannot exhaust password/MFA limits.
var vaultLimiter = newRateLimiter(30, time.Minute)

func VaultRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := auth.FromContext(r.Context())
		if !ok {
			authError(w, 401, "missing_session", "Sign in again.")
			return
		}
		if !vaultLimiter.allow(access.User.ID) {
			authError(w, 429, "vault_rate_limit", "Too many Vault operations. Wait a moment.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CredentialRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := auth.FromContext(r.Context())
		if !ok {
			authError(w, 401, "missing_session", "Sign in again.")
			return
		}
		if !credentialLimiter.allow(access.User.ID) {
			authError(w, 429, "rate_limited", "Too many credential changes. Try again in a minute.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

var ansibleLimiter = newRateLimiter(60, time.Minute)

func AnsibleRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := auth.FromContext(r.Context())
		if !ok {
			authError(w, 401, "missing_session", "Sign in again.")
			return
		}
		if !ansibleLimiter.allow(access.User.ID) {
			authError(w, 429, "ansible_rate_limit", "Too many Ansible requests. Wait a moment.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
