package middleware

import (
	"net/http"
	"sync"
	"time"

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

var loginLimiter = newRateLimiter(5, 15*time.Minute)

func LoginRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loginLimiter.allow(httpx.ClientIP(r, trustProxy)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too many login attempts — try again in 15 minutes","code":"rate_limited"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
