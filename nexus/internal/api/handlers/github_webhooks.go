package handlers

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/githubactions"
)

// Fixed global limits precede body reads and DB/crypto work. The limiter has no
// attacker-controlled map keys and applies independently of login budgets.
type GitHubWebhookHandler struct {
	Service *githubactions.Service
	mu      sync.Mutex
	window  time.Time
	count   int
	slots   chan struct{}
}

func NewGitHubWebhookHandler(service *githubactions.Service) *GitHubWebhookHandler {
	return &GitHubWebhookHandler{Service: service, slots: make(chan struct{}, 8)}
}
func (h *GitHubWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.Service.Enabled {
		writeErr(w, "Webhook unavailable.", "not_found", 404)
		return
	}
	h.mu.Lock()
	now := time.Now()
	if now.Sub(h.window) >= time.Minute {
		h.window = now
		h.count = 0
	}
	allowed := h.count < 120
	if allowed {
		h.count++
	}
	h.mu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		writeErr(w, "Webhook budget exceeded.", "rate_limited", 429)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		writeErr(w, "Webhook capacity reached.", "unavailable", 503)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeErr(w, "Use an uncompressed JSON delivery.", "bad_request", 400)
		return
	}
	for _, name := range []string{"X-Hub-Signature-256", "X-GitHub-Delivery", "X-GitHub-Event"} {
		if len(r.Header.Values(name)) != 1 {
			writeErr(w, "Valid delivery headers required.", "bad_request", 400)
			return
		}
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = http.NewResponseController(w).SetReadDeadline(time.Time{}) }()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	body, err := io.ReadAll(r.Body)
	defer clear(body)
	if err != nil {
		writeErr(w, "Delivery exceeds the supported size or could not be read.", "bad_request", 413)
		return
	}
	duplicate, err := h.Service.ReceiveWebhook(ctx, chi.URLParam(r, "endpoint"), r.Header.Get("X-GitHub-Event"), r.Header.Get("X-GitHub-Delivery"), r.Header.Get("X-Hub-Signature-256"), body)
	if err != nil {
		switch {
		case errors.Is(err, githubactions.ErrDenied):
			writeErr(w, "Webhook verification failed.", "invalid_delivery", 401)
		case errors.Is(err, githubactions.ErrInput):
			writeErr(w, "Unsupported or stale delivery.", "bad_request", 400)
		case errors.Is(err, githubactions.ErrWebhookCapacity):
			writeErr(w, "Inspect receipt capacity before rotating the endpoint.", "capacity_reached", 409)
		default:
			writeErr(w, "Webhook unavailable.", "unavailable", 503)
		}
		return
	}
	writeJSON(w, map[string]any{"accepted": true, "duplicate": duplicate}, 202)
}
