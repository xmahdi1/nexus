package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const pendingTTL = 5 * time.Minute

type pendingEntry struct {
	expiresAt time.Time
}

var (
	pendingMu       sync.Mutex
	pendingSessions = make(map[string]pendingEntry)
)

func NewPendingToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := hex.EncodeToString(b)

	pendingMu.Lock()
	for k := range pendingSessions {
		delete(pendingSessions, k)
	}
	pendingSessions[token] = pendingEntry{expiresAt: time.Now().Add(pendingTTL)}
	pendingMu.Unlock()

	return token
}

func ConsumePendingToken(token string) bool {
	pendingMu.Lock()
	defer pendingMu.Unlock()

	entry, ok := pendingSessions[token]
	if !ok {
		return false
	}
	delete(pendingSessions, token)
	return time.Now().Before(entry.expiresAt)
}
