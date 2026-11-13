package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestPoolRefusesUnverifiedHostsAndCancelledRequests(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := gossh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool()
	// Verification is checked before dialing, even with a parseable key.
	if client, err := pool.Get(ServerConfig{ID: "fixture", Host: "192.0.2.10", Port: 22, User: "fixture", PrivKey: pem.EncodeToMemory(private)}); err == nil || client != nil || !strings.Contains(err.Error(), "verification is required") {
		t.Fatalf("unverified host accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.GetContext(ctx, ServerConfig{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request was not stopped: %v", err)
	}
}
