package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestSessionTTLLimits(t *testing.T) {
	t.Setenv("NEXUS_PASSWORD_HASH", "fixture")
	t.Setenv("NEXUS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	for _, tc := range []struct {
		idle, absolute string
		valid          bool
	}{{"12h", "168h", true}, {"0s", "168h", false}, {"13h", "12h", false}, {"1m", "721h", false}, {"invalid", "168h", false}} {
		t.Setenv("NEXUS_SESSION_IDLE_TTL", tc.idle)
		t.Setenv("NEXUS_SESSION_ABSOLUTE_TTL", tc.absolute)
		_, err := Load()
		if (err == nil) != tc.valid {
			t.Fatalf("unexpected TTL validation: %v", err)
		}
	}
}
func TestAtomicLegacyConfigAndSnapshots(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	original := "NEXUS_ENCRYPTION_KEY=fixture-unchanged\nNEXUS_PASSWORD_HASH='old'\nNEXUS_TOTP_ENABLED=false\n"
	if err := os.WriteFile(".env", []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{PasswordHash: "old"}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs <- cfg.UpdatePasswordHash("new-hash") }()
	go func() { defer wg.Done(); errs <- cfg.UpdateTOTP("fixture-secret", true) }()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	hash, secret, enabled := cfg.AuthSnapshot()
	if hash != "new-hash" || secret != "fixture-secret" || !enabled {
		t.Fatal("inconsistent in-memory config")
	}
	content, err := os.ReadFile(".env")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"NEXUS_ENCRYPTION_KEY=fixture-unchanged", "NEXUS_PASSWORD_HASH='new-hash'", "NEXUS_TOTP_SECRET=fixture-secret", "NEXUS_TOTP_ENABLED=true"} {
		if !strings.Contains(string(content), expected) {
			t.Fatal("lost config during concurrent updates")
		}
	}
	info, _ := os.Stat(".env")
	if info.Mode().Perm() != 0600 {
		t.Fatal("config permissions not private")
	}
	// A write failure never changes the live auth snapshot.
	if err := os.Rename(".env", "saved.env"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(".env", 0700); err != nil {
		t.Fatal(err)
	}
	if err := cfg.UpdateTOTP("replacement", false); err == nil {
		t.Fatal("ignored config failure")
	}
	_, secret, enabled = cfg.AuthSnapshot()
	if secret != "fixture-secret" || !enabled {
		t.Fatal("failed write changed live MFA")
	}
}
