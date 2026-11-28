package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
)

func TestOwnerCLIFromEnvPreservesConfiguration(t *testing.T) {
	directory := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy CLI password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "legacy.db")
	t.Setenv("NEXUS_PASSWORD_HASH", string(hash))
	t.Setenv("NEXUS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
	t.Setenv("NEXUS_DB_PATH", path)
	t.Setenv("NEXUS_TOTP_SECRET", "fixture-totp-secret")
	t.Setenv("NEXUS_TOTP_ENABLED", "true")
	configuration := []byte("# fixture .env must remain unchanged\nNEXUS_TOTP_ENABLED=true\n")
	if err := os.WriteFile(".env", configuration, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	prompt := func(string) ([]byte, error) { t.Fatal("legacy import prompted for password"); return nil, nil }
	for i := 0; i < 2; i++ {
		if err := runOwnerBootstrap([]string{"--from-env", "OWNER"}, prompt, &output); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(".env")
	if err != nil || !bytes.Equal(got, configuration) {
		t.Fatal("modified .env")
	}
	database, err := db.Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	defer c.Close()
	var user models.User
	if err := database.First(&user, "username = ?", "owner").Error; err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != string(hash) {
		t.Fatal("legacy hash was changed")
	}
	if strings.Contains(output.String(), string(hash)) || strings.Contains(output.String(), "fixture-totp-secret") {
		t.Fatal("CLI exposed credentials")
	}
}
func TestOwnerCLIFreshAndInvalidInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	var output bytes.Buffer
	prompt := func(string) ([]byte, error) { return []byte("new CLI fixture password"), nil }
	if err := runOwnerBootstrap([]string{"--db", path, "owner"}, prompt, &output); err != nil {
		t.Fatal(err)
	}
	database, err := db.Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	defer c.Close()
	var user models.User
	database.First(&user)
	if !identity.VerifyPassword(user.PasswordHash, []byte("new CLI fixture password")) {
		t.Fatal("new password not usable")
	}
	missing := filepath.Join(t.TempDir(), "must-not-exist.db")
	for _, args := range [][]string{{"--db", missing, "../bad"}, {"--db", missing}, {"owner"}} {
		if err := runOwnerBootstrap(args, prompt, &output); err == nil {
			t.Fatal("invalid flags accepted")
		}
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("invalid request created DB")
	}
	calls := 0
	mismatch := func(string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("first password"), nil
		}
		return []byte("different password"), nil
	}
	if err := runOwnerBootstrap([]string{"--db", missing, "owner"}, mismatch, &output); err == nil {
		t.Fatal("mismatched confirmation accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("bad confirmation created DB")
	}
}
