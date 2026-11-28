package main

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"golang.org/x/crypto/bcrypt"
)

func TestLocalRecoveryCommandUsesFixtureAndAudits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.db")
	hash, err := bcrypt.GenerateFromPassword([]byte("local fixture password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	t.Setenv("NEXUS_DB_PATH", path)
	t.Setenv("NEXUS_PASSWORD_HASH", string(hash))
	t.Setenv("NEXUS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("NEXUS_TOTP_ENABLED", "false")
	t.Setenv("NEXUS_TOTP_SECRET", "")
	database, err := db.Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	defer c.Close()
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PasswordHash: string(hash), EncryptionKey: key}
	if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(database, cfg)
	login, err := service.Login("owner", "local fixture password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAccountRecovery([]string{"--reason", "lost sole administrator factor", "owner"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "/recover#token=") || strings.Contains(output.String(), string(hash)) {
		t.Fatal("unsafe or absent recovery output")
	}
	if _, err := service.Authenticate(login.Token); err == nil {
		t.Fatal("CLI retained session")
	}
	var count int64
	database.Table("authorization_events").Where("actor_id='local-cli' AND action='users.reset.mfa.local'").Count(&count)
	if count != 1 {
		t.Fatal("local recovery not audited")
	}
	if err := runAccountRecovery([]string{"owner"}, &output); err == nil {
		t.Fatal("missing reason accepted")
	}
}
