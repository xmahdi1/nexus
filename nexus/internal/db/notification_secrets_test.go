package db

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
)

func TestNotificationMigrationRequiresKeyAndPreservesRecovery(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "schema35.db")
	key := bytes.Repeat([]byte{5}, 32)
	legacy := openFixture(t, path)
	if err := migrate(legacy, schemaMigrations[:35], func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec("UPDATE alert_configs SET telegram_token='private-fictional-notification-token',telegram_chat_id='fictional-chat',telegram_enabled=1 WHERE id='default'").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := Init(path); err == nil {
		t.Fatal("keyless migration accepted")
	}
	if legacy.Migrator().HasColumn("alert_configs", "telegram_token_enc") {
		t.Fatal("failed migration committed schema")
	}
	database, err := Init(path, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	if database.Migrator().HasColumn("alert_configs", "telegram_token") {
		t.Fatal("live plaintext token column retained")
	}
	var sealed string
	if err := database.Raw("SELECT telegram_token_enc FROM alert_configs WHERE id='default'").Scan(&sealed).Error; err != nil {
		t.Fatal(err)
	}
	plain, err := nexuscrypto.DecryptNotificationToken(key, "default", sealed)
	if err != nil || string(plain) != "private-fictional-notification-token" {
		t.Fatal("migration lost token", err)
	}
	if _, err := nexuscrypto.DecryptNotificationToken(key, "other", sealed); err == nil {
		t.Fatal("token binding absent")
	}
	if _, err := Init(path, bytes.Repeat([]byte{6}, 32)); err == nil {
		t.Fatal("wrong key reopened notification secret")
	}
	destination := filepath.Join(root, "rotated")
	if err := RotateRecoverySet(path, destination, key); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := Init(filepath.Join(destination, "nexus.db"), next)
	if err != nil {
		t.Fatal(err)
	}
	rotatedConnection, _ := rotated.DB()
	defer rotatedConnection.Close()
	var enabled bool
	if err := rotated.Raw("SELECT telegram_enabled FROM alert_configs WHERE id='default'").Scan(&enabled).Error; err != nil || enabled {
		t.Fatal("recovery retained notification authority", err)
	}
	var rewrapped string
	if err := rotated.Raw("SELECT telegram_token_enc FROM alert_configs WHERE id='default'").Scan(&rewrapped).Error; err != nil {
		t.Fatal(err)
	}
	plain, err = nexuscrypto.DecryptNotificationToken(next, "default", rewrapped)
	if err != nil || string(plain) != "private-fictional-notification-token" || rewrapped == sealed {
		t.Fatal("rotation did not preserve and re-encrypt token", err)
	}
	if _, err := nexuscrypto.DecryptNotificationToken(key, "default", rewrapped); err == nil {
		t.Fatal("rotated token accepted old key")
	}
	var original string
	if err := database.Raw("SELECT telegram_token_enc FROM alert_configs WHERE id='default'").Scan(&original).Error; err != nil || original != sealed {
		t.Fatal("rotation modified source", err)
	}
}
