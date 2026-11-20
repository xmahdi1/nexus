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

func TestRotationRecoverySet(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	database, err := Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	sealed, err := nexuscrypto.EncryptTemplateDefinition(key, "custom", nexuscrypto.TemplateDefinition{Compose: "private-recipe", VarsJSON: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO custom_templates(id,name,definition_enc) VALUES('custom','Template',?)", sealed).Error; err != nil {
		t.Fatal(err)
	}
	legacy, _ := nexuscrypto.Encrypt(key, []byte("mfa-fixture"))
	if err := database.Exec("INSERT INTO auth_credentials(user_id,totp_secret_enc) VALUES('u',?)", legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO auth_challenges(token_hash,principal_id,credential_epoch,purpose,expires_at) VALUES('pending','u','epoch','login',CURRENT_TIMESTAMP)").Error; err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO auth_sessions(id,principal_id,token_hash,credential_epoch,created_at,last_used_at,expires_at,device_label,client_ip) VALUES('session','u','session-token','epoch',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fixture','127.0.0.1')",
		"INSERT INTO account_invitations(id,user_id,token_hash,inviter_id,created_at,expires_at) VALUES('invite','u','invite-token','u',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
		"INSERT INTO account_resets(id,user_id,token_hash,kind,credential_epoch,requested_by,reason,created_at,expires_at) VALUES('reset','u','reset-token','mfa','epoch','u','fixture',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
		"INSERT INTO account_reset_enrollments(token_hash,reset_id,secret_enc,password_hash,expires_at) VALUES('reset-token','reset','','hash',CURRENT_TIMESTAMP)",
	} {
		if err := database.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(root, "rotated")
	if err := RotateRecoverySet(source, destination, key); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nexus.db", "encryption-key.base64", "manifest.json", "READY"} {
		info, err := os.Stat(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("nonprivate recovery file", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, next) {
		t.Fatal("key not changed")
	}
	rotated, err := Init(filepath.Join(destination, "nexus.db"), next)
	if err != nil {
		t.Fatal(err)
	}
	rotatedConn, _ := rotated.DB()
	defer rotatedConn.Close()
	var value string
	rotated.Raw("SELECT definition_enc FROM custom_templates WHERE id='custom'").Scan(&value)
	definition, err := nexuscrypto.DecryptTemplateDefinition(next, "custom", value)
	if err != nil || definition.Compose != "private-recipe" {
		t.Fatal("template lost", err)
	}
	rotated.Raw("SELECT totp_secret_enc FROM auth_credentials WHERE user_id='u'").Scan(&value)
	plain, err := nexuscrypto.Decrypt(next, value)
	if err != nil || string(plain) != "mfa-fixture" {
		t.Fatal("MFA lost", err)
	}
	var count int64
	rotated.Table("auth_challenges").Count(&count)
	if count != 0 {
		t.Fatal("pending authority retained")
	}
	database.Table("auth_challenges").Count(&count)
	if count != 1 {
		t.Fatal("source authority changed")
	}
	for _, table := range []string{"auth_sessions", "account_invitations", "account_resets", "account_reset_enrollments"} {
		if err := rotated.Table(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("copied authority retained", table, err)
		}
		if err := database.Table(table).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("source authority changed", table, err)
		}
	}
	if err := validateExistingDataKey(database, key); err != nil {
		t.Fatal("source changed", err)
	}
	if err := validateExistingDataKey(rotated, key); err == nil {
		t.Fatal("old key accepted")
	}
	if err := RotateRecoverySet(source, destination, key); err == nil {
		t.Fatal("overwrote existing set")
	}
	wrong := filepath.Join(root, "wrong")
	if err := RotateRecoverySet(source, wrong, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := os.Stat(filepath.Join(wrong, "READY")); !os.IsNotExist(err) {
		t.Fatal("failed set published")
	}
}

func TestRewrapPreservesDeploymentBinding(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	value, err := nexuscrypto.EncryptDeploymentVariables(oldKey, "app", "host", []byte("private-vars"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := rewrapSecret(secretField{kind: "deployment"}, oldKey, newKey, "app", "host", value)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := nexuscrypto.DecryptDeploymentVariables(newKey, "app", "host", sealed)
	if err != nil || string(plain) != "private-vars" {
		t.Fatal(err)
	}
	if _, err := nexuscrypto.DecryptDeploymentVariables(newKey, "app", "other", sealed); err == nil {
		t.Fatal("binding lost")
	}
}

func TestRotationFailureLeavesSourceAndNoReady(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	database, err := Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	if err := database.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "z"} {
		sealed, err := nexuscrypto.EncryptTemplateDefinition(key, id, nexuscrypto.TemplateDefinition{Compose: id})
		if err != nil {
			t.Fatal(err)
		}
		if err := database.Exec("INSERT INTO custom_templates(id,name,definition_enc) VALUES(?,?,?)", id, id, sealed).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Exec("CREATE TRIGGER fail_rotation BEFORE UPDATE ON custom_templates WHEN NEW.id='z' BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "failed")
	if err := RotateRecoverySet(source, destination, key); err == nil {
		t.Fatal("partial rotation succeeded")
	}
	if _, err := os.Stat(filepath.Join(destination, "READY")); !os.IsNotExist(err) {
		t.Fatal("failed set published")
	}
	copyDB := openFixture(t, filepath.Join(destination, "nexus.db"))
	if err := validateExistingDataKey(copyDB, key); err != nil {
		t.Fatal("transaction did not roll back", err)
	}
	var count int64
	copyDB.Table("custom_templates").Count(&count)
	if count != 2 {
		t.Fatal("committed WAL rows lost")
	}
	if err := validateExistingDataKey(database, key); err != nil {
		t.Fatal("source changed", err)
	}
}
