package db

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestBackupRestore(t *testing.T) {
	dir := t.TempDir()
	source, snapshot := filepath.Join(dir, "source.db"), filepath.Join(dir, "snapshot.db")
	database, err := Init(source)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	defer conn.Close()
	if err := database.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	secret := []byte("disposable-fixture-private-key")
	encrypted, err := nexuscrypto.Encrypt(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	server := models.Server{ID: "fixture", Name: "Lab", Host: "192.0.2.10", Username: "fixture", PrivateKeyEnc: encrypted}
	if err := database.Create(&server).Error; err != nil {
		t.Fatal(err)
	}
	if err := Backup(source, snapshot); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(snapshot)
	if info.Mode().Perm() != 0600 {
		t.Fatal("backup permissions must be 0600")
	}
	restored, err := Init(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	restoreConn, _ := restored.DB()
	defer restoreConn.Close()
	var integrity string
	if err := restored.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil || integrity != "ok" {
		t.Fatalf("integrity: %s %v", integrity, err)
	}
	var got models.Server
	if err := restored.First(&got, "id = ?", server.ID).Error; err != nil {
		t.Fatal(err)
	}
	plaintext, err := nexuscrypto.Decrypt(key, got.PrivateKeyEnc)
	if err != nil || !bytes.Equal(plaintext, secret) {
		t.Fatalf("restored credential: %v", err)
	}
	if err := Backup(source, snapshot); err == nil {
		t.Fatal("overwrote existing backup")
	}
	if err := Backup(source, source); err == nil {
		t.Fatal("overwrote source")
	}
	if err := Backup(filepath.Join(dir, "missing.db"), filepath.Join(dir, "missing-backup.db")); err == nil {
		t.Fatal("accepted missing source")
	}
	bad := filepath.Join(dir, "bad.db")
	os.WriteFile(bad, []byte("not sqlite"), 0600)
	failed := filepath.Join(dir, "failed.db")
	if err := Backup(bad, failed); err == nil {
		t.Fatal("accepted corrupt database")
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("failed backup was retained")
	}
}
