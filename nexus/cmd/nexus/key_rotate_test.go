package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmahdi1/nexus/internal/db"
)

func TestKeyRotateCLI(t *testing.T) {
	root := t.TempDir()
	key := bytes.Repeat([]byte{3}, 32)
	source := filepath.Join(root, "fixture.db")
	database, err := db.Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	connection.Close()
	keyFile := filepath.Join(root, "key")
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(keyFile, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"--offline", "--key-file", keyFile, source, filepath.Join(root, "recovery")}
	if err := runKeyRotate(args, &out); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(encoded)) {
		t.Fatal("key printed")
	}
	if err := runKeyRotate(args[1:], &out); err == nil {
		t.Fatal("offline acknowledgement missing")
	}
	if err := os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err := runKeyRotate(args, &out); err == nil {
		t.Fatal("public key file accepted")
	}
}
