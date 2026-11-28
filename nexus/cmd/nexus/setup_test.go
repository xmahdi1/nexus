package main

import (
	"bytes"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupPrivateFileNeverOverwritesOrPrintsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	var output bytes.Buffer
	password := func(string) ([]byte, error) { return []byte("fixture password only"), nil }
	if err := runInitialSetup([]string{"--env-file", path}, password, &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(string(data)), "\n")
	hash := strings.Trim(strings.TrimPrefix(fields[0], "NEXUS_PASSWORD_HASH="), "'")
	key := strings.TrimPrefix(fields[1], "NEXUS_ENCRYPTION_KEY=")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 || bcrypt.CompareHashAndPassword([]byte(hash), []byte("fixture password only")) != nil {
		t.Fatal("invalid initial credentials")
	}
	if strings.Contains(output.String(), key) || strings.Contains(output.String(), hash) {
		t.Fatal("printed credentials in file mode")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("configuration is not private")
	}
	if err := runInitialSetup([]string{"--env-file", path}, func(string) ([]byte, error) { t.Fatal("overwrite prompted for password"); return nil, nil }, &output); err == nil {
		t.Fatal("existing configuration overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, data) {
		t.Fatal("existing configuration changed")
	}
}
