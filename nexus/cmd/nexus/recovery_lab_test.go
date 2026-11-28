package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/db/migrations"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Optional process-level acceptance for the actual built CLI. This needs neither
// Docker nor a listener; it does not certify an image or a matching old binary.
func TestNativeCLILegacyUpgradeRotationAndRecovery(t *testing.T) {
	binary := os.Getenv("NEXUS_NATIVE_LAB_BINARY")
	if binary == "" {
		t.Skip("set NEXUS_NATIVE_LAB_BINARY to the locally built Nexus CLI")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute native fixture binary path required")
	}
	root := t.TempDir()
	source := filepath.Join(root, "legacy.db")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	legacy, err := gorm.Open(sqlite.Open(source), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Transaction(migrations.Baseline); err != nil {
		t.Fatal(err)
	}
	connection, _ := legacy.DB()
	if err := legacy.Exec(`INSERT INTO deployed_apps(id,server_id,vars_json) VALUES('app','fixture','{"PASSWORD":"private-fixture-value"}')`).Error; err != nil {
		t.Fatal(err)
	}
	connection.Close()
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "NEXUS_") {
			env = append(env, value)
		}
	}
	env = append(env, "NEXUS_PASSWORD_HASH=fixture-config-only-no-login", "NEXUS_ENCRYPTION_KEY="+base64.StdEncoding.EncodeToString(key), "NEXUS_DB_PATH="+source, "NEXUS_TOTP_ENABLED=false")
	var rotationOutput []byte
	defer func() { clear(rotationOutput) }()
	cli := func(environment []string, success bool, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		command.Dir = root // Config loading can only see this owned empty directory.
		command.Env = environment
		output, err := command.CombinedOutput()
		defer clear(output)
		if (err == nil) != success || ctx.Err() != nil {
			t.Fatal("native CLI fixture command had an unexpected outcome", args[0], err)
		}
		if bytes.Contains(output, []byte("private-fixture-value")) {
			t.Fatal("native CLI printed protected fixture input")
		}
		for _, value := range environment {
			if encoded, ok := strings.CutPrefix(value, "NEXUS_ENCRYPTION_KEY="); ok && encoded != "" && bytes.Contains(output, []byte(encoded)) {
				t.Fatal("native CLI printed its configured encryption key")
			}
		}
		if args[0] == "key-rotate" {
			rotationOutput = bytes.Clone(output)
		}
	}
	cli(env, false, "db-migrate", source)
	cli(env, true, "db-migrate", "--from-env", source)
	current, err := db.Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ = current.DB()
	const summary = `{"name":"ssh.service","details":{"active":"active"}}`
	if err := current.Exec(`INSERT INTO inventory_changes(server_id,run_id,resource_id,kind,at,after_json) VALUES('fixture','scan','service','observed',CURRENT_TIMESTAMP,?)`, summary).Error; err != nil {
		t.Fatal(err)
	}
	connection.Close()
	keyFile := filepath.Join(root, "key.base64")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "rotated")
	cli(env, true, "key-rotate", "--offline", "--key-file", keyFile, source, destination)
	encoded, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	next, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || bytes.Equal(next, key) {
		t.Fatal("native CLI did not create a new key")
	}
	defer clear(next)
	if bytes.Contains(rotationOutput, bytes.TrimSpace(encoded)) || bytes.Contains(rotationOutput, next) {
		t.Fatal("native CLI printed its newly generated encryption key")
	}
	rotatedPath := filepath.Join(destination, "nexus.db")
	cli(env, false, "db-migrate", "--from-env", rotatedPath)
	nextEnv := append([]string(nil), env...)
	for i, value := range nextEnv {
		if strings.HasPrefix(value, "NEXUS_ENCRYPTION_KEY=") {
			nextEnv[i] = "NEXUS_ENCRYPTION_KEY=" + base64.StdEncoding.EncodeToString(next)
		}
	}
	cli(nextEnv, true, "db-migrate", "--from-env", rotatedPath)
	backupPath := filepath.Join(root, "recovered.db")
	cli(nextEnv, true, "db-backup", rotatedPath, backupPath)
	recovered, err := db.Init(backupPath, next)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ = recovered.DB()
	defer connection.Close()
	var sealed, historical string
	if err := recovered.Raw("SELECT vars_enc FROM deployed_apps WHERE id='app'").Row().Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	plain, err := nexuscrypto.DecryptDeploymentVariables(next, "app", "fixture", sealed)
	if err != nil || !bytes.Contains(plain, []byte("private-fixture-value")) {
		t.Fatal("recovered CLI backup lost protected data", err)
	}
	clear(plain)
	if err := recovered.Raw("SELECT after_json FROM inventory_changes WHERE resource_id='service'").Row().Scan(&historical); err != nil || historical != summary {
		t.Fatal("recovered CLI backup changed inventory history", err)
	}
	snapshots, err := filepath.Glob(source + ".pre-migration-*.db")
	if err != nil || len(snapshots) == 0 {
		t.Fatal("native migration produced no original recovery snapshot", err)
	}
	for _, snapshot := range snapshots {
		original, err := sql.Open("sqlite3", "file:"+snapshot+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		var oldValue string
		err = original.QueryRow("SELECT vars_json FROM deployed_apps WHERE id='app'").Scan(&oldValue)
		original.Close()
		if err != nil || !strings.Contains(oldValue, "private-fixture-value") {
			t.Fatal("original legacy snapshot was not recoverable", err)
		}
	}
	cli(env, true, "db-migrate", "--from-env", source)
	t.Log("Built native CLI: genuine legacy upgrade, wrong-key rejection, offline rotation, backup recovery, inventory history preservation and original recovery snapshots passed. Image/old-image acceptance remains separate.")
}
