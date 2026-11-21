package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"path/filepath"
	"strings"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/db/migrations"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestLocalMigrationLoadsMatchingKeyWithoutStartingWorkers(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	key := bytes.Repeat([]byte{4}, 32)
	path := filepath.Join(directory, "legacy.db")
	// Construct the immutable legacy schema directly. Deleting the newest
	// migration ledger entries does not recreate an older database.
	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	if err := database.Transaction(migrations.Baseline); err != nil {
		t.Fatal(err)
	}
	encrypted, err := nexuscrypto.Encrypt(key, []byte("fixture key bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO servers(id,name,host,port,username,private_key_enc)VALUES('fixture','Fixture','192.0.2.1',22,'fixture',?)", encrypted).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec(`INSERT INTO deployed_apps(id,server_id,vars_json)VALUES('app','fixture',?)`, `{"password":"private fixture only"}`).Error; err != nil {
		t.Fatal(err)
	}
	if err := runDBMigrate([]string{path}, io.Discard); err == nil {
		t.Fatal("keyless migration accepted plaintext values")
	}
	t.Setenv("NEXUS_PASSWORD_HASH", "fixture-load-only-no-login")
	t.Setenv("NEXUS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	var output bytes.Buffer
	if err := runDBMigrate([]string{"--from-env", path}, &output); err != nil {
		t.Fatal(err)
	}
	// Reopen as the application does after an offline migration; do not reuse a
	// connection whose prepared schema predates another connection's DDL.
	reopened, err := db.Init(path, key)
	if err != nil {
		t.Fatal(err)
	}
	reopenedConnection, _ := reopened.DB()
	defer reopenedConnection.Close()
	var app models.DeployedApp
	if err := reopened.First(&app, "id='app'").Error; err != nil {
		t.Fatal(err)
	}
	value, err := nexuscrypto.DecryptDeploymentVariables(key, app.ID, app.ServerID, app.VarsEnc)
	if err != nil || !strings.Contains(string(value), "private fixture only") {
		t.Fatal("CLI encryption did not preserve variables", err)
	}
	if strings.Contains(output.String(), "private fixture only") {
		t.Fatal("CLI printed secret input")
	}
	if !strings.Contains(output.String(), "No workers or HTTP listener started") {
		t.Fatal("missing local-only completion")
	}
}
