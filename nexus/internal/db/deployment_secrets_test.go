package db

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func seedDeploymentV8(t *testing.T, path string, key []byte) *gorm.DB {
	t.Helper()
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:8], nil); err != nil {
		t.Fatal(err)
	}
	encrypted, err := nexuscrypto.Encrypt(key, []byte("fixture SSH material"))
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Exec("INSERT INTO servers(id,name,host,port,username,private_key_enc)VALUES('host','Host','192.0.2.10',22,'fixture',?)", encrypted).Error; err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO deployed_apps(id,server_id,name,vars_json,status)VALUES('app','host','unchanged',?,'running')`, `{"password":"legacy-secret-fixture","port":"5432"}`).Error; err != nil {
		t.Fatal(err)
	}
	return old
}
func TestDeploymentSecretUpgradeBackupRollbackAndKeyValidation(t *testing.T) {
	key := bytes.Repeat([]byte{6}, 32)
	path := filepath.Join(t.TempDir(), "upgrade.db")
	seedDeploymentV8(t, path, key)
	current, err := Init(path, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := current.DB()
	defer conn.Close()
	if current.Migrator().HasColumn("deployed_apps", "vars_json") {
		t.Fatal("plaintext column remains")
	}
	var app models.DeployedApp
	if err := current.First(&app, "id='app'").Error; err != nil {
		t.Fatal(err)
	}
	value, err := nexuscrypto.DecryptDeploymentVariables(key, app.ID, app.ServerID, app.VarsEnc)
	if err != nil || string(value) != `{"password":"legacy-secret-fixture","port":"5432"}` || app.Name != "unchanged" || app.Status != "running" {
		t.Fatal("deployment changed", err)
	}
	visible, _ := json.Marshal(app)
	if strings.Contains(string(visible), "legacy-secret") || strings.Contains(string(visible), app.VarsEnc) {
		t.Fatal("API model exposed variables")
	}
	if _, err := Init(path, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("wrong key accepted on reopen")
	}
	snapshots, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(snapshots) != 1 {
		t.Fatal("missing rollback snapshot")
	}
	info, err := os.Stat(snapshots[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private snapshot required", err)
	}
	restored := openFixture(t, snapshots[0])
	if err := migrate(restored, schemaMigrations[:8], nil); err != nil {
		t.Fatal("old schema cannot reopen", err)
	}
	var legacy string
	if err := restored.Table("deployed_apps").Where("id='app'").Pluck("vars_json", &legacy).Error; err != nil || legacy != string(value) {
		t.Fatal("rollback lost original variables", err)
	}
	if err := migrate(current, schemaMigrations[:8], nil); err == nil {
		t.Fatal("old registry accepted new schema")
	}
}
func TestDeploymentSecretMigrationFailsAtomically(t *testing.T) {
	for _, failure := range []string{"missing_key", "wrong_key", "write_failure"} {
		t.Run(failure, func(t *testing.T) {
			key := bytes.Repeat([]byte{6}, 32)
			path := filepath.Join(t.TempDir(), "failure.db")
			old := seedDeploymentV8(t, path, key)
			attempt := key
			switch failure {
			case "missing_key":
				attempt = nil
			case "wrong_key":
				attempt = bytes.Repeat([]byte{1}, 32)
			case "write_failure":
				if err := old.Exec(`INSERT INTO deployed_apps(id,server_id,name,vars_json,status)VALUES('zzz','host','Second',?,'stopped')`, `{"secret":"second-record-fixture"}`).Error; err != nil {
					t.Fatal(err)
				}
				if err := old.Exec(`CREATE TRIGGER reject_secret_update BEFORE UPDATE ON deployed_apps WHEN NEW.id='zzz' BEGIN SELECT RAISE(ABORT,'fixture');END`).Error; err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Init(path, attempt); err == nil {
				t.Fatal("migration failure accepted")
			}
			var latest int
			old.Raw("SELECT max(version) FROM schema_migrations").Scan(&latest)
			if latest != 8 || old.Migrator().HasColumn("deployed_apps", "vars_enc") {
				t.Fatal("failed migration changed schema/ledger")
			}
			var value string
			old.Table("deployed_apps").Where("id='app'").Pluck("vars_json", &value)
			if !strings.Contains(value, "legacy-secret-fixture") {
				t.Fatal("failed migration lost original data")
			}
		})
	}
}
