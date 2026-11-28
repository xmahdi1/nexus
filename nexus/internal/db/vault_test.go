package db

import (
	"database/sql"
	"github.com/xmahdi1/nexus/internal/models"
	"path/filepath"
	"testing"
)

func TestVaultConnectionUpgradeBacksUpSchema11AndPreservesJobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault-upgrade.db")
	database := openFixture(t, path)
	if err := migrate(database, schemaMigrations[:11], nil); err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.Server{ID: "host", Name: "Preserved", Host: "192.0.2.1", Username: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.ScheduledTask{ID: "task", ServerID: "host", Command: "fixture", Supervised: true, Enabled: false, LastStatus: "pending"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Model(&models.ScheduledTask{}).Where("id=?", "task").Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	connection.Close()
	database, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ = database.DB()
	defer connection.Close()
	var task models.ScheduledTask
	if err := database.First(&task, "id=?", "task").Error; err != nil || !task.Supervised || task.Enabled || task.Command != "fixture" {
		t.Fatal("existing job damaged", err)
	}
	if !database.Migrator().HasTable("vault_connections") {
		t.Fatal("connection table absent")
	}
	backups, err := filepath.Glob(path + ".pre-migration-*.db")
	if err != nil || len(backups) != 1 {
		t.Fatal("missing private pre-upgrade snapshot", err)
	}
	snapshot, err := sql.Open("sqlite3", "file:"+backups[0]+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var version int
	if err := snapshot.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 11 {
		t.Fatal("snapshot is not original schema 11", version, err)
	}
}
