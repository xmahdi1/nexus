package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestInventoryDetailsUpgradeKeepsOriginalHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory-upgrade.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:13], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO inventory_changes(server_id,run_id,resource_id,kind,at) VALUES('host','scan','old-resource','observed',CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
	}
	connection, _ := old.DB()
	connection.Close()
	current, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ = current.DB()
	defer connection.Close()
	var before, after string
	if err := current.Raw("SELECT before_json,after_json FROM inventory_changes WHERE resource_id='old-resource'").Row().Scan(&before, &after); err != nil || before != "" || after != "" {
		t.Fatal("upgrade invented historical details", err)
	}
	backups, err := filepath.Glob(path + ".pre-migration-*.db")
	if err != nil || len(backups) != 1 {
		t.Fatal("missing schema-13 snapshot", err)
	}
	snapshot, err := sql.Open("sqlite3", "file:"+backups[0]+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var version, count int
	if err := snapshot.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 13 {
		t.Fatal("incorrect recovery version", err)
	}
	if err := snapshot.QueryRow("SELECT count(*) FROM inventory_changes WHERE resource_id='old-resource'").Scan(&count); err != nil || count != 1 {
		t.Fatal("original history lost", err)
	}
}
