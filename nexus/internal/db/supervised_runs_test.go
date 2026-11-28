package db

import (
	"bytes"
	"path/filepath"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestSupervisionUpgradeDoesNotAdoptExistingTasks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema10.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:10], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec("INSERT INTO scheduled_tasks(id,server_id,command,enabled,last_status)VALUES('old','host','preserve command',1,'pending')").Error; err != nil {
		t.Fatal(err)
	}
	current, err := Init(path, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := current.DB()
	defer connection.Close()
	var task models.ScheduledTask
	if err := current.First(&task, "id='old'").Error; err != nil {
		t.Fatal(err)
	}
	if task.Supervised || task.Command != "preserve command" || !task.Enabled {
		t.Fatal("existing task execution mode changed")
	}
	snapshots, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(snapshots) != 1 {
		t.Fatal("missing schema-10 recovery snapshot")
	}
	snapshot := openFixture(t, snapshots[0])
	if snapshot.Migrator().HasColumn("scheduled_tasks", "supervised") {
		t.Fatal("snapshot is not the old schema")
	}
}

func TestJobOutputRotationUsesItsOriginalBindings(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	sealed, err := nexuscrypto.EncryptJobOutput(oldKey, "run", "host", []byte("output fixture"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := rewrapSecret(secretField{kind: "job"}, oldKey, newKey, "run", "host", sealed)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nexuscrypto.DecryptJobOutput(newKey, "run", "host", rotated)
	if err != nil || string(data) != "output fixture" {
		t.Fatal(err)
	}
	if _, err := nexuscrypto.DecryptJobOutput(newKey, "run", "other", rotated); err == nil {
		t.Fatal("rotation lost server binding")
	}
}
