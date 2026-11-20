package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/models"
)

func TestInteractiveUpgradePreservesScheduledIdentityAndHostAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:12], nil); err != nil {
		t.Fatal(err)
	}
	// Use the real schema-12 shape, without the new model's default columns.
	if err := old.Exec(`INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,output_enc,created_at) VALUES('scheduled','task','host','actor','digest','unknown','retained-ciphertext',?)`, time.Now().UTC()).Error; err != nil {
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
	var run models.SupervisedRun
	if err := current.First(&run, "id='scheduled'").Error; err != nil || run.Kind != "scheduled" || run.TaskID != "task" || run.OutputEnc != "retained-ciphertext" || run.FinishedAt != nil {
		t.Fatal("scheduled identity or ciphertext changed", err)
	}
	operation := models.SupervisedRun{ID: "interactive", Kind: "operation", ServerID: "host", ActorID: "actor", Action: "compose-up", State: "prepared", CreatedAt: time.Now().UTC()}
	if current.Create(&operation).Error == nil {
		t.Fatal("interactive operation bypassed scheduled host admission")
	}
	if err := current.Model(&run).Update("finished_at", time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	if err := current.Create(&operation).Error; err != nil {
		t.Fatal("resolved host remained blocked", err)
	}
	backups, err := filepath.Glob(path + ".pre-migration-*.db")
	if err != nil || len(backups) != 1 {
		t.Fatal("pre-upgrade snapshot missing", err)
	}
	snapshot, err := sql.Open("sqlite3", "file:"+backups[0]+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var version int
	if err := snapshot.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 12 {
		t.Fatal("snapshot is not schema 12", version, err)
	}
	var ciphertext string
	if err := snapshot.QueryRow("SELECT output_enc FROM supervised_runs WHERE id='scheduled'").Scan(&ciphertext); err != nil || ciphertext != "retained-ciphertext" {
		t.Fatal("snapshot lost original run", err)
	}
}
