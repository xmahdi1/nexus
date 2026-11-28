package db

import (
	"bytes"
	"path/filepath"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestTemplateUpgradePreservesSourceAndRollback(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	path := filepath.Join(t.TempDir(), "v9.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:9], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO custom_templates(id,name,compose,vars_json,post_deploy)VALUES('custom','Metadata',?,?,?)`, "private source", `[{"default":"private-default"}]`, "private instructions").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := Init(path); err == nil {
		t.Fatal("keyless template conversion accepted")
	}
	current, err := Init(path, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := current.DB()
	defer connection.Close()
	var row models.CustomTemplate
	if err := current.First(&row, "id='custom'").Error; err != nil {
		t.Fatal(err)
	}
	value, err := nexuscrypto.DecryptTemplateDefinition(key, row.ID, row.DefinitionEnc)
	if err != nil || value.Compose != "private source" || value.PostDeploy != "private instructions" || value.VarsJSON != `[{"default":"private-default"}]` {
		t.Fatal("definition not preserved", err)
	}
	for _, column := range []string{"compose", "vars_json", "post_deploy"} {
		if current.Migrator().HasColumn("custom_templates", column) {
			t.Fatal("plaintext column retained", column)
		}
	}
	snapshots, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(snapshots) < 1 {
		t.Fatal("missing private recovery set")
	}
	restored := openFixture(t, snapshots[0])
	if err := migrate(restored, schemaMigrations[:9], nil); err != nil {
		t.Fatal("old schema recovery failed", err)
	}
	var original string
	restored.Table("custom_templates").Where("id='custom'").Pluck("compose", &original)
	if original != "private source" {
		t.Fatal("snapshot lost source")
	}
	if _, err := Init(path, bytes.Repeat([]byte{4}, 32)); err == nil {
		t.Fatal("wrong key reopen accepted")
	}
}
func TestTemplateMigrationRollsBackAfterWriteFailure(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	path := filepath.Join(t.TempDir(), "v9.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:9], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO custom_templates(id,name,compose)VALUES('a','First','first'),('z','Second','second');CREATE TRIGGER reject_template BEFORE UPDATE ON custom_templates WHEN NEW.id='z' BEGIN SELECT RAISE(ABORT,'fixture');END`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := Init(path, key); err == nil {
		t.Fatal("partial migration accepted")
	}
	var version int
	old.Raw("SELECT max(version) FROM schema_migrations").Scan(&version)
	if version != 9 || old.Migrator().HasColumn("custom_templates", "definition_enc") {
		t.Fatal("failed migration changed schema")
	}
	var value string
	old.Table("custom_templates").Where("id='a'").Pluck("compose", &value)
	if value != "first" {
		t.Fatal("failed migration changed original")
	}
}
