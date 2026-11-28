package db

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db/migrations"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openFixture(t *testing.T, path string) *gorm.DB {
	t.Helper()
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "_busy_timeout=5000&_txlock=immediate"}
	db, err := gorm.Open(sqlite.Open(uri.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := db.DB()
	t.Cleanup(func() { conn.Close() })
	return db
}

func TestFreshAndRepeatedStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	for i := 0; i < 2; i++ {
		db, err := Init(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, model := range []any{&models.Server{}, &models.ProxyRule{}, &models.Service{}, &models.AlertConfig{}, &models.MonitoredContainer{}, &models.ServerAlertConfig{}, &models.ScheduledTask{}, &models.DeployedApp{}, &models.CustomTemplate{}, &models.LoginEvent{}} {
			if !db.Migrator().HasTable(model) {
				t.Errorf("missing table for %T", model)
			}
		}
		var entries []schemaMigration
		if err := db.Find(&entries).Error; err != nil || len(entries) != len(schemaMigrations) || entries[0].Version != 1 {
			t.Fatalf("ledger: %#v %v", entries, err)
		}
		var cfg models.AlertConfig
		if err := db.First(&cfg, "id = ?", "default").Error; err != nil {
			t.Fatal(err)
		}
		conn, _ := db.DB()
		conn.Close()
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 0 {
		t.Fatalf("fresh/repeated startup made backups: %v", backups)
	}
}

func TestInventoryControlsUpgradePreservesHistoryAndDoesNotEnableSchedules(t *testing.T) {
	database := openFixture(t, filepath.Join(t.TempDir(), "schema34.db"))
	if err := migrate(database, schemaMigrations[:34], func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO inventory_resources(id,server_id,kind,natural_key,display_name,source,fingerprint,first_seen_at,last_seen_at,last_verified_at,data_state)VALUES('asset','fixture','host','registered-host','preserved','ssh','hash',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'stale')`,
		`INSERT INTO discovery_runs(id,server_id,actor_id,status,started_at,finished_at,warning)VALUES('run','fixture','actor','succeeded',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'')`,
		`INSERT INTO inventory_changes(server_id,run_id,resource_id,kind,at,before_json,after_json)VALUES('fixture','run','asset','observed',CURRENT_TIMESTAMP,'','{"name":"preserved"}')`,
		`INSERT INTO inventory_documents(server_id,notes,revision,updated_at)VALUES('fixture','preserved notes',3,CURRENT_TIMESTAMP)`,
	} {
		if err := database.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := migrate(database, schemaMigrations, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	var count int64
	for _, table := range []string{"inventory_policies", "inventory_collection_sources"} {
		if err := database.Table(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("upgrade enabled collection or invented provenance", table, count, err)
		}
	}
	var trigger, lastRun, notes, after string
	database.Raw("SELECT trigger FROM discovery_runs WHERE id='run'").Row().Scan(&trigger)
	database.Raw("SELECT last_run_id FROM inventory_resources WHERE id='asset'").Row().Scan(&lastRun)
	database.Raw("SELECT notes FROM inventory_documents WHERE server_id='fixture'").Row().Scan(&notes)
	database.Raw("SELECT after_json FROM inventory_changes WHERE resource_id='asset'").Row().Scan(&after)
	if trigger != "manual" || lastRun != "" || notes != "preserved notes" || after != `{"name":"preserved"}` {
		t.Fatal("upgrade changed existing observations", trigger, lastRun, notes, after)
	}
}

func TestAnsibleMigrationPreservesExistingInvocationsAndIndexes(t *testing.T) {
	database := openFixture(t, filepath.Join(t.TempDir(), "schema18.db"))
	if err := migrate(database, schemaMigrations[:18], func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"scheduled", "operation"} {
		if err := database.Exec("INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,invocation_id,output_enc,created_at,kind,operation_context) VALUES(?,?,?,?,?,'unknown',?,'preserved-ciphertext',CURRENT_TIMESTAMP,?,'public-profile')", kind, "task-"+kind, kind, "actor", "hash", "invocation-"+kind, kind).Error; err != nil {
			t.Fatal(err)
		}
	}
	var before []models.SupervisedRun
	database.Order("id").Find(&before)
	if err := migrate(database, schemaMigrations, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	var after []models.SupervisedRun
	database.Order("id").Find(&after)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing invocation or encrypted output changed during table rebuild")
	}
	if database.Exec("INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,created_at,kind) VALUES('duplicate','','operation','actor','hash','prepared',CURRENT_TIMESTAMP,'ansible')").Error == nil {
		t.Fatal("per-controller admission index lost")
	}
	if err := database.Exec("INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,created_at,kind) VALUES('ansible','','controller','actor','hash','prepared',CURRENT_TIMESTAMP,'ansible')").Error; err != nil {
		t.Fatal("new run kind unavailable", err)
	}
}

func TestAdoptLegacyDatabaseAndRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy := openFixture(t, path)
	// All legacy tables, no version ledger, as on a previously running instance.
	if err := legacy.AutoMigrate(&models.Server{}, &models.ProxyRule{}, &models.Service{},
		&migrations.AlertConfig{}, &models.MonitoredContainer{}, &models.ServerAlertConfig{},
		&migrations.ScheduledTask{}, &migrations.DeployedApp{}, &migrations.CustomTemplate{}, &models.LoginEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{5}, 32)
	ciphertext, err := nexuscrypto.Encrypt(key, []byte("fixture-key"))
	if err != nil {
		t.Fatal(err)
	}
	server := models.Server{ID: "legacy", Name: "Lab", Host: "192.0.2.10", Username: "test", PrivateKeyEnc: ciphertext, KnownHostKey: "pinned", Tags: "production"}
	rows := []any{&server,
		&models.Service{ID: "bookmark", Name: "Service", URL: "https://example.test"},
		&migrations.ScheduledTask{ID: "task", ServerID: server.ID, Command: "fixture-only", Enabled: false},
		&models.ProxyRule{ID: "proxy", ServerID: server.ID, Domain: "example.test", Target: "localhost:80"},
		&migrations.DeployedApp{ID: "app", ServerID: server.ID, VarsJSON: `{"fixture":"value"}`},
		&migrations.CustomTemplate{ID: "template", Compose: "fixture"},
		&models.MonitoredContainer{ID: "container", ServerID: server.ID, ContainerID: "fixture"},
		&models.ServerAlertConfig{ID: server.ID, CPUThreshold: 75},
		&models.LoginEvent{Reason: "fixture", Success: true},
	}
	for _, row := range rows {
		if err := legacy.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}

	if err := legacy.Create(&migrations.AlertConfig{ID: "default"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Model(&migrations.AlertConfig{}).Where("id = ?", "default").Updates(map[string]any{"telegram_token": "fixture-token", "notify_server_down": false}).Error; err != nil {
		t.Fatal(err)
	}
	originals := make([][]map[string]interface{}, len(rows))
	for i, row := range rows {
		if err := legacy.Model(row).Find(&originals[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	var before models.Server
	legacy.First(&before, "id = ?", server.ID)
	db, err := Init(path, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := db.DB()
	defer conn.Close()
	var after models.Server
	db.First(&after, "id = ?", server.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("server changed during adoption")
	}
	for i, row := range rows {
		var actual []map[string]interface{}
		if err := db.Model(row).Find(&actual).Error; err != nil {
			t.Fatal(err)
		}
		for j, old := range originals[i] {
			for key, value := range old {
				if key == "vars_json" || (i == 5 && (key == "compose" || key == "post_deploy")) {
					continue
				}
				if !reflect.DeepEqual(value, actual[j][key]) {
					t.Fatalf("changed legacy column %s for %T", key, row)
				}
			}
		}
		if len(originals[i]) != len(actual) {
			t.Fatalf("changed stored fields for %T", row)
		}
		var count int64
		if err := db.Model(row).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("lost %T: count %d err %v", row, count, err)
		}
	}
	var sealed models.DeployedApp
	if err := db.First(&sealed, "id='app'").Error; err != nil {
		t.Fatal(err)
	}
	recoveredVars, err := nexuscrypto.DecryptDeploymentVariables(key, sealed.ID, sealed.ServerID, sealed.VarsEnc)
	if err != nil || string(recoveredVars) != `{"fixture":"value"}` {
		t.Fatal("deployment variables changed", err)
	}
	if db.Migrator().HasColumn("deployed_apps", "vars_json") {
		t.Fatal("plaintext deployment column retained")
	}

	var cfg models.AlertConfig
	db.First(&cfg, "id = ?", "default")
	token, err := nexuscrypto.DecryptNotificationToken(key, cfg.ID, cfg.TelegramTokenEnc)
	if err != nil || string(token) != "fixture-token" || cfg.NotifyServerDown {
		t.Fatal("overwrote existing configuration")
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 1 {
		t.Fatalf("expected recovery snapshot, got %v", backups)
	}
	// Inspect recovery snapshot without Init: it must contain the original schema,
	// not the new ledger. Opening it through migration would defeat rollback.
	restored := openFixture(t, backups[0])
	if restored.Migrator().HasTable("schema_migrations") {
		t.Fatal("snapshot includes migration writes")
	}
	var recovered models.Server
	if err := restored.First(&recovered, "id = ?", server.ID).Error; err != nil {
		t.Fatal(err)
	}
	plaintext, err := nexuscrypto.Decrypt(key, recovered.PrivateKeyEnc)
	if err != nil || string(plaintext) != "fixture-key" || !reflect.DeepEqual(before, recovered) {
		t.Fatal("rollback lost credential or server metadata")
	}
	var integrity string
	if err := restored.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil || integrity != "ok" {
		t.Fatal("invalid recovery snapshot")
	}
	info, _ := os.Stat(backups[0])
	if info.Mode().Perm() != 0600 {
		t.Fatal("snapshot is not private")
	}
}

func TestPartialLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.db")
	legacy := openFixture(t, path)
	if err := legacy.Exec("CREATE TABLE servers (id text PRIMARY KEY, name text NOT NULL, host text NOT NULL, port integer NOT NULL DEFAULT 22, username text NOT NULL, private_key_enc text)").Error; err != nil {
		t.Fatal(err)
	}
	legacy.Exec("INSERT INTO servers(id,name,host,username,private_key_enc) VALUES ('old','old','192.0.2.1','test','ciphertext')")
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := upgraded.DB()
	defer conn.Close()
	var server models.Server
	if err := upgraded.First(&server, "id = ?", "old").Error; err != nil || server.PrivateKeyEnc != "ciphertext" {
		t.Fatalf("partial upgrade: %v", err)
	}
	if !upgraded.Migrator().HasColumn(&models.Server{}, "tags") {
		t.Fatal("missing new legacy column")
	}
}

func TestMigrationFailureIsAtomicAndRetryable(t *testing.T) {
	db := openFixture(t, filepath.Join(t.TempDir(), "failed.db"))
	injected := errors.New("injected failure")
	steps := []migration{
		{1, "one", func(tx *gorm.DB) error { return tx.Exec("CREATE TABLE first_table(id integer)").Error }},
		{2, "two", func(tx *gorm.DB) error {
			if err := tx.Exec("CREATE TABLE second_table(id integer)").Error; err != nil {
				return err
			}
			return injected
		}},
	}
	if err := migrate(db, steps, nil); !errors.Is(err, injected) {
		t.Fatalf("wrong failure: %v", err)
	}
	for _, name := range []string{"schema_migrations", "first_table", "second_table"} {
		if db.Migrator().HasTable(name) {
			t.Errorf("partial migration retained %s", name)
		}
	}
	steps[1].Up = func(tx *gorm.DB) error { return tx.Exec("CREATE TABLE second_table(id integer)").Error }
	if err := migrate(db, steps, nil); err != nil {
		t.Fatal(err)
	}
	var count int64
	db.Model(&schemaMigration{}).Count(&count)
	if count != 2 {
		t.Fatal("retry did not apply both steps")
	}
}

func TestBackupFailureBlocksChanges(t *testing.T) {
	db := openFixture(t, filepath.Join(t.TempDir(), "backup-failed.db"))
	db.Exec("CREATE TABLE legacy(id integer)")
	called := false
	steps := []migration{{1, "one", func(tx *gorm.DB) error { called = true; return nil }}}
	if err := migrate(db, steps, func() error { return errors.New("disk full") }); err == nil || !strings.Contains(err.Error(), "pre-migration backup failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if called || db.Migrator().HasTable("schema_migrations") {
		t.Fatal("migration ran despite failed backup")
	}
	if err := migrate(db, steps, nil); err == nil {
		t.Fatal("existing DB migrated without backup gate")
	}
}

func TestRejectUnknownOrInconsistentLedger(t *testing.T) {
	for _, entry := range []schemaMigration{{Version: 2, Name: "future"}, {Version: 1, Name: "modified"}} {
		t.Run(entry.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unknown.db")
			db, err := Init(path)
			if err != nil {
				t.Fatal(err)
			}
			conn, _ := db.DB()
			defer conn.Close()
			db.Exec("DELETE FROM schema_migrations")
			entry.AppliedAt = time.Now().UTC()
			if err := db.Create(&entry).Error; err != nil {
				t.Fatal(err)
			}
			if opened, err := Init(path); err == nil {
				c, _ := opened.DB()
				c.Close()
				t.Fatal("accepted unsupported ledger")
			}
		})
	}
}

func TestConcurrentStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := Init(path)
			if err == nil {
				c, _ := db.DB()
				c.Close()
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	db := openFixture(t, path)
	var count int64
	db.Model(&schemaMigration{}).Count(&count)
	if count != int64(len(schemaMigrations)) {
		t.Fatal("duplicate migrations")
	}
}

func TestFailedUpgradePreservesPreviouslyAppliedVersion(t *testing.T) {
	db := openFixture(t, filepath.Join(t.TempDir(), "upgrade-failure.db"))
	if err := migrate(db, schemaMigrations, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.Service{ID: "keep", Name: "keep", URL: "https://example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	steps := append([]migration{}, schemaMigrations...)
	steps = append(steps, migration{len(schemaMigrations) + 1, "fail", func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM services").Error; err != nil {
			return err
		}
		if err := tx.Exec("CREATE TABLE partial_upgrade(id integer)").Error; err != nil {
			return err
		}
		return errors.New("injected upgrade failure")
	}})
	backedUp := false
	if err := migrate(db, steps, func() error { backedUp = true; return nil }); err == nil {
		t.Fatal("failure accepted")
	}
	if !backedUp {
		t.Fatal("upgrade skipped backup gate")
	}
	var count int64
	db.Model(&schemaMigration{}).Count(&count)
	if count != int64(len(schemaMigrations)) {
		t.Fatal("changed existing migration ledger")
	}
	db.Model(&models.Service{}).Count(&count)
	if count != 1 || db.Migrator().HasTable("partial_upgrade") {
		t.Fatal("partial upgrade did not roll back")
	}
}

func TestInitFailsClosedOnIncompatibleLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incompatible.db")
	db := openFixture(t, path)
	// A view occupying a required table name cannot be adopted as a table.
	if err := db.Exec("CREATE VIEW servers AS SELECT 'fixture' AS id").Error; err != nil {
		t.Fatal(err)
	}
	if opened, err := Init(path); err == nil {
		conn, _ := opened.DB()
		conn.Close()
		t.Fatal("incompatible schema returned a usable database")
	}
	if db.Migrator().HasTable("schema_migrations") {
		t.Fatal("retained failed initialization ledger")
	}
}

func TestVersionOneIdentityUpgradeAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-one.db")
	legacy := openFixture(t, path)
	if err := migrate(legacy, schemaMigrations[:1], nil); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{6}, 32)
	encrypted, err := nexuscrypto.Encrypt(key, []byte("identity-upgrade-key"))
	if err != nil {
		t.Fatal(err)
	}
	server := models.Server{ID: "keep", Name: "Lab", Host: "192.0.2.11", Username: "fixture", PrivateKeyEnc: encrypted, KnownHostKey: "pinned"}
	if err := legacy.Create(&server).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := upgraded.DB()
	defer c.Close()
	if !upgraded.Migrator().HasTable(&models.User{}) {
		t.Fatal("identity schema missing")
	}
	var count int64
	upgraded.Model(&models.User{}).Count(&count)
	if count != 0 {
		t.Fatal("migration created a default account")
	}
	var actual models.Server
	upgraded.First(&actual, "id = ?", server.ID)
	if actual.PrivateKeyEnc != encrypted || actual.KnownHostKey != "pinned" {
		t.Fatal("upgrade altered SSH credentials")
	}
	snapshots, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(snapshots) != 1 {
		t.Fatal("identity upgrade did not snapshot version one")
	}
	restored := openFixture(t, snapshots[0])
	if restored.Migrator().HasTable(&models.User{}) {
		t.Fatal("pre-upgrade snapshot contains new users table")
	}
	var ledger []schemaMigration
	restored.Find(&ledger)
	if len(ledger) != 1 || ledger[0].Version != 1 {
		t.Fatal("rollback ledger differs from version one")
	}
	restored.First(&actual, "id = ?", server.ID)
	secret, err := nexuscrypto.Decrypt(key, actual.PrivateKeyEnc)
	if err != nil || string(secret) != "identity-upgrade-key" {
		t.Fatal("rollback lost encryption compatibility")
	}
}

func TestIdentityMigrationRejectsCollisionsAndRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collision.db")
	legacy := openFixture(t, path)
	if err := migrate(legacy, schemaMigrations[:1], nil); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec("CREATE TABLE users (id text PRIMARY KEY, legacy_data text)").Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec("INSERT INTO users VALUES ('keep','untouched')").Error; err != nil {
		t.Fatal(err)
	}
	if opened, err := Init(path); err == nil {
		c, _ := opened.DB()
		c.Close()
		t.Fatal("overwrote unrelated users table")
	}
	var value string
	legacy.Raw("SELECT legacy_data FROM users WHERE id='keep'").Scan(&value)
	if value != "untouched" || legacy.Migrator().HasTable("identity_bootstrap") {
		t.Fatal("collision migration changed data")
	}
	var count int64
	legacy.Model(&schemaMigration{}).Count(&count)
	if count != 1 {
		t.Fatal("failed identity migration recorded")
	}
}

func TestVersionTwoSessionMigrationKeepsOwnerDormantAndRecoverable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-two.db")
	legacy := openFixture(t, path)
	if err := migrate(legacy, schemaMigrations[:2], nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	owner := models.User{ID: "stable-owner", Username: "owner", DisplayName: "Owner", PasswordHash: "fixture-hash-preserved", Status: "active", CreatedAt: now, UpdatedAt: now}
	if err := legacy.Create(&owner).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec("INSERT INTO identity_bootstrap(id,owner_user_id,created_at,source) VALUES(1,?,?,'local_cli')", owner.ID, now).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := upgraded.DB()
	defer c.Close()
	var mode string
	upgraded.Raw("SELECT mode FROM auth_state WHERE id=1").Scan(&mode)
	if mode != "legacy" {
		t.Fatal("migration silently activated accounts")
	}
	var restoredOwner models.User
	upgraded.First(&restoredOwner, "id=?", owner.ID)
	if !reflect.DeepEqual(owner, restoredOwner) {
		t.Fatal("session migration changed prepared account")
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 1 {
		t.Fatal("missing version-two recovery snapshot")
	}
	recovery := openFixture(t, backups[0])
	if recovery.Migrator().HasTable("auth_sessions") {
		t.Fatal("recovery snapshot contains new session schema")
	}
	var ledger []schemaMigration
	recovery.Order("version").Find(&ledger)
	if len(ledger) != 2 || ledger[1].Version != 2 {
		t.Fatal("recovery snapshot not compatible with previous slice")
	}
}

func TestVersionThreeAuthorizationUpgradeAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-three.db")
	legacy := openFixture(t, path)
	if err := migrate(legacy, schemaMigrations[:3], nil); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec(`INSERT INTO scheduled_tasks(id,server_id,command,enabled,last_status,last_output) VALUES('pending','dev','fixture',1,'pending','prior output'),('uncertain','dev','fixture',1,'running','preserved diagnostics')`).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := upgraded.DB()
	defer c.Close()
	var pending, uncertain models.ScheduledTask
	upgraded.First(&pending, "id='pending'")
	upgraded.First(&uncertain, "id='uncertain'")
	if pending.ActorID != "legacy-admin" || !pending.Enabled || pending.Command != "fixture" || pending.LastOutput != "prior output" {
		t.Fatal("legacy pending task changed or lacks execution identity")
	}
	if uncertain.Enabled || uncertain.LastStatus != "interrupted" || !strings.Contains(uncertain.LastOutput, "preserved diagnostics") {
		t.Fatal("uncertain legacy execution was retried or diagnostics lost")
	}
	var count int64
	upgraded.Table("role_grants").Where("principal_id='legacy-admin' AND role_id IN ?", []string{"admin", "host-control", "log-reader"}).Count(&count)
	if count != 3 {
		t.Fatal("missing explicit compatibility grants")
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 1 {
		t.Fatal("missing pre-RBAC backup")
	}
	recovery := openFixture(t, backups[0])
	if recovery.Migrator().HasTable("role_grants") || recovery.Migrator().HasColumn("scheduled_tasks", "actor_id") {
		t.Fatal("rollback snapshot includes new authorization schema")
	}
	var mode string
	recovery.Raw("SELECT mode FROM auth_state WHERE id=1").Scan(&mode)
	if mode != "legacy" {
		t.Fatal("rollback changed auth state")
	}
}

func TestVersionFourAccountAdmissionUpgradeAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-four.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:4], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at) VALUES('owner','owner','Owner','preserved-hash','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),('dormant','dormant','Dormant','other-hash','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
 INSERT INTO identity_bootstrap(id,owner_user_id,created_at,source) VALUES(1,'owner',CURRENT_TIMESTAMP,'local_cli');
 UPDATE auth_state SET mode='owner',owner_user_id='owner' WHERE id=1;
 INSERT INTO auth_credentials(user_id,totp_secret_enc,totp_enabled,version) VALUES('owner','preserved-ciphertext',1,7);`).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := upgraded.DB()
	defer c.Close()
	var admissions []struct{ UserID string }
	if err := upgraded.Table("account_admissions").Find(&admissions).Error; err != nil || len(admissions) != 1 || admissions[0].UserID != "owner" {
		t.Fatal("migration admitted dormant account", admissions, err)
	}
	var credential struct {
		TOTPSecretEnc    string
		Version          int
		RecoveryRequired bool
	}
	if err := upgraded.Table("auth_credentials").Where("user_id='owner'").Take(&credential).Error; err != nil || credential.TOTPSecretEnc != "preserved-ciphertext" || credential.Version != 7 || credential.RecoveryRequired {
		t.Fatal("credential migration corrupted state", credential, err)
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 1 {
		t.Fatal("missing snapshot")
	}
	restored := openFixture(t, backups[0])
	if restored.Migrator().HasTable("account_admissions") || restored.Migrator().HasColumn("auth_credentials", "recovery_required") {
		t.Fatal("rollback snapshot contains v5")
	}
	if err := migrate(restored, schemaMigrations[:4], nil); err != nil {
		t.Fatal("v4 snapshot not readable", err)
	}
}

func TestVersionFiveAuditPolicyUpgradeAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v5.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:5], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO server_groups(id,name,created_at)VALUES('prod','Production',CURRENT_TIMESTAMP),('dev','Development',CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := upgraded.DB()
	defer c.Close()
	var protected bool
	upgraded.Table("server_groups").Where("id='prod'").Pluck("require_mfa", &protected)
	if !protected {
		t.Fatal("Production not protected")
	}
	upgraded.Table("server_groups").Where("id='dev'").Pluck("require_mfa", &protected)
	if protected {
		t.Fatal("Development unexpectedly protected")
	}
	if !upgraded.Migrator().HasTable("operation_events") {
		t.Fatal("missing audit")
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 1 {
		t.Fatal("missing snapshot")
	}
	restored := openFixture(t, backups[0])
	if restored.Migrator().HasTable("operation_events") || restored.Migrator().HasColumn("server_groups", "require_mfa") {
		t.Fatal("snapshot contains new schema")
	}
	if err := migrate(restored, schemaMigrations[:5], nil); err != nil {
		t.Fatal("old ledger unreadable", err)
	}
}

func TestVersionSevenInventoryUpgradePreservesAuditAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v7.db")
	old := openFixture(t, path)
	if err := migrate(old, schemaMigrations[:7], nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO operation_events(operation_id,at,actor_id,session_id,action,resource_type,resource_id,server_id,source,outcome,request_id)VALUES('preserved',CURRENT_TIMESTAMP,'fixture','','fixture','server','dev','dev','domain','succeeded','')`).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := upgraded.DB()
	defer conn.Close()
	var count int64
	upgraded.Table("operation_events").Where("operation_id='preserved'").Count(&count)
	if count != 1 {
		t.Fatal("audit lost")
	}
	if !upgraded.Migrator().HasTable("inventory_hosts") || !upgraded.Migrator().HasTable("discovery_runs") {
		t.Fatal("missing inventory schema")
	}
	backups, _ := filepath.Glob(path + ".pre-migration-*.db")
	if len(backups) != 1 {
		t.Fatal("missing snapshot")
	}
	restored := openFixture(t, backups[0])
	if restored.Migrator().HasTable("inventory_resources") {
		t.Fatal("rollback includes v8")
	}
	if err := migrate(restored, schemaMigrations[:7], nil); err != nil {
		t.Fatal("v7 rollback unreadable", err)
	}
}
