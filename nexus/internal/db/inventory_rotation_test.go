package db

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func TestOfflineRotationPreservesInventoryAndInteractiveIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	database, err := Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	defer connection.Close()
	if err := database.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.Server{ID: "fixture", Name: "Fixture", Host: "192.0.2.1", Username: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, resource := range []struct{ id, kind, name, source string }{
		{"host", "host", "fixture-host", "ssh"},
		{"service", "service", "ssh.service", "systemd"},
	} {
		if err := database.Exec(`INSERT INTO inventory_resources(id,server_id,kind,natural_key,display_name,source,fingerprint,first_seen_at,last_seen_at,last_verified_at,data_state) VALUES(?,'fixture',?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fresh')`, resource.id, resource.kind, resource.name, resource.name, resource.source, "fixture-digest").Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{
		`INSERT INTO inventory_hosts(resource_id,hostname,os,kernel) VALUES('host','fixture-host','Fixture Linux','fixture-kernel')`,
		`INSERT INTO inventory_services(resource_id,unit,load,active,sub) VALUES('service','ssh.service','loaded','active','running')`,
		`INSERT INTO inventory_relationships(id,server_id,source_id,target_id,kind,source,first_seen_at,last_verified_at,data_state) VALUES('link','fixture','host','service','manages','systemd',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fresh')`,
		`INSERT INTO discovery_runs(id,server_id,actor_id,status,started_at,finished_at,warning) VALUES('scan','fixture','actor','succeeded',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'')`,
		`INSERT INTO inventory_changes(server_id,run_id,resource_id,kind,at,before_json,after_json) VALUES('fixture','scan','service','updated',CURRENT_TIMESTAMP,'{"name":"ssh.service","details":{"active":"inactive"}}','{"name":"ssh.service","details":{"active":"active"}}')`,
	} {
		if err := database.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	output, err := nexuscrypto.EncryptJobOutput(key, "operation", "fixture", []byte("private fixture output"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := models.SupervisedRun{ID: "operation", Kind: "operation", Action: "compose-up", ServerID: "fixture", ActorID: "actor", SourceSessionID: "expired-session", TargetHash: strings.Repeat("a", 64), CommandHash: strings.Repeat("b", 64), State: "exited", CreatedAt: now, FinishedAt: &now, OutputEnc: output}
	if err := database.Create(&run).Error; err != nil {
		t.Fatal(err)
	}
	// Snapshot complete public rows, including provenance and history. The real
	// rotation copies SQLite/WAL state; this must not be reconstructed from models.
	queries := []string{
		"SELECT * FROM inventory_resources ORDER BY id",
		"SELECT * FROM inventory_hosts ORDER BY resource_id",
		"SELECT * FROM inventory_services ORDER BY resource_id",
		"SELECT * FROM inventory_relationships ORDER BY id",
		"SELECT * FROM inventory_changes ORDER BY id",
		"SELECT * FROM discovery_runs ORDER BY id",
	}
	read := func(db *gorm.DB, query string) []map[string]any {
		t.Helper()
		var rows []map[string]any
		if err := db.Raw(query).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		return rows
	}
	before := make([][]map[string]any, len(queries))
	for i, query := range queries {
		before[i] = read(database, query)
	}
	destination := filepath.Join(root, "rotated")
	if err := RotateRecoverySet(source, destination, key); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	next, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(next)
	rotated, err := Init(filepath.Join(destination, "nexus.db"), next)
	if err != nil {
		t.Fatal(err)
	}
	rotatedConnection, _ := rotated.DB()
	defer rotatedConnection.Close()
	for i, query := range queries {
		if !reflect.DeepEqual(before[i], read(rotated, query)) || !reflect.DeepEqual(before[i], read(database, query)) {
			t.Fatal("rotation altered inventory or source data", query)
		}
	}
	var preserved models.SupervisedRun
	if err := rotated.First(&preserved, "id=?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if preserved.OutputEnc == output {
		t.Fatal("interactive ciphertext was not rotated")
	}
	plain, err := nexuscrypto.DecryptJobOutput(next, run.ID, run.ServerID, preserved.OutputEnc)
	if err != nil || string(plain) != "private fixture output" {
		t.Fatal("rotated interactive output is unreadable", err)
	}
	clear(plain)
	if _, err := nexuscrypto.DecryptJobOutput(next, run.ID, "other-server", preserved.OutputEnc); err == nil {
		t.Fatal("rotation lost interactive server binding")
	}
	if _, err := nexuscrypto.DecryptJobOutput(key, run.ID, run.ServerID, preserved.OutputEnc); err == nil {
		t.Fatal("rotated output accepted the old key")
	}
	preserved.OutputEnc = run.OutputEnc
	if !reflect.DeepEqual(run, preserved) {
		t.Fatal("rotation changed interactive identity or metadata")
	}
	var original models.SupervisedRun
	if err := database.First(&original, "id=?", run.ID).Error; err != nil || original.OutputEnc != output {
		t.Fatal("source ciphertext was changed", err)
	}
}
