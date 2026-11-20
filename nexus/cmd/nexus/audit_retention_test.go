package main

import (
	"bytes"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/db"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditPruneBacksUpBeforeRetentionAndRejectsUnsafeLimits(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "fixture.db")
	backup := filepath.Join(directory, "backup.db")
	database, err := db.Init(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	defer conn.Close()
	if err := database.Create(&audit.Event{OperationID: "expired", At: time.Now().AddDate(-2, 0, 0), ActorID: "fixture", Source: "domain", Outcome: "succeeded"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := audit.Append(database, audit.Event{OperationID: "fresh", ActorID: "fixture", Source: "domain", Outcome: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAuditPrune([]string{"--days", "1", "--backup", backup, path}, &output); err == nil {
		t.Fatal("unsafe retention accepted")
	}
	if err := runAuditPrune([]string{"--days", "365", "--backup", backup, path}, &output); err != nil {
		t.Fatal(err)
	}
	var count int64
	database.Model(&audit.Event{}).Count(&count)
	if count != 2 {
		t.Fatal("wrong retention", count)
	}
	restored, err := db.Init(backup)
	if err != nil {
		t.Fatal(err)
	}
	rconn, _ := restored.DB()
	defer rconn.Close()
	restored.Model(&audit.Event{}).Count(&count)
	if count != 2 {
		t.Fatal("backup lost history")
	}
	if err := runAuditPrune([]string{"--days", "365", "--backup", backup, path}, &output); err == nil {
		t.Fatal("overwrote backup")
	}
}
