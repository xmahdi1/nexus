package db

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRecoveryCopiesDisableInventorySchedulesWithoutChangingSource(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "snapshot"
		if rotate {
			name = "rotation"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			key := bytes.Repeat([]byte{7}, 32)
			source := filepath.Join(root, "source.db")
			database, err := Init(source, key)
			if err != nil {
				t.Fatal(err)
			}
			connection, _ := database.DB()
			defer connection.Close()
			if err := database.Exec(`INSERT INTO inventory_policies(server_id,actor_id,enabled,interval_minutes,freshness_minutes,retention_days,revision,next_run_at,claim_id,lease_until,last_status,updated_at)
VALUES('fixture','owner',1,5,60,30,9,CURRENT_TIMESTAMP,'active-claim',datetime('now','+2 minutes'),'running',CURRENT_TIMESTAMP)`).Error; err != nil {
				t.Fatal(err)
			}
			query := "SELECT * FROM inventory_policies ORDER BY server_id"
			var before []map[string]any
			if err := database.Raw(query).Scan(&before).Error; err != nil {
				t.Fatal(err)
			}
			copyPath := filepath.Join(root, "copy.db")
			if rotate {
				destination := filepath.Join(root, "rotated")
				if err := RotateRecoverySet(source, destination, key); err != nil {
					t.Fatal(err)
				}
				encoded, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
				if err != nil {
					t.Fatal(err)
				}
				key, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
				if err != nil {
					t.Fatal(err)
				}
				copyPath = filepath.Join(destination, "nexus.db")
			} else if err := RecoverySnapshot(source, copyPath, key); err != nil {
				t.Fatal(err)
			}
			copied, err := Init(copyPath, key)
			if err != nil {
				t.Fatal(err)
			}
			copiedConnection, _ := copied.DB()
			defer copiedConnection.Close()
			var after, original []map[string]any
			if err := copied.Raw(query).Scan(&after).Error; err != nil {
				t.Fatal(err)
			}
			if err := database.Raw(query).Scan(&original).Error; err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, original) {
				t.Fatal("source schedule changed")
			}
			if len(after) != 1 {
				t.Fatal("lost schedule configuration")
			}
			// Runtime authority is removed; the definition, owner, due time and
			// revision remain available for intentional review after recovery.
			for _, field := range []string{"enabled", "claim_id", "lease_until", "last_status"} {
				delete(before[0], field)
			}
			var state struct {
				Enabled    bool
				ClaimID    string
				LeaseUntil *string
				LastStatus string
			}
			if err := copied.Table("inventory_policies").Take(&state).Error; err != nil {
				t.Fatal(err)
			}
			if state.Enabled || state.ClaimID != "" || state.LeaseUntil != nil || state.LastStatus != "recovery_copy" {
				t.Fatal("copied execution authority retained", state)
			}
			for _, field := range []string{"enabled", "claim_id", "lease_until", "last_status"} {
				delete(after[0], field)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("recovery changed schedule definition")
			}
		})
	}
}
