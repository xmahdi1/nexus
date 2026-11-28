package migrations

import "gorm.io/gorm"

func InventoryControls(tx *gorm.DB) error {
	return tx.Exec(`
CREATE TABLE inventory_policies (
 server_id text PRIMARY KEY NOT NULL,
 actor_id text NOT NULL,
 enabled numeric NOT NULL DEFAULT 0,
 interval_minutes integer NOT NULL DEFAULT 60,
 freshness_minutes integer NOT NULL DEFAULT 15,
 retention_days integer NOT NULL DEFAULT 0,
 revision integer NOT NULL DEFAULT 1,
 next_run_at datetime NOT NULL,
 failure_count integer NOT NULL DEFAULT 0,
 last_status text NOT NULL DEFAULT '',
 claim_id text NOT NULL DEFAULT '',
 lease_until datetime,
 updated_at datetime NOT NULL
);
CREATE INDEX idx_inventory_policy_due ON inventory_policies(enabled,next_run_at);
CREATE TABLE inventory_collection_sources (
 run_id text NOT NULL,
 source text NOT NULL,
 server_id text NOT NULL,
 status text NOT NULL,
 collected_at datetime NOT NULL,
 PRIMARY KEY(run_id,source)
);
CREATE INDEX idx_inventory_source_server ON inventory_collection_sources(server_id,run_id);
ALTER TABLE inventory_resources ADD COLUMN last_run_id text NOT NULL DEFAULT '';
ALTER TABLE inventory_relationships ADD COLUMN last_run_id text NOT NULL DEFAULT '';
ALTER TABLE discovery_runs ADD COLUMN trigger text NOT NULL DEFAULT 'manual';
CREATE INDEX idx_inventory_resource_run ON inventory_resources(last_run_id);
CREATE INDEX idx_inventory_relationship_run ON inventory_relationships(last_run_id);
CREATE INDEX idx_inventory_history_age ON inventory_changes(server_id,at);
CREATE INDEX idx_discovery_finished ON discovery_runs(server_id,finished_at);
`).Error
}
