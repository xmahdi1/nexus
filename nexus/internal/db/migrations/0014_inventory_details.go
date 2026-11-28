package migrations

import "gorm.io/gorm"

func InventoryDetails(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE inventory_services(resource_id text PRIMARY KEY NOT NULL,unit text NOT NULL,load text NOT NULL,active text NOT NULL,sub text NOT NULL);
CREATE TABLE inventory_relationships(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,source_id text NOT NULL,target_id text NOT NULL,kind text NOT NULL,source text NOT NULL,first_seen_at datetime NOT NULL,last_verified_at datetime NOT NULL,data_state text NOT NULL);
CREATE INDEX idx_inventory_relationship_scope ON inventory_relationships(server_id,id);
ALTER TABLE inventory_changes ADD COLUMN before_json text NOT NULL DEFAULT '';
ALTER TABLE inventory_changes ADD COLUMN after_json text NOT NULL DEFAULT '';
CREATE INDEX idx_inventory_change_resource ON inventory_changes(server_id,resource_id,id);`).Error
}
