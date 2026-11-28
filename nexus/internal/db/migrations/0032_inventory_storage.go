package migrations

import "gorm.io/gorm"

func InventoryStorage(tx *gorm.DB) error {
	return tx.Exec(`
CREATE TABLE inventory_block_devices (
    resource_id text PRIMARY KEY NOT NULL,
    name text NOT NULL,
    type text NOT NULL,
    device_number text NOT NULL,
    size_bytes integer NOT NULL,
    read_only numeric NOT NULL
);
CREATE TABLE inventory_mounts (
    resource_id text PRIMARY KEY NOT NULL,
    target text NOT NULL,
    filesystem_type text NOT NULL,
    device_number text NOT NULL
);
CREATE TABLE inventory_resolvers (
    resource_id text PRIMARY KEY NOT NULL,
    address text NOT NULL,
    priority integer NOT NULL
);`).Error
}
