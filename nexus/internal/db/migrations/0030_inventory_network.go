package migrations

import "gorm.io/gorm"

func InventoryNetwork(tx *gorm.DB) error {
	return tx.Exec(`
CREATE TABLE inventory_interfaces (
    resource_id text PRIMARY KEY NOT NULL,
    name text NOT NULL,
    mtu integer NOT NULL,
    state text NOT NULL
);
CREATE TABLE inventory_addresses (
    resource_id text PRIMARY KEY NOT NULL,
    interface_name text NOT NULL,
    address text NOT NULL,
    prefix_length integer NOT NULL,
    scope text NOT NULL
);
CREATE TABLE inventory_routes (
    resource_id text PRIMARY KEY NOT NULL,
    destination text NOT NULL,
    gateway text NOT NULL,
    interface_name text NOT NULL,
    family integer NOT NULL,
    metric integer NOT NULL,
    type text NOT NULL,
    weight integer NOT NULL,
    next_hop_id integer NOT NULL
);`).Error
}
