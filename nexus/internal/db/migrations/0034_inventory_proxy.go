package migrations

import "gorm.io/gorm"

func InventoryProxy(tx *gorm.DB) error {
	return tx.Exec(`
CREATE TABLE inventory_proxy_routes (
    resource_id text PRIMARY KEY NOT NULL,
    engine text NOT NULL,
    host text NOT NULL,
    path text NOT NULL,
    match_kind text NOT NULL,
    port integer NOT NULL,
    tls numeric NOT NULL,
    upstreams text NOT NULL
);
CREATE TABLE inventory_tls_certificates (
    resource_id text PRIMARY KEY NOT NULL,
    engine text NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    issuer text NOT NULL,
    fingerprint_sha256 text NOT NULL,
    not_before datetime NOT NULL,
    not_after datetime NOT NULL,
    name_matches numeric NOT NULL
);`).Error
}
