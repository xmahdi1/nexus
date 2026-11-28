package migrations

import "gorm.io/gorm"

func VaultConnections(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE vault_connections(server_id text PRIMARY KEY NOT NULL REFERENCES servers(id) ON DELETE CASCADE,port integer NOT NULL CHECK(port BETWEEN 1024 AND 65535),tls_name text NOT NULL,ca_pem text NOT NULL DEFAULT '',namespace text NOT NULL DEFAULT '');CREATE TRIGGER vault_connection_remove AFTER DELETE ON servers BEGIN DELETE FROM vault_connections WHERE server_id=OLD.id; END;`).Error
}
