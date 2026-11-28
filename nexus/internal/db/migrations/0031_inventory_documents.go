package migrations

import "gorm.io/gorm"

func InventoryDocuments(tx *gorm.DB) error {
	return tx.Exec(`
CREATE TABLE inventory_documents (
    server_id text PRIMARY KEY NOT NULL,
    notes text NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    updated_at datetime NOT NULL
);`).Error
}
