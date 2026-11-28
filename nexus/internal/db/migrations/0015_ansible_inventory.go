package migrations

import "gorm.io/gorm"

// Inventory credentials are intentionally separate from login sessions and SSH
// credentials. Only hashes are stored, and authority always depends on the
// issuing session and current server grants.
func AnsibleInventory(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE ansible_inventory_tokens (
 id text PRIMARY KEY NOT NULL, token_hash text NOT NULL UNIQUE,
 actor_id text NOT NULL, session_id text NOT NULL, group_id text NOT NULL,
 created_at datetime NOT NULL, expires_at datetime NOT NULL);
 CREATE INDEX idx_ansible_inventory_owner ON ansible_inventory_tokens(actor_id,expires_at);
 INSERT INTO roles(id,name) VALUES ('ansible-inventory','ansible-inventory');
 INSERT INTO role_permissions(role_id,permission_key) VALUES
 ('ansible-inventory','servers.read'),('ansible-inventory','ansible.inventory.read');`).Error
}
