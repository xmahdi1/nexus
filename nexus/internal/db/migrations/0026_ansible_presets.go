package migrations

import "gorm.io/gorm"

func AnsiblePresets(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE ansible_presets(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,name text NOT NULL,config_enc text NOT NULL,digest text NOT NULL,created_by text NOT NULL,created_at datetime NOT NULL,archived numeric NOT NULL DEFAULT 0);
CREATE INDEX idx_ansible_presets_scope ON ansible_presets(server_id,created_at);
ALTER TABLE ansible_plans ADD COLUMN preset_id text NOT NULL DEFAULT '';`).Error
}
