package migrations

import "gorm.io/gorm"

func HighRisk(tx *gorm.DB) error {
	return tx.Exec(`ALTER TABLE server_groups ADD COLUMN require_mfa numeric NOT NULL DEFAULT 0;
 UPDATE server_groups SET require_mfa=1 WHERE lower(trim(name))='production';`).Error
}
