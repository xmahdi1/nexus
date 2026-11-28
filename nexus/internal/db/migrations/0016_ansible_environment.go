package migrations

import "gorm.io/gorm"

func AnsibleEnvironment(tx *gorm.DB) error {
	return tx.Exec(`INSERT INTO roles(id,name) VALUES('ansible-environment','ansible-environment');
 INSERT INTO role_permissions(role_id,permission_key) VALUES
 ('ansible-environment','ansible.environment.read'),
 ('ansible-environment','ansible.environment.manage');`).Error
}
