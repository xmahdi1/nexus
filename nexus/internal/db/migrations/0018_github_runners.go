package migrations

import "gorm.io/gorm"

func GitHubRunners(tx *gorm.DB) error {
	return tx.Exec(`ALTER TABLE supervised_runs ADD COLUMN operation_context text NOT NULL DEFAULT '';
INSERT INTO roles(id,name) VALUES('github-runners','github-runners');
INSERT INTO role_permissions(role_id,permission_key) VALUES('github-runners','github.runners.read'),('github-runners','github.runners.manage');`).Error
}
