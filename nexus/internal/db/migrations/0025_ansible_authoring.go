package migrations

import "gorm.io/gorm"

func AnsibleAuthoring(tx *gorm.DB) error {
	return tx.Exec(`ALTER TABLE ansible_revisions ADD COLUMN source_connection_id text NOT NULL DEFAULT '';
ALTER TABLE ansible_revisions ADD COLUMN source_repository_id integer NOT NULL DEFAULT 0;
ALTER TABLE ansible_revisions ADD COLUMN source_commit_sha text NOT NULL DEFAULT '';
CREATE TABLE ansible_templates(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,name text NOT NULL,bundle_enc text NOT NULL,digest text NOT NULL,created_by text NOT NULL,created_at datetime NOT NULL,archived numeric NOT NULL DEFAULT 0);
CREATE INDEX idx_ansible_templates_scope ON ansible_templates(server_id,created_at);
INSERT INTO roles(id,name)VALUES('github-projects-reader','github-projects-reader');
INSERT INTO role_permissions(role_id,permission_key)VALUES('github-projects-reader','github.actions.read'),('github-projects-reader','github.projects.read');`).Error
}
