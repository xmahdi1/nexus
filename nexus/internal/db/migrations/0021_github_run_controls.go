package migrations

import "gorm.io/gorm"

func GitHubRunControls(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE github_cancellations(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,connection_id text NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,run_id integer NOT NULL,run_attempt integer NOT NULL,state text NOT NULL CHECK(state IN ('prepared','submitting','requested','not_submitted','unknown')),created_at datetime NOT NULL,submitted_at datetime);
CREATE INDEX idx_github_cancellations_server ON github_cancellations(server_id,created_at);
INSERT INTO roles(id,name)VALUES('github-actions-controller','github-actions-controller'),('github-actions-logs','github-actions-logs'),('github-actions-artifacts','github-actions-artifacts');
INSERT INTO role_permissions(role_id,permission_key)VALUES('github-actions-controller','github.actions.read'),('github-actions-controller','github.actions.cancel'),('github-actions-logs','github.actions.read'),('github-actions-logs','github.actions.logs.read'),('github-actions-artifacts','github.actions.read'),('github-actions-artifacts','github.actions.artifacts.read');`).Error
}
