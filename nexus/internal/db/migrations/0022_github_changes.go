package migrations

import "gorm.io/gorm"

func GitHubChanges(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE github_changes(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,connection_id text NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('runner_remove','workflow_edit')),input_enc text NOT NULL,state text NOT NULL CHECK(state IN ('prepared','submitting','branch_created','file_written','applied','not_submitted','incomplete','unknown')),phase text NOT NULL DEFAULT '',resource_id integer NOT NULL DEFAULT 0,branch text NOT NULL DEFAULT '',commit_sha text NOT NULL DEFAULT '',pull_number integer NOT NULL DEFAULT 0,created_at datetime NOT NULL,submitted_at datetime);
CREATE INDEX idx_github_changes_server ON github_changes(server_id,created_at);
INSERT INTO roles(id,name)VALUES('github-provider-runners-reader','github-provider-runners-reader'),('github-provider-runners-manager','github-provider-runners-manager'),('github-workflow-reader','github-workflow-reader'),('github-workflow-editor','github-workflow-editor');
INSERT INTO role_permissions(role_id,permission_key)VALUES('github-provider-runners-reader','github.actions.read'),('github-provider-runners-reader','github.runners.provider.read'),('github-provider-runners-manager','github.actions.read'),('github-provider-runners-manager','github.runners.provider.read'),('github-provider-runners-manager','github.runners.provider.manage'),('github-workflow-reader','github.actions.read'),('github-workflow-reader','github.workflows.read'),('github-workflow-editor','github.actions.read'),('github-workflow-editor','github.workflows.read'),('github-workflow-editor','github.workflows.write');`).Error
}
