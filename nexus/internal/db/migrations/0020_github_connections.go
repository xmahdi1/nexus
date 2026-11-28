package migrations

import "gorm.io/gorm"

func GitHubConnections(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE github_connections(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,owner text NOT NULL,name text NOT NULL,repository_id integer NOT NULL,client_id text NOT NULL,installation_id integer NOT NULL,config_enc text NOT NULL,created_by text NOT NULL,created_at datetime NOT NULL,disabled numeric NOT NULL DEFAULT 0);
CREATE INDEX idx_github_connections_server ON github_connections(server_id,created_at);
CREATE TABLE github_dispatches(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,connection_id text NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,input_enc text NOT NULL,state text NOT NULL CHECK(state IN ('prepared','submitting','submitted','not_submitted','unknown')),workflow_id integer NOT NULL,ref text NOT NULL,run_id integer NOT NULL DEFAULT 0,created_at datetime NOT NULL,submitted_at datetime);
CREATE INDEX idx_github_dispatches_server ON github_dispatches(server_id,created_at);
INSERT INTO roles(id,name)VALUES('github-actions-reader','github-actions-reader'),('github-connections','github-connections'),('github-actions-dispatcher','github-actions-dispatcher');
INSERT INTO role_permissions(role_id,permission_key)VALUES('github-actions-reader','github.actions.read'),('github-connections','github.connections.manage'),('github-connections','github.actions.read'),('github-actions-dispatcher','github.actions.read'),('github-actions-dispatcher','github.actions.dispatch');`).Error
}
