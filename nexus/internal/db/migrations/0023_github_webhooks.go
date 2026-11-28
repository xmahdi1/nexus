package migrations

import "gorm.io/gorm"

func GitHubWebhooks(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE github_webhooks(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,connection_id text NOT NULL UNIQUE,endpoint_id text NOT NULL UNIQUE,secret_enc text NOT NULL,disabled numeric NOT NULL DEFAULT 0,created_by text NOT NULL,created_at datetime NOT NULL);
CREATE TABLE github_webhook_receipts(id text PRIMARY KEY NOT NULL,hook_id text NOT NULL,delivery_hash text NOT NULL,body_hash text NOT NULL,event text NOT NULL,received_at datetime NOT NULL,UNIQUE(hook_id,delivery_hash),UNIQUE(hook_id,body_hash));
CREATE INDEX idx_github_webhook_receipts_time ON github_webhook_receipts(hook_id,received_at);
CREATE TABLE github_run_observations(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,connection_id text NOT NULL,run_id integer NOT NULL,run_attempt integer NOT NULL,workflow_id integer NOT NULL,status text NOT NULL,conclusion text NOT NULL,head_sha text NOT NULL,source_updated_at datetime NOT NULL,state_rank integer NOT NULL,received_at datetime NOT NULL,UNIQUE(connection_id,run_id));
CREATE INDEX idx_github_run_observations_scope ON github_run_observations(server_id,connection_id,received_at);
INSERT INTO roles(id,name)VALUES('github-webhooks','github-webhooks');
INSERT INTO role_permissions(role_id,permission_key)VALUES('github-webhooks','github.actions.read'),('github-webhooks','github.webhooks.manage');`).Error
}
