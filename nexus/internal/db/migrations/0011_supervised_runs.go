package migrations

import "gorm.io/gorm"

func SupervisedRuns(tx *gorm.DB) error {
	return tx.Exec(`ALTER TABLE scheduled_tasks ADD COLUMN supervised numeric NOT NULL DEFAULT 0;
 CREATE TABLE supervised_runs(id text PRIMARY KEY NOT NULL,task_id text NOT NULL,server_id text NOT NULL,actor_id text NOT NULL,command_hash text NOT NULL,state text NOT NULL,invocation_id text NOT NULL DEFAULT '',output_enc text NOT NULL DEFAULT '',exit_code integer,truncated numeric NOT NULL DEFAULT 0,artifacts_removed numeric NOT NULL DEFAULT 0,detail text NOT NULL DEFAULT '',created_at datetime NOT NULL,dispatch_started_at datetime,cancel_requested_at datetime,verified_at datetime,last_checked_at datetime,finished_at datetime);
 CREATE INDEX idx_supervised_runs_task ON supervised_runs(server_id,task_id,created_at);
 CREATE UNIQUE INDEX idx_supervised_one_unresolved ON supervised_runs(server_id) WHERE finished_at IS NULL;
 `).Error
}
