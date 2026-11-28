package migrations

import "gorm.io/gorm"

// Preserve invocation/output identities while extending the closed run kinds.
func AnsibleExecution(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE supervised_runs_next(
id text PRIMARY KEY NOT NULL,task_id text NOT NULL,server_id text NOT NULL,actor_id text NOT NULL,command_hash text NOT NULL,state text NOT NULL,
invocation_id text NOT NULL DEFAULT '',output_enc text NOT NULL DEFAULT '',exit_code integer,truncated numeric NOT NULL DEFAULT 0,
artifacts_removed numeric NOT NULL DEFAULT 0,detail text NOT NULL DEFAULT '',created_at datetime NOT NULL,dispatch_started_at datetime,
cancel_requested_at datetime,verified_at datetime,last_checked_at datetime,finished_at datetime,
kind text NOT NULL DEFAULT 'scheduled' CHECK(kind IN ('scheduled','operation','ansible')),action text NOT NULL DEFAULT '',
source_session_id text NOT NULL DEFAULT '',target_hash text NOT NULL DEFAULT '',operation_context text NOT NULL DEFAULT '');
INSERT INTO supervised_runs_next SELECT id,task_id,server_id,actor_id,command_hash,state,invocation_id,output_enc,exit_code,truncated,
artifacts_removed,detail,created_at,dispatch_started_at,cancel_requested_at,verified_at,last_checked_at,finished_at,
kind,action,source_session_id,target_hash,operation_context FROM supervised_runs;
DROP TABLE supervised_runs;
ALTER TABLE supervised_runs_next RENAME TO supervised_runs;
CREATE INDEX idx_supervised_runs_task ON supervised_runs(server_id,task_id,created_at);
CREATE UNIQUE INDEX idx_supervised_one_unresolved ON supervised_runs(server_id) WHERE finished_at IS NULL;
CREATE INDEX idx_supervised_kind_server ON supervised_runs(kind,server_id,created_at);
CREATE TABLE ansible_run_plans(run_id text PRIMARY KEY NOT NULL,plan_id text UNIQUE NOT NULL);
CREATE TABLE execution_host_locks(server_id text PRIMARY KEY NOT NULL,run_id text NOT NULL);
CREATE INDEX idx_execution_host_locks_run ON execution_host_locks(run_id);`).Error
}
