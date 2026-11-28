package migrations

import "gorm.io/gorm"

func AnsibleOrchestration(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE ansible_queue(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,plan_id text UNIQUE NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,state text NOT NULL CHECK(state IN ('waiting','admitted','cancelled','blocked','expired')),detail text NOT NULL DEFAULT '',after_run_id text NOT NULL DEFAULT '',not_before datetime NOT NULL,expires_at datetime NOT NULL,created_at datetime NOT NULL,admitted_at datetime);
CREATE INDEX idx_ansible_queue_due ON ansible_queue(state,not_before,created_at);
CREATE TABLE ansible_schedules(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,name text NOT NULL,preset_id text NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,config_enc text NOT NULL,digest text NOT NULL,interval_minutes integer NOT NULL,next_at datetime NOT NULL,enabled numeric NOT NULL DEFAULT 1,pending_plan_id text NOT NULL DEFAULT '',last_state text NOT NULL DEFAULT '',created_at datetime NOT NULL);
CREATE INDEX idx_ansible_schedules_due ON ansible_schedules(enabled,next_at);
INSERT INTO roles(id,name)VALUES('ansible-scheduler','ansible-scheduler');
INSERT INTO role_permissions(role_id,permission_key)VALUES('ansible-scheduler','ansible.projects.read'),('ansible-scheduler','ansible.schedules.manage');`).Error
}
