package migrations

import "gorm.io/gorm"

func BackupManagement(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE backup_policy_settings(policy_id text PRIMARY KEY NOT NULL,keep_last integer NOT NULL,max_age_minutes integer NOT NULL,verify_after_days integer NOT NULL,updated_by text NOT NULL,updated_at datetime NOT NULL);
CREATE TABLE backup_retention_jobs(run_id text PRIMARY KEY NOT NULL,binding text NOT NULL,request_enc text NOT NULL);
CREATE TABLE backup_retention_claims(preview_run_id text PRIMARY KEY NOT NULL,run_id text UNIQUE NOT NULL);
CREATE TABLE backup_coverage_scans(scope_id text PRIMARY KEY NOT NULL,scanned_at datetime NOT NULL,watch_gaps numeric NOT NULL,report_json text NOT NULL);
CREATE TABLE backup_alerts(id text PRIMARY KEY NOT NULL,scope_id text NOT NULL,policy_id text NOT NULL,code text NOT NULL,severity text NOT NULL,state text NOT NULL,first_seen_at datetime NOT NULL,last_seen_at datetime NOT NULL,resolved_at datetime);
CREATE INDEX idx_backup_alerts_scope ON backup_alerts(scope_id,state,last_seen_at);
INSERT INTO roles(id,name)VALUES('backup-retention-manager','backup-retention-manager');
INSERT INTO role_permissions(role_id,permission_key)VALUES('backup-retention-manager','backups.prune');`).Error
}
