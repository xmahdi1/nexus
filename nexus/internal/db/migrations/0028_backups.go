package migrations

import "gorm.io/gorm"

func Backups(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE backup_policies(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,name text NOT NULL,actor_id text NOT NULL,config_enc text NOT NULL,digest text NOT NULL,mode text NOT NULL,interval_minutes integer NOT NULL,next_at datetime,enabled numeric NOT NULL DEFAULT 0,archived numeric NOT NULL DEFAULT 0,last_run_id text NOT NULL DEFAULT '',last_state text NOT NULL DEFAULT '',last_success_at datetime,last_check_at datetime,last_restore_at datetime,created_at datetime NOT NULL);
CREATE INDEX idx_backup_policies_due ON backup_policies(enabled,next_at);
CREATE INDEX idx_backup_policies_scope ON backup_policies(server_id,created_at);
CREATE TABLE backup_run_cleanup(run_id text PRIMARY KEY NOT NULL,cleaned numeric NOT NULL DEFAULT 0,finalized numeric NOT NULL DEFAULT 0);
INSERT INTO roles(id,name)VALUES('backup-reader','backup-reader'),('backup-administrator','backup-administrator'),('nexus-backup-administrator','nexus-backup-administrator');
INSERT INTO role_permissions(role_id,permission_key)VALUES
('backup-reader','backups.read'),('backup-reader','servers.read'),
('backup-administrator','backups.read'),('backup-administrator','backups.manage'),('backup-administrator','backups.execute'),('backup-administrator','backups.restore'),('backup-administrator','backups.schedule'),('backup-administrator','servers.read'),('backup-administrator','servers.connect'),('backup-administrator','secrets.use'),('backup-administrator','secrets.create'),('backup-administrator','jobs.read'),('backup-administrator','jobs.execute'),('backup-administrator','jobs.cancel'),('backup-administrator','jobs.manage'),('backup-administrator','logs.read'),
('nexus-backup-administrator','backups.nexus.manage'),('nexus-backup-administrator','backups.read'),('nexus-backup-administrator','backups.manage'),('nexus-backup-administrator','backups.execute'),('nexus-backup-administrator','backups.restore'),('nexus-backup-administrator','backups.schedule'),('nexus-backup-administrator','secrets.use'),('nexus-backup-administrator','secrets.create'),('nexus-backup-administrator','secrets.reveal'),('nexus-backup-administrator','jobs.read'),('nexus-backup-administrator','jobs.execute'),('nexus-backup-administrator','jobs.cancel'),('nexus-backup-administrator','jobs.manage'),('nexus-backup-administrator','logs.read');`).Error
}
