package migrations

import "gorm.io/gorm"

// Interactive operations share the existing per-host admission lock, encrypted
// output and process-identity protocol with scheduled runs. An empty task_id is
// reserved for kind=operation; normal task IDs are always generated nonempty.
func InteractiveOperations(tx *gorm.DB) error {
	return tx.Exec(`ALTER TABLE supervised_runs ADD COLUMN kind text NOT NULL DEFAULT 'scheduled' CHECK(kind IN ('scheduled','operation'));
ALTER TABLE supervised_runs ADD COLUMN action text NOT NULL DEFAULT '';
ALTER TABLE supervised_runs ADD COLUMN source_session_id text NOT NULL DEFAULT '';
ALTER TABLE supervised_runs ADD COLUMN target_hash text NOT NULL DEFAULT '';
CREATE INDEX idx_supervised_kind_server ON supervised_runs(kind,server_id,created_at);`).Error
}
