package migrations

import "gorm.io/gorm"

func OperationAudit(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE operation_events (
 id integer PRIMARY KEY AUTOINCREMENT,
 operation_id text NOT NULL, at datetime NOT NULL, actor_id text NOT NULL,
 session_id text NOT NULL, action text NOT NULL, resource_type text NOT NULL,
 resource_id text NOT NULL, server_id text NOT NULL, source text NOT NULL,
 outcome text NOT NULL, request_id text NOT NULL, http_status integer NOT NULL DEFAULT 0,
 duration_ms integer NOT NULL DEFAULT 0
 );
 CREATE INDEX idx_operation_events_operation ON operation_events(operation_id,id);
 CREATE INDEX idx_operation_events_actor ON operation_events(actor_id,id);
 CREATE INDEX idx_operation_events_server ON operation_events(server_id,id);
 CREATE INDEX idx_operation_events_at ON operation_events(at);
 CREATE TRIGGER operation_events_no_update BEFORE UPDATE ON operation_events BEGIN SELECT RAISE(ABORT,'operation events are append only'); END;`).Error
}
