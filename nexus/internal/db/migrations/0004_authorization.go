package migrations

import (
	"gorm.io/gorm"
	"time"
)

func Authorization(tx *gorm.DB) error {
	if err := tx.Exec(`CREATE TABLE roles(id text PRIMARY KEY NOT NULL,name text NOT NULL UNIQUE);
 CREATE TABLE role_permissions(role_id text NOT NULL REFERENCES roles(id),permission_key text NOT NULL,PRIMARY KEY(role_id,permission_key));
 CREATE TABLE role_grants(id text PRIMARY KEY NOT NULL,principal_id text NOT NULL,principal_kind text NOT NULL CHECK(principal_kind IN ('legacy','user','service')),role_id text NOT NULL REFERENCES roles(id),scope_type text NOT NULL CHECK(scope_type IN ('global','server_group','server')),scope_id text NOT NULL CHECK((scope_type='global' AND scope_id='') OR (scope_type!='global' AND length(scope_id)>0)),created_by text NOT NULL,created_at datetime NOT NULL,UNIQUE(principal_id,principal_kind,role_id,scope_type,scope_id));
 CREATE INDEX idx_role_grants_principal ON role_grants(principal_id);
 CREATE TABLE server_groups(id text PRIMARY KEY NOT NULL,name text NOT NULL COLLATE NOCASE UNIQUE CHECK(length(trim(name)) BETWEEN 1 AND 80),created_at datetime NOT NULL);
 CREATE TABLE server_group_members(group_id text NOT NULL REFERENCES server_groups(id),server_id text NOT NULL REFERENCES servers(id),PRIMARY KEY(group_id,server_id));
 CREATE TABLE service_principals(id text PRIMARY KEY NOT NULL,name text NOT NULL,status text NOT NULL CHECK(status IN ('active','disabled')));
 CREATE TABLE authorization_events(id integer PRIMARY KEY AUTOINCREMENT,at datetime NOT NULL,actor_id text NOT NULL,action text NOT NULL,resource_id text NOT NULL,outcome text NOT NULL,request_id text NOT NULL);
 CREATE INDEX idx_authorization_events_at ON authorization_events(at);
 ALTER TABLE scheduled_tasks ADD COLUMN actor_id text NOT NULL DEFAULT '';
 ALTER TABLE scheduled_tasks ADD COLUMN created_by text NOT NULL DEFAULT '';
 ALTER TABLE scheduled_tasks ADD COLUMN run_id text NOT NULL DEFAULT '';
 ALTER TABLE scheduled_tasks ADD COLUMN lease_until datetime;
 `).Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "viewer", "viewer").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "servers.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "metrics.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "docker.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "network.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "firewall.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "proxy.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "inventory.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "viewer", "secrets.use").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "operator", "operator").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "servers.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "metrics.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "docker.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "network.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "firewall.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "proxy.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "inventory.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "secrets.use").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "operator", "docker.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "admin", "admin").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "servers.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "servers.create").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "servers.update").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "servers.delete").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "servers.connect").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "metrics.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "docker.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "docker.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "docker.remove").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "network.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "firewall.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "firewall.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "proxy.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "proxy.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "inventory.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "inventory.discover").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "inventory.edit").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "inventory.export").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "deployments.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "deployments.approve").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "jobs.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "jobs.create").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "jobs.execute").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "jobs.cancel").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "jobs.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "secrets.metadata.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "secrets.create").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "secrets.use").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "secrets.rotate").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "users.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "users.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "roles.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "sessions.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "audit.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "settings.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "integrations.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "services.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "services.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "templates.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "templates.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "groups.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "admin", "groups.manage").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "host-control", "host-control").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "servers.terminal").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "servers.execute").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "files.list").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "files.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "files.write").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "files.delete").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "docker.exec").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "compose.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "compose.write").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "deployments.execute").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "deployments.rollback").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "secrets.use").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "host-control", "servers.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "log-reader", "log-reader").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "log-reader", "logs.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "log-reader", "servers.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "log-reader", "secrets.use").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "secret-reader", "secret-reader").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "secret-reader", "secrets.reveal").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "secret-reader", "secrets.metadata.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO roles(id,name) VALUES(?,?)", "collector", "collector").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "servers.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "servers.connect").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "metrics.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "docker.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "proxy.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "network.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "inventory.read").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES(?,?)", "collector", "secrets.use").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES('collector','notifications.send')").Error; err != nil {
		return err
	}
	if err := tx.Exec("UPDATE scheduled_tasks SET last_status='interrupted',enabled=0,last_output=COALESCE(last_output,'') || char(10) || 'Prior execution state is uncertain; review before enabling again.' WHERE last_status='running'").Error; err != nil {
		return err
	}
	var state struct{ Mode, OwnerUserID string }
	if err := tx.Table("auth_state").Where("id=1").Take(&state).Error; err != nil {
		return err
	}
	actor, kind := "legacy-admin", "legacy"
	if state.Mode == "owner" {
		actor, kind = state.OwnerUserID, "user"
	}
	for _, role := range []string{"admin", "host-control", "log-reader"} {
		if err := tx.Exec("INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES(?,?,?,?,'global','','migration-0004',?)", "compat-"+role, actor, kind, role, time.Now().UTC()).Error; err != nil {
			return err
		}
	}
	if err := tx.Exec("UPDATE scheduled_tasks SET actor_id=? WHERE actor_id=''", actor).Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO service_principals(id,name,status) VALUES('system-monitor','Built-in read-only monitor','active')").Error; err != nil {
		return err
	}
	if err := tx.Exec("INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES('monitor-collector','system-monitor','service','collector','global','','migration-0004',?)", time.Now().UTC()).Error; err != nil {
		return err
	}
	return nil
}
