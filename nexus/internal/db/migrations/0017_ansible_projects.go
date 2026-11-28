package migrations

import "gorm.io/gorm"

func AnsibleProjects(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE ansible_projects(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,name text NOT NULL,created_by text NOT NULL,created_at datetime NOT NULL,archived numeric NOT NULL DEFAULT 0);
 CREATE INDEX idx_ansible_projects_server ON ansible_projects(server_id,id);
 CREATE TABLE ansible_revisions(id text PRIMARY KEY NOT NULL,project_id text NOT NULL,server_id text NOT NULL,digest text NOT NULL,bundle_enc text NOT NULL,created_by text NOT NULL,created_at datetime NOT NULL);
 CREATE INDEX idx_ansible_revisions_project ON ansible_revisions(server_id,project_id,created_at);
 CREATE TABLE ansible_plans(id text PRIMARY KEY NOT NULL,project_id text NOT NULL,revision_id text NOT NULL,server_id text NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,digest text NOT NULL,config_enc text NOT NULL,state text NOT NULL CHECK(state IN ('prepared','approved','cancelled')),approved_by text NOT NULL DEFAULT '',approver_session_id text NOT NULL DEFAULT '',created_at datetime NOT NULL,expires_at datetime NOT NULL,approved_at datetime);
 CREATE INDEX idx_ansible_plans_server ON ansible_plans(server_id,created_at);
 INSERT INTO roles(id,name) VALUES ('ansible-projects','ansible-projects'),('ansible-executor','ansible-executor'),('ansible-approver','ansible-approver');
 INSERT INTO role_permissions(role_id,permission_key) VALUES
 ('ansible-projects','ansible.projects.read'),('ansible-projects','ansible.projects.manage'),
 ('ansible-executor','ansible.projects.read'),('ansible-executor','ansible.playbooks.execute'),
 ('ansible-approver','ansible.projects.read'),('ansible-approver','ansible.playbooks.approve');`).Error
}
