package migrations

import "gorm.io/gorm"

func GitHubOrganizations(tx *gorm.DB) error {
	return tx.Exec(`CREATE TABLE github_organizations(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,login text NOT NULL,organization_id integer NOT NULL,client_id text NOT NULL,installation_id integer NOT NULL,config_enc text NOT NULL,disabled numeric NOT NULL DEFAULT 0,created_by text NOT NULL,created_at datetime NOT NULL);
CREATE INDEX idx_github_organizations_scope ON github_organizations(server_id,created_at);
CREATE TABLE github_organization_changes(id text PRIMARY KEY NOT NULL,server_id text NOT NULL,connection_id text NOT NULL,actor_id text NOT NULL,source_session_id text NOT NULL,kind text NOT NULL CHECK(kind IN ('runner_remove','registration')),input_enc text NOT NULL,state text NOT NULL CHECK(state IN ('prepared','submitting','applied','not_submitted','unknown')),resource_id integer NOT NULL DEFAULT 0,created_at datetime NOT NULL,submitted_at datetime,expires_at datetime);
CREATE INDEX idx_github_org_changes_scope ON github_organization_changes(server_id,connection_id,created_at);
INSERT INTO roles(id,name)VALUES('github-org-connections','github-org-connections'),('github-org-runners-reader','github-org-runners-reader'),('github-org-runners-manager','github-org-runners-manager'),('github-org-runners-enroller','github-org-runners-enroller');
INSERT INTO role_permissions(role_id,permission_key)VALUES
('github-org-connections','github.organizations.read'),('github-org-connections','github.organizations.connections.manage'),
('github-org-runners-reader','github.organizations.read'),
('github-org-runners-manager','github.organizations.read'),('github-org-runners-manager','github.organizations.runners.manage'),
('github-org-runners-enroller','github.organizations.read'),('github-org-runners-enroller','github.organizations.runners.register');`).Error
}
