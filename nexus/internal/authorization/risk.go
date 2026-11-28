package authorization

import "strings"

func Risk(policy Policy) string {
	for _, permission := range policy.Permissions {
		if permission == "github.runners.manage" {
			return "high"
		}
	}
	if strings.Contains(policy.Path, "/vault") && policy.Method != "GET" {
		return "high"
	}
	if strings.HasPrefix(policy.Path, "/ws/terminal/") {
		return "critical"
	}
	if policy.Method == "DELETE" {
		return "high"
	}
	for _, p := range policy.Permissions {
		switch p {
		case "github.projects.read", "github.organizations.read", "github.organizations.connections.manage", "github.organizations.runners.manage", "github.organizations.runners.register", "github.webhooks.manage", "github.runners.provider.read", "github.runners.provider.manage", "github.workflows.read", "github.workflows.write", "github.actions.cancel", "github.actions.logs.read", "github.actions.artifacts.read", "github.connections.manage", "github.actions.dispatch", "ansible.projects.manage", "ansible.playbooks.execute", "ansible.playbooks.approve", "ansible.environment.manage", "secrets.reveal", "docker.exec", "servers.execute", "files.write", "files.delete", "compose.write", "deployments.execute", "firewall.manage", "proxy.manage":
			return "high"
		}
	}
	return "low"
}
func (s *Service) Protected(server string) (bool, error) {
	var count int64
	err := s.DB.Table("server_group_members m").Joins("JOIN server_groups g ON g.id=m.group_id").Where("m.server_id=? AND g.require_mfa=1", server).Count(&count).Error
	return count > 0, err
}
