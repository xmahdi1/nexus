package authorization

import "strings"

func Risk(policy Policy) string {
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
		case "ansible.environment.manage", "secrets.reveal", "docker.exec", "servers.execute", "files.write", "files.delete", "compose.write", "deployments.execute", "firewall.manage", "proxy.manage":
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
