package authorization

import "strings"

const LegacyPrincipal = "legacy-admin"
const MonitorPrincipal = "system-monitor"

// These are role templates, not evaluator shortcuts. Runtime decisions use the
// versioned role_permissions rows and validated resource scopes.
var RoleTemplates = map[string][]string{
	"viewer":        strings.Fields(`servers.read metrics.read docker.read network.read firewall.read proxy.read inventory.read secrets.use`),
	"operator":      strings.Fields(`servers.read metrics.read docker.read network.read firewall.read proxy.read inventory.read secrets.use docker.manage`),
	"admin":         strings.Fields(`servers.read servers.create servers.update servers.delete servers.connect metrics.read docker.read docker.manage docker.remove network.read firewall.read firewall.manage proxy.read proxy.manage inventory.read inventory.discover inventory.edit inventory.export deployments.read deployments.approve jobs.read jobs.create jobs.execute jobs.cancel jobs.manage secrets.metadata.read secrets.create secrets.use secrets.rotate users.read users.manage roles.manage sessions.manage audit.read settings.manage integrations.manage services.read services.manage templates.read templates.manage groups.read groups.manage`),
	"host-control":  strings.Fields(`servers.terminal servers.execute files.list files.read files.write files.delete docker.exec compose.read compose.write deployments.execute deployments.rollback secrets.use servers.read`),
	"log-reader":    strings.Fields(`logs.read servers.read secrets.use`),
	"secret-reader": strings.Fields(`secrets.reveal secrets.metadata.read`),
	"collector":     strings.Fields(`notifications.send servers.read servers.connect metrics.read docker.read proxy.read network.read inventory.read secrets.use`),
}
var known = func() map[string]bool {
	m := map[string]bool{}
	for _, permissions := range RoleTemplates {
		for _, p := range permissions {
			m[p] = true
		}
	}
	return m
}()

func Known(permission string) bool { return known[permission] }

type Policy struct {
	Method, Path string
	Permissions  []string
	Scope        string
	Self         bool
}

// Scope is global, server, or collection. Self routes still require a live
// session but cannot be used to administer someone else's account/device.
var Policies = []Policy{}

func register(method, path, scope, permissions string) {
	Policies = append(Policies, Policy{Method: method, Path: path, Scope: scope, Permissions: strings.Fields(permissions)})
}
func self(method, path string) {
	Policies = append(Policies, Policy{Method: method, Path: path, Self: true})
}
func init() {
	for _, row := range []string{"GET /api/users users.read", "GET /api/users/invitations users.read", "POST /api/users/invitations users.manage", "DELETE /api/users/invitations/{inviteId} users.manage", "PATCH /api/users/{uid} users.manage", "POST /api/users/{uid}/resets users.manage", "POST /api/users/{uid}/unlock users.manage"} {
		p := strings.Fields(row)
		permissions := p[2]
		if p[0] != "GET" {
			permissions += " roles.manage"
		}
		register(p[0], p[1], "global", permissions)
	}

	for _, route := range []string{"POST /api/auth/logout", "GET /api/auth/me", "GET /api/auth/sessions", "DELETE /api/auth/sessions/{sid}", "POST /api/auth/logout-all", "POST /api/auth/password", "GET /api/auth/mfa/status", "POST /api/auth/mfa/setup", "POST /api/auth/mfa/enable", "POST /api/auth/mfa/disable", "POST /api/auth/mfa/recovery-codes", "GET /api/auth/permissions"} {
		parts := strings.SplitN(route, " ", 2)
		self(parts[0], parts[1])
	}
	register("GET", "/api/auth/audit", "global", "audit.read")
	register("POST", "/api/keys/generate", "global", "secrets.create")
	register("GET", "/api/servers", "collection", "servers.read")
	register("POST", "/api/servers", "global", "servers.create secrets.create")
	register("GET", "/api/servers/{id}", "server", "servers.read")
	register("DELETE", "/api/servers/{id}", "server", "servers.delete")
	register("POST", "/api/servers/{id}/test", "server", "servers.connect secrets.use")
	register("PATCH", "/api/servers/{id}/tags", "server", "servers.update")
	register("GET", "/api/servers/{id}/metrics", "server", "metrics.read secrets.use")
	register("GET", "/api/servers/{id}/containers", "server", "docker.read secrets.use")
	for _, action := range []string{"start", "stop", "restart"} {
		register("POST", "/api/servers/{id}/containers/{cid}/"+action, "server", "docker.manage secrets.use")
	}
	register("DELETE", "/api/servers/{id}/containers/{cid}", "server", "docker.remove secrets.use")
	register("POST", "/api/servers/{id}/containers/{cid}/exec", "server", "docker.exec secrets.use")
	register("GET", "/api/servers/{id}/compose", "server", "compose.read secrets.use")
	register("PUT", "/api/servers/{id}/compose", "server", "compose.write secrets.use")
	for _, action := range []string{"up", "down"} {
		register("POST", "/api/servers/{id}/compose/"+action, "server", "deployments.execute secrets.use")
	}
	for _, row := range []string{"GET files files.list", "GET files/preview files.read", "GET files/download files.read", "POST files/upload files.write", "DELETE files files.delete", "POST files/mkdir files.write", "PUT files files.write"} {
		p := strings.Fields(row)
		register(p[0], "/api/servers/{id}/"+p[1], "server", p[2]+" secrets.use")
	}
	register("GET", "/api/servers/{id}/proxy/detect", "server", "proxy.read secrets.use")
	register("GET", "/api/servers/{id}/proxy", "server", "proxy.read")
	for _, row := range []string{"POST proxy", "DELETE proxy/{ruleId}", "PUT proxy/{ruleId}", "POST proxy/{ruleId}/ssl"} {
		p := strings.Fields(row)
		register(p[0], "/api/servers/{id}/"+p[1], "server", "proxy.manage secrets.use")
	}
	register("GET", "/api/services", "global", "services.read")
	for _, row := range []string{"POST /api/services", "PUT /api/services/{id}", "DELETE /api/services/{id}"} {
		p := strings.Fields(row)
		register(p[0], p[1], "global", "services.manage")
	}
	register("GET", "/api/monitor/status", "collection", "metrics.read")
	for _, method := range []string{"GET", "PUT"} {
		register(method, "/api/monitor/config", "global", "settings.manage")
	}
	register("POST", "/api/monitor/config/test", "global", "integrations.manage")
	register("GET", "/api/servers/{id}/monitor/containers", "server", "docker.read")
	register("POST", "/api/servers/{id}/monitor/containers", "server", "settings.manage docker.read secrets.use")
	register("DELETE", "/api/servers/{id}/monitor/containers/{containerId}", "server", "settings.manage")
	register("GET", "/api/servers/{id}/alerts", "server", "metrics.read")
	register("PUT", "/api/servers/{id}/alerts", "server", "settings.manage")
	register("GET", "/api/templates", "global", "templates.read compose.read")
	for _, row := range []string{"POST custom", "PUT custom/{id}", "DELETE custom/{id}"} {
		p := strings.Fields(row)
		register(p[0], "/api/templates/"+p[1], "global", "templates.manage")
	}
	register("GET", "/api/servers/{id}/apps", "server", "deployments.read secrets.use")
	register("POST", "/api/servers/{id}/apps/deploy", "server", "deployments.execute secrets.use")
	register("DELETE", "/api/servers/{id}/apps/{appId}", "server", "deployments.execute secrets.use")
	register("GET", "/api/servers/{id}/cron", "server", "jobs.read logs.read secrets.use")
	for _, method := range []string{"POST", "DELETE"} {
		register(method, "/api/servers/{id}/cron", "server", "jobs.manage servers.execute secrets.use")
	}
	register("GET", "/api/servers/{id}/tasks", "server", "jobs.read logs.read")
	register("POST", "/api/servers/{id}/tasks", "server", "jobs.create jobs.execute servers.execute secrets.use")
	register("PUT", "/api/servers/{id}/tasks/{tid}", "server", "jobs.manage jobs.execute servers.execute secrets.use")
	register("DELETE", "/api/servers/{id}/tasks/{tid}", "server", "jobs.manage")
	register("POST", "/api/servers/{id}/tasks/{tid}/run", "server", "jobs.execute servers.execute secrets.use")
	register("GET", "/api/servers/{id}/firewall", "server", "firewall.read network.read secrets.use")
	for _, row := range []string{"POST enable", "POST disable", "POST rules", "DELETE rules/{n}"} {
		p := strings.Fields(row)
		register(p[0], "/api/servers/{id}/firewall/"+p[1], "server", "firewall.manage secrets.use")
	}
	register("GET", "/ws/terminal/{id}", "server", "servers.terminal servers.execute secrets.use")
	register("GET", "/ws/logs/{id}/{cid}", "server", "logs.read secrets.use")
	register("GET", "/ws/metrics/{id}", "server", "metrics.read secrets.use")
	for _, row := range []string{"GET /api/roles users.read", "GET /api/grants users.read", "POST /api/grants roles.manage", "DELETE /api/grants/{grantId} roles.manage", "GET /api/server-groups groups.read", "POST /api/server-groups groups.manage", "PUT /api/server-groups/{gid}/servers/{serverId} groups.manage", "DELETE /api/server-groups/{gid}/servers/{serverId} groups.manage", "DELETE /api/server-groups/{gid} groups.manage", "GET /api/authorization/events audit.read"} {
		p := strings.Fields(row)
		permissions := p[2]
		if strings.Contains(p[1], "/servers/") || (p[0] == "DELETE" && p[1] == "/api/server-groups/{gid}") {
			permissions += " roles.manage"
		}
		register(p[0], p[1], "global", permissions)
	}
}

// Resolve is intentionally independent of route registration. A newly added
// handler without an explicit registry entry is denied by common middleware.
func Resolve(method, path string) (Policy, map[string]string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, policy := range Policies {
		if policy.Method != method {
			continue
		}
		pattern := strings.Split(strings.Trim(policy.Path, "/"), "/")
		if len(parts) != len(pattern) {
			continue
		}
		params := map[string]string{}
		match := true
		for i, p := range pattern {
			if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
				if parts[i] == "" {
					match = false
					break
				}
				params[strings.Trim(p, "{}")] = parts[i]
			} else if p != parts[i] {
				match = false
				break
			}
		}
		if match {
			return policy, params, true
		}
	}
	return Policy{}, nil, false
}

func Public(method, path string) bool {
	if method != "POST" {
		return false
	}
	switch path {
	case "/api/auth/login", "/api/auth/mfa/verify", "/api/auth/mfa/recovery", "/api/auth/invitations/accept", "/api/auth/reset/info", "/api/auth/reset/password", "/api/auth/reset/mfa/setup", "/api/auth/reset/mfa/confirm":
		return true
	}
	return false
}
