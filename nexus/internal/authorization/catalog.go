package authorization

import (
	"strings"

	"github.com/xmahdi1/nexus/internal/remoteaction"
	"github.com/xmahdi1/nexus/internal/vault"
)

const LegacyPrincipal = "legacy-admin"
const MonitorPrincipal = "system-monitor"

// These are role templates, not evaluator shortcuts. Runtime decisions use the
// versioned role_permissions rows and validated resource scopes.
var RoleTemplates = map[string][]string{
	"backup-retention-manager":        strings.Fields(`backups.prune`),
	"backup-reader":                   strings.Fields(`backups.read servers.read`),
	"backup-administrator":            strings.Fields(`backups.read backups.manage backups.execute backups.restore backups.schedule servers.read servers.connect secrets.use secrets.create jobs.read jobs.execute jobs.cancel jobs.manage logs.read`),
	"nexus-backup-administrator":      strings.Fields(`backups.nexus.manage backups.read backups.manage backups.execute backups.restore backups.schedule secrets.use secrets.create secrets.reveal jobs.read jobs.execute jobs.cancel jobs.manage logs.read`),
	"ansible-scheduler":               strings.Fields(`ansible.projects.read ansible.schedules.manage`),
	"github-projects-reader":          strings.Fields(`github.actions.read github.projects.read`),
	"github-org-connections":          strings.Fields(`github.organizations.read github.organizations.connections.manage`),
	"github-org-runners-reader":       strings.Fields(`github.organizations.read`),
	"github-org-runners-manager":      strings.Fields(`github.organizations.read github.organizations.runners.manage`),
	"github-org-runners-enroller":     strings.Fields(`github.organizations.read github.organizations.runners.register`),
	"github-webhooks":                 strings.Fields(`github.actions.read github.webhooks.manage`),
	"github-provider-runners-reader":  strings.Fields(`github.actions.read github.runners.provider.read`),
	"github-provider-runners-manager": strings.Fields(`github.actions.read github.runners.provider.read github.runners.provider.manage`),
	"github-workflow-reader":          strings.Fields(`github.actions.read github.workflows.read`),
	"github-workflow-editor":          strings.Fields(`github.actions.read github.workflows.read github.workflows.write`),
	"github-actions-controller":       strings.Fields(`github.actions.read github.actions.cancel`),
	"github-actions-logs":             strings.Fields(`github.actions.read github.actions.logs.read`),
	"github-actions-artifacts":        strings.Fields(`github.actions.read github.actions.artifacts.read`),
	"github-actions-reader":           strings.Fields(`github.actions.read`),
	"github-connections":              strings.Fields(`github.connections.manage github.actions.read`),
	"github-actions-dispatcher":       strings.Fields(`github.actions.read github.actions.dispatch`),
	"github-runners":                  strings.Fields(`github.runners.read github.runners.manage`),
	"ansible-projects":                strings.Fields(`ansible.projects.read ansible.projects.manage`),
	"ansible-executor":                strings.Fields(`ansible.projects.read ansible.playbooks.execute`),
	"ansible-approver":                strings.Fields(`ansible.projects.read ansible.playbooks.approve`),
	"ansible-environment":             strings.Fields(`ansible.environment.read ansible.environment.manage`),
	"ansible-inventory":               strings.Fields(`servers.read ansible.inventory.read`),
	"viewer":                          strings.Fields(`servers.read metrics.read docker.read network.read firewall.read proxy.read inventory.read secrets.use`),
	"operator":                        strings.Fields(`servers.read metrics.read docker.read network.read firewall.read proxy.read inventory.read secrets.use docker.manage`),
	"admin":                           strings.Fields(`servers.read servers.create servers.update servers.delete servers.connect metrics.read docker.read docker.manage docker.remove network.read firewall.read firewall.manage proxy.read proxy.manage inventory.read inventory.discover inventory.edit inventory.export deployments.read deployments.approve jobs.read jobs.create jobs.execute jobs.cancel jobs.manage secrets.metadata.read secrets.create secrets.use secrets.rotate users.read users.manage roles.manage sessions.manage audit.read settings.manage integrations.manage services.read services.manage templates.read templates.manage groups.read groups.manage`),
	"host-control":                    strings.Fields(`servers.terminal servers.execute files.list files.read files.write files.delete docker.exec compose.read compose.write deployments.execute deployments.rollback secrets.use servers.read`),
	"log-reader":                      strings.Fields(`logs.read servers.read secrets.use`),
	"secret-reader":                   strings.Fields(`secrets.reveal secrets.metadata.read`),
	"collector":                       strings.Fields(`notifications.send servers.read servers.connect metrics.read docker.read proxy.read network.read inventory.read secrets.use`),
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
	for _, route := range []struct{ method, path, permissions string }{
		{"GET", "/api/servers/{id}/ansible/schedules", "ansible.projects.read"},
		{"POST", "/api/servers/{id}/ansible/schedules", "ansible.projects.read ansible.schedules.manage secrets.create secrets.use"},
		{"POST", "/api/servers/{id}/ansible/schedules/{scheduleId}", "ansible.projects.read ansible.schedules.manage"},
		{"GET", "/api/servers/{id}/ansible/presets", "ansible.projects.read"},
		{"POST", "/api/servers/{id}/ansible/presets", "ansible.projects.manage secrets.create"},
		{"POST", "/api/servers/{id}/ansible/presets/{presetId}/content", "ansible.projects.read secrets.reveal"},
		{"POST", "/api/servers/{id}/ansible/presets/{presetId}/prepare", "ansible.projects.read ansible.playbooks.execute secrets.use"},
		{"POST", "/api/servers/{id}/ansible/presets/{presetId}/archive", "ansible.projects.manage"},
		{"GET", "/api/servers/{id}/ansible/templates", "ansible.projects.read"},
		{"POST", "/api/servers/{id}/ansible/templates", "ansible.projects.manage secrets.create"},
		{"POST", "/api/servers/{id}/ansible/templates/{templateId}/content", "ansible.projects.read secrets.reveal"},
		{"POST", "/api/servers/{id}/ansible/templates/{templateId}/archive", "ansible.projects.manage"},
		{"POST", "/api/servers/{id}/ansible/projects/{projectId}/revisions/import", "ansible.projects.manage github.projects.read secrets.create secrets.use"},
	} {
		register(route.method, route.path, "server", route.permissions)
	}
	for _, route := range []struct{ method, path, permissions string }{
		{"GET", "/api/servers/{id}/github/organizations", "servers.read github.organizations.read"},
		{"POST", "/api/servers/{id}/github/organizations", "servers.read github.organizations.connections.manage secrets.create secrets.use"},
		{"POST", "/api/servers/{id}/github/organizations/{organizationId}/disable", "servers.read github.organizations.connections.manage"},
		{"POST", "/api/servers/{id}/github/organizations/{organizationId}/runners", "servers.read github.organizations.read secrets.use"},
		{"POST", "/api/servers/{id}/github/organizations/{organizationId}/runners/remove", "servers.read github.organizations.runners.manage secrets.use"},
		{"POST", "/api/servers/{id}/github/organizations/{organizationId}/registration-token", "servers.read github.organizations.runners.register secrets.use secrets.reveal"},
		{"GET", "/api/servers/{id}/github/organization-changes", "servers.read github.organizations.read"},
	} {
		register(route.method, route.path, "server", route.permissions)
	}
	for _, route := range []struct{ method, path, permissions string }{
		{"GET", "/api/servers/{id}/github/connections/{connectionId}/webhook", "servers.read github.webhooks.manage"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/webhook", "servers.read github.webhooks.manage secrets.create secrets.reveal"},
		{"DELETE", "/api/servers/{id}/github/connections/{connectionId}/webhook", "servers.read github.webhooks.manage"},
		{"GET", "/api/servers/{id}/github/connections/{connectionId}/events", "servers.read github.actions.read"},
		{"GET", "/api/servers/{id}/github/connections", "servers.read github.actions.read"},
		{"POST", "/api/servers/{id}/github/connections", "servers.read github.connections.manage secrets.create secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/disable", "servers.read github.connections.manage"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/workflows", "servers.read github.actions.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/dispatch", "servers.read github.actions.dispatch secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs", "servers.read github.actions.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs/{runId}/jobs", "servers.read github.actions.read secrets.use"},
		{"GET", "/api/servers/{id}/github/dispatches", "servers.read github.actions.read"},
		{"GET", "/api/servers/{id}/github/cancellations", "servers.read github.actions.read"},
		{"GET", "/api/servers/{id}/github/changes", "servers.read github.actions.read"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/provider-runners", "servers.read github.runners.provider.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/provider-runners/remove", "servers.read github.runners.provider.manage secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/workflow-file", "servers.read github.workflows.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/workflow-change", "servers.read github.workflows.write secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs/{runId}", "servers.read github.actions.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs/{runId}/cancel", "servers.read github.actions.cancel secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs/{runId}/artifacts", "servers.read github.actions.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs/{runId}/artifacts/{artifactId}/download", "servers.read github.actions.artifacts.read secrets.use"},
		{"POST", "/api/servers/{id}/github/connections/{connectionId}/runs/{runId}/jobs/{jobId}/logs", "servers.read github.actions.logs.read secrets.use"},
	} {
		register(route.method, route.path, "server", route.permissions)
	}

	for _, route := range []struct{ method, path, permissions string }{
		{"GET", "/api/servers/{id}/ansible/queue", "ansible.projects.read jobs.read"},
		{"POST", "/api/servers/{id}/ansible/plans/{planId}/queue", "ansible.projects.read ansible.playbooks.execute jobs.execute jobs.read"},
		{"POST", "/api/servers/{id}/ansible/queue/{queueId}/cancel", "ansible.projects.read jobs.cancel"},
		{"POST", "/api/servers/{id}/ansible/plans/{planId}/run", "ansible.projects.read ansible.playbooks.execute jobs.execute"},
		{"GET", "/api/servers/{id}/ansible/runs", "ansible.projects.read jobs.read"},
		{"POST", "/api/servers/{id}/ansible/runs/{rid}/inspect", "ansible.projects.read jobs.read logs.read secrets.use"},
		{"POST", "/api/servers/{id}/ansible/runs/{rid}/cancel", "ansible.projects.read jobs.cancel"},
		{"DELETE", "/api/servers/{id}/ansible/runs/{rid}/artifacts", "ansible.projects.read jobs.manage logs.read secrets.use"},
	} {
		register(route.method, route.path, "server", route.permissions)
	}
	for _, route := range []struct{ method, path, permissions string }{
		{"GET", "/policies", "backups.read"}, {"POST", "/policies", "backups.read backups.manage secrets.create secrets.use"},
		{"GET", "/health", "backups.read"}, {"POST", "/coverage", "backups.read backups.manage secrets.use"},
		{"GET", "/policies/{policyId}/settings", "backups.read"}, {"PUT", "/policies/{policyId}/settings", "backups.manage"},
		{"POST", "/policies/{policyId}/schedule", "backups.manage backups.schedule"}, {"POST", "/policies/{policyId}/archive", "backups.manage"},
		{"POST", "/policies/{policyId}/runs", "backups.read secrets.use jobs.execute"},
		{"POST", "/discover", "backups.read backups.manage secrets.use"}, {"GET", "/runs", "backups.read jobs.read"},
		{"POST", "/runs/{rid}/inspect", "backups.read jobs.read logs.read secrets.use"},
		{"POST", "/runs/{rid}/cancel", "backups.read jobs.cancel"},
		{"POST", "/runs/{rid}/cleanup", "backups.read jobs.read jobs.manage logs.read secrets.use"},
	} {
		register(route.method, "/api/servers/{id}/backups"+route.path, "server", route.permissions)
		register(route.method, "/api/backups/nexus"+route.path, "global", route.permissions+" backups.nexus.manage")
	}
	register("GET", "/api/servers/{id}/github/runners", "server", "github.runners.read jobs.read")
	for _, route := range []struct{ method, path, permissions string }{
		{"GET", "/api/servers/{id}/ansible/projects", "ansible.projects.read"},
		{"POST", "/api/servers/{id}/ansible/projects", "ansible.projects.manage"},
		{"POST", "/api/servers/{id}/ansible/projects/{projectId}/archive", "ansible.projects.manage"},
		{"GET", "/api/servers/{id}/ansible/projects/{projectId}/revisions", "ansible.projects.read"},
		{"POST", "/api/servers/{id}/ansible/projects/{projectId}/revisions", "ansible.projects.manage secrets.create"},
		{"POST", "/api/servers/{id}/ansible/projects/{projectId}/revisions/{revisionId}/content", "ansible.projects.read secrets.reveal"},
		{"POST", "/api/servers/{id}/ansible/projects/{projectId}/plans", "ansible.projects.read ansible.playbooks.execute"},
		{"GET", "/api/servers/{id}/ansible/plans", "ansible.projects.read"},
		{"GET", "/api/servers/{id}/ansible/plans/{planId}", "ansible.projects.read"},
		{"POST", "/api/servers/{id}/ansible/plans/{planId}/content", "ansible.projects.read secrets.reveal"},
		{"POST", "/api/servers/{id}/ansible/plans/{planId}/approve", "ansible.projects.read ansible.playbooks.approve secrets.reveal"},
		{"POST", "/api/servers/{id}/ansible/plans/{planId}/cancel", "ansible.projects.manage"},
	} {
		register(route.method, route.path, "server", route.permissions)
	}

	register("GET", "/api/automation/ansible/groups", "collection", "ansible.inventory.read servers.read")
	register("GET", "/api/automation/ansible/inventory", "collection", "ansible.inventory.read servers.read")
	register("GET", "/api/automation/ansible/preview", "collection", "ansible.inventory.read servers.read")
	register("GET", "/api/automation/ansible/tokens", "collection", "ansible.inventory.read servers.read")
	register("POST", "/api/automation/ansible/tokens", "collection", "ansible.inventory.read servers.read")
	register("DELETE", "/api/automation/ansible/tokens/{tokenId}", "collection", "ansible.inventory.read servers.read")
	self("GET", "/api/features")
	self("GET", "/api/version")
	for _, action := range remoteaction.Catalog() {
		register("POST", "/api/servers/{id}/operations/"+action.Route, "server", strings.Join(action.Permissions, " "))
	}
	register("GET", "/api/servers/{id}/operations/runs", "server", "jobs.read")
	register("GET", "/api/servers/{id}/operations/runs/{rid}", "server", "jobs.read logs.read secrets.use")
	register("POST", "/api/servers/{id}/operations/runs/{rid}/inspect", "server", "jobs.read logs.read servers.execute secrets.use")
	register("POST", "/api/servers/{id}/operations/runs/{rid}/cancel", "server", "jobs.cancel servers.execute secrets.use")
	register("DELETE", "/api/servers/{id}/operations/runs/{rid}/artifacts", "server", "jobs.manage logs.read servers.execute secrets.use")
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		register(method, "/api/servers/{id}/vault", "server", "integrations.manage servers.read")
	}
	register("POST", "/api/servers/{id}/vault/inspect", "server", "integrations.manage servers.connect secrets.use")
	for _, action := range []string{"auth", "capabilities"} {
		register("POST", "/api/servers/{id}/vault/access/"+action, "server", "integrations.manage servers.connect secrets.use secrets.metadata.read")
	}
	for _, action := range []string{"policies", "policy"} {
		register("POST", "/api/servers/{id}/vault/access/"+action, "server", "integrations.manage servers.connect secrets.use roles.manage")
	}
	for _, action := range []string{"list", "metadata"} {
		register("POST", "/api/servers/{id}/vault/kv/"+action, "server", "integrations.manage servers.connect secrets.use secrets.metadata.read")
	}
	register("POST", "/api/servers/{id}/vault/kv/read", "server", "integrations.manage servers.connect secrets.use secrets.reveal")
	register("POST", "/api/servers/{id}/vault/kv/write", "server", "integrations.manage servers.connect secrets.use secrets.create")
	register("GET", "/api/servers/{id}/vault/admin/operations", "server", "integrations.manage servers.connect secrets.use")
	for _, op := range vault.AdminOperations() {
		register("POST", "/api/servers/{id}/vault/admin/"+op.ID, "server", strings.Join(op.Permissions, " "))
	}
	register("GET", "/api/servers/{id}/inventory", "server", "inventory.read")
	register("GET", "/api/servers/{id}/inventory/policy", "server", "inventory.read")
	register("PUT", "/api/servers/{id}/inventory/policy", "server", "inventory.read inventory.edit inventory.discover secrets.use")
	register("GET", "/api/servers/{id}/inventory/relationships", "server", "inventory.read")
	register("GET", "/api/servers/{id}/inventory/history", "server", "inventory.read")
	register("GET", "/api/servers/{id}/inventory/documentation", "server", "inventory.read inventory.export")
	register("PUT", "/api/servers/{id}/inventory/documentation", "server", "inventory.read inventory.edit")
	register("POST", "/api/servers/{id}/inventory/discover", "server", "inventory.discover secrets.use")
	self("POST", "/api/auth/step-up")
	register("PUT", "/api/server-groups/{gid}/policy", "global", "roles.manage groups.manage")
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
	register("GET", "/api/audit/events", "global", "audit.read")
	register("GET", "/api/audit/operations/{operationId}", "global", "audit.read")
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
	register("GET", "/api/templates/custom/{id}", "global", "templates.manage compose.read secrets.use")
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
	register("GET", "/api/servers/{id}/tasks/{tid}/runs", "server", "jobs.read logs.read")
	register("GET", "/api/servers/{id}/tasks/{tid}/runs/{rid}", "server", "jobs.read logs.read secrets.use")
	register("POST", "/api/servers/{id}/tasks/{tid}/runs/{rid}/inspect", "server", "jobs.read logs.read servers.execute secrets.use")
	register("POST", "/api/servers/{id}/tasks/{tid}/runs/{rid}/cancel", "server", "jobs.cancel servers.execute secrets.use")
	register("DELETE", "/api/servers/{id}/tasks/{tid}/runs/{rid}/artifacts", "server", "jobs.manage logs.read servers.execute secrets.use")
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

// GitHubWebhook is the sole public provider-event route. It does not authorize
// delivery: the receiving handler must verify the exact body signature.
func GitHubWebhook(method, path string) bool {
	const prefix = "/api/hooks/github/"
	if method != "POST" || !strings.HasPrefix(path, prefix) {
		return false
	}
	id := strings.TrimPrefix(path, prefix)
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
