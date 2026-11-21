package api

import (
	"encoding/json"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/automation"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/xmahdi1/nexus/internal/api/handlers"
	nexusMW "github.com/xmahdi1/nexus/internal/api/middleware"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/docker"
	"github.com/xmahdi1/nexus/internal/filemanager"
	"github.com/xmahdi1/nexus/internal/httpx"
	"github.com/xmahdi1/nexus/internal/metrics"
	"github.com/xmahdi1/nexus/internal/monitor"
	"github.com/xmahdi1/nexus/internal/operations"
	"github.com/xmahdi1/nexus/internal/proxy"
	"github.com/xmahdi1/nexus/internal/remoteaction"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/static"
	"github.com/xmahdi1/nexus/internal/templates"
	"github.com/xmahdi1/nexus/internal/terminal"
	"github.com/xmahdi1/nexus/internal/vault"
	"gorm.io/gorm"
)

func NewRouter(db *gorm.DB, cfg *config.Config, pool *nexusssh.Pool, mon *monitor.Monitor) http.Handler {
	nexusMW.SetTrustProxy(cfg.TrustProxy)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(nexusMW.RequestLog)
	r.Use(nexusMW.Recoverer)
	r.Use(middleware.CleanPath)
	r.Use(nexusMW.Security(cfg))
	r.Use(corsMiddleware)
	ansibleService := &automation.InventoryService{DB: db, Sessions: auth.NewService(db, cfg)}
	r.Use(nexusMW.Management(auth.NewService(db, cfg), authorization.New(db), nexusMW.InventorySession(ansibleService, cfg.AutomationEnabled)))

	r.Get("/health/live", liveness)
	r.Get("/health/ready", readiness(db))

	authH := handlers.NewAuthHandler(cfg, db)
	policyH := handlers.NewAuthorizationHandler(db, cfg)
	accountsH := handlers.NewAccountHandler(db, cfg)
	serversH := handlers.NewServersHandler(db, cfg.EncryptionKey, pool, mon)
	metricsH := metrics.NewHandler(db, cfg.EncryptionKey, pool)
	dockerH := handlers.NewDockerHandler(db, cfg.EncryptionKey, pool, cfg.OperationSupervisionEnabled)
	composeH := handlers.NewComposeHandler(db, cfg.EncryptionKey, pool, cfg.OperationSupervisionEnabled)
	filesH := filemanager.NewHandler(db, cfg.EncryptionKey, pool)
	termH := terminal.NewHandler(db, cfg.EncryptionKey, pool, cfg.EncryptionKey)
	logsH := docker.NewLogsHandler(db, cfg.EncryptionKey, pool, cfg.EncryptionKey)
	proxyH := proxy.NewHandler(db, cfg.EncryptionKey, pool, cfg.ACME)
	svcH := handlers.NewServicesHandler(db)
	monH := handlers.NewMonitorHandler(db, mon)
	tplH := templates.NewHandler(db, cfg.EncryptionKey, pool)
	cronH := handlers.NewCronHandler(db, cfg.EncryptionKey, pool)
	execH := handlers.NewExecHandler(db, cfg.EncryptionKey, pool)
	tasksH := handlers.NewTasksHandler(db, cfg.JobSupervisionEnabled)
	runsH := handlers.NewSupervisedRunsHandler(db, cfg.EncryptionKey, pool)
	operationsH := handlers.NewOperationsHandler(operations.New(db, cfg.EncryptionKey, pool, auth.NewService(db, cfg), cfg.OperationSupervisionEnabled))
	fwH := handlers.NewFirewallHandler(db, []byte(cfg.EncryptionKey), pool)

	r.With(nexusMW.LoginRateLimit).Post("/api/auth/login", authH.Login)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/mfa/verify", authH.MFAVerify)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/mfa/recovery", accountsH.RecoveryLogin)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/invitations/accept", accountsH.Accept)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/reset/info", accountsH.ResetInfo)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/reset/password", accountsH.ResetPassword)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/reset/mfa/setup", accountsH.ResetMFASetup)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/reset/mfa/confirm", accountsH.ResetMFAConfirm)

	r.Group(func(r chi.Router) {
		ansibleH := &handlers.AnsibleInventoryHandler{Service: ansibleService, Enabled: cfg.AutomationEnabled}
		r.Get("/api/automation/ansible/groups", ansibleH.Groups)
		r.Get("/api/automation/ansible/inventory", ansibleH.Inventory)
		r.Get("/api/automation/ansible/preview", ansibleH.Preview)
		r.Get("/api/automation/ansible/tokens", ansibleH.List)
		r.With(nexusMW.CredentialRateLimit).Post("/api/automation/ansible/tokens", ansibleH.Issue)
		r.Delete("/api/automation/ansible/tokens/{tokenId}", ansibleH.Revoke)

		r.Post("/api/auth/logout", authH.Logout)
		r.Get("/api/users", accountsH.Users)
		r.Get("/api/users/invitations", accountsH.Invitations)
		r.With(nexusMW.CredentialRateLimit).Post("/api/users/invitations", accountsH.Invite)
		r.With(nexusMW.CredentialRateLimit).Delete("/api/users/invitations/{inviteId}", accountsH.RevokeInvite)
		r.With(nexusMW.CredentialRateLimit).Patch("/api/users/{uid}", accountsH.Status)
		r.With(nexusMW.CredentialRateLimit).Post("/api/users/{uid}/resets", accountsH.Reset)
		r.With(nexusMW.CredentialRateLimit).Post("/api/users/{uid}/unlock", accountsH.Unlock)
		r.With(nexusMW.CredentialRateLimit).Post("/api/auth/mfa/recovery-codes", accountsH.Regenerate)
		r.Get("/api/auth/me", authH.Me)
		r.Get("/api/features", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"automation": cfg.AutomationEnabled, "inventory": cfg.InventoryEnabled, "jobSupervision": cfg.JobSupervisionEnabled, "operationSupervision": cfg.OperationSupervisionEnabled, "vault": cfg.VaultEnabled})
		})
		for _, action := range remoteaction.Catalog() {
			r.Post("/api/servers/{id}/operations/"+action.Route, operationsH.Start(action.ID))
		}
		r.Get("/api/servers/{id}/operations/runs", operationsH.List)
		r.Get("/api/servers/{id}/operations/runs/{rid}", operationsH.Read)
		r.Post("/api/servers/{id}/operations/runs/{rid}/inspect", operationsH.Inspect)
		r.Post("/api/servers/{id}/operations/runs/{rid}/cancel", operationsH.Cancel)
		r.Delete("/api/servers/{id}/operations/runs/{rid}/artifacts", operationsH.Release)
		vaultH := handlers.NewVaultHandler(db, cfg.EncryptionKey, pool, cfg.VaultEnabled)
		r.Get("/api/servers/{id}/vault", vaultH.Read)
		r.Put("/api/servers/{id}/vault", vaultH.Save)
		r.Delete("/api/servers/{id}/vault", vaultH.Delete)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/inspect", vaultH.Inspect)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/access/auth", vaultH.AuthMethods)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/access/policies", vaultH.Policies)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/access/policy", vaultH.Policy)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/access/capabilities", vaultH.Capabilities)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/kv/list", vaultH.KVList)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/kv/metadata", vaultH.KVMetadata)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/kv/read", vaultH.KVRead)
		r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/kv/write", vaultH.KVWrite)
		r.Get("/api/servers/{id}/vault/admin/operations", vaultH.AdminOperations)
		for _, op := range vault.AdminOperations() {
			r.With(nexusMW.VaultRateLimit).Post("/api/servers/{id}/vault/admin/"+op.ID, vaultH.Admin(op.ID))
		}
		inventoryH := handlers.NewInventoryHandler(db, cfg, pool)
		r.Get("/api/servers/{id}/inventory", inventoryH.Read)
		r.Get("/api/servers/{id}/inventory/relationships", inventoryH.Relationships)
		r.Get("/api/servers/{id}/inventory/history", inventoryH.History)
		r.With(nexusMW.CredentialRateLimit).Post("/api/servers/{id}/inventory/discover", inventoryH.Discover)
		r.With(nexusMW.CredentialRateLimit).Post("/api/auth/step-up", policyH.StepUp)
		r.With(nexusMW.CredentialRateLimit).Put("/api/server-groups/{gid}/policy", policyH.SetGroupPolicy)
		r.Get("/api/auth/permissions", policyH.Permissions)
		r.Get("/api/roles", policyH.Roles)
		r.Get("/api/grants", policyH.Grants)
		r.With(nexusMW.CredentialRateLimit).Post("/api/grants", policyH.AddGrant)
		r.With(nexusMW.CredentialRateLimit).Delete("/api/grants/{grantId}", policyH.DeleteGrant)
		r.Get("/api/server-groups", policyH.Groups)
		r.With(nexusMW.CredentialRateLimit).Post("/api/server-groups", policyH.CreateGroup)
		r.With(nexusMW.CredentialRateLimit).Put("/api/server-groups/{gid}/servers/{serverId}", policyH.Membership)
		r.With(nexusMW.CredentialRateLimit).Delete("/api/server-groups/{gid}/servers/{serverId}", policyH.Membership)
		r.With(nexusMW.CredentialRateLimit).Delete("/api/server-groups/{gid}", policyH.DeleteGroup)
		r.Get("/api/authorization/events", policyH.Events)
		r.Get("/api/audit/events", handlers.NewAuditHandler(db).List)
		r.Get("/api/audit/operations/{operationId}", handlers.NewAuditHandler(db).Inspect)
		r.Get("/api/auth/sessions", authH.Sessions)
		r.Delete("/api/auth/sessions/{sid}", authH.RevokeSession)
		r.Post("/api/auth/logout-all", authH.LogoutAll)
		r.With(nexusMW.CredentialRateLimit).Post("/api/auth/password", authH.ChangePassword)
		r.Get("/api/auth/audit", authH.AuditLog)
		r.Get("/api/auth/mfa/status", authH.MFAStatus)
		r.With(nexusMW.CredentialRateLimit).Post("/api/auth/mfa/setup", authH.MFASetup)
		r.With(nexusMW.CredentialRateLimit).Post("/api/auth/mfa/enable", authH.MFAEnable)
		r.With(nexusMW.CredentialRateLimit).Post("/api/auth/mfa/disable", authH.MFADisable)

		r.Post("/api/keys/generate", serversH.GenerateKey)
		r.Get("/api/servers", serversH.List)
		r.Post("/api/servers", serversH.Create)
		r.Get("/api/servers/{id}", serversH.Get)
		r.Delete("/api/servers/{id}", serversH.Delete)
		r.Post("/api/servers/{id}/test", serversH.TestConnection)
		r.Patch("/api/servers/{id}/tags", serversH.UpdateTags)

		r.Get("/api/servers/{id}/metrics", metricsH.Get)

		r.Get("/api/servers/{id}/containers", dockerH.ListContainers)
		r.Post("/api/servers/{id}/containers/{cid}/start", dockerH.Start)
		r.Post("/api/servers/{id}/containers/{cid}/stop", dockerH.Stop)
		r.Post("/api/servers/{id}/containers/{cid}/restart", dockerH.Restart)
		r.Delete("/api/servers/{id}/containers/{cid}", dockerH.Remove)
		r.Post("/api/servers/{id}/containers/{cid}/exec", execH.DbExec)

		r.Get("/api/servers/{id}/compose", composeH.Read)
		r.Put("/api/servers/{id}/compose", composeH.Write)
		r.Post("/api/servers/{id}/compose/up", composeH.Up)
		r.Post("/api/servers/{id}/compose/down", composeH.Down)

		r.Get("/api/servers/{id}/files", filesH.List)
		r.Get("/api/servers/{id}/files/preview", filesH.Preview)
		r.Get("/api/servers/{id}/files/download", filesH.Download)
		r.Post("/api/servers/{id}/files/upload", filesH.Upload)
		r.Delete("/api/servers/{id}/files", filesH.Delete)
		r.Post("/api/servers/{id}/files/mkdir", filesH.Mkdir)
		r.Put("/api/servers/{id}/files", filesH.Write)

		r.Get("/api/servers/{id}/proxy/detect", proxyH.Detect)
		r.Get("/api/servers/{id}/proxy", proxyH.List)
		r.Post("/api/servers/{id}/proxy", proxyH.Create)
		r.Delete("/api/servers/{id}/proxy/{ruleId}", proxyH.Delete)
		r.Put("/api/servers/{id}/proxy/{ruleId}", proxyH.Update)
		r.Post("/api/servers/{id}/proxy/{ruleId}/ssl", proxyH.EnableSSL)

		r.Get("/api/services", svcH.List)
		r.Post("/api/services", svcH.Create)
		r.Put("/api/services/{id}", svcH.Update)
		r.Delete("/api/services/{id}", svcH.Delete)

		r.Get("/api/monitor/status", monH.Status)
		r.Get("/api/monitor/config", monH.GetConfig)
		r.Put("/api/monitor/config", monH.UpdateConfig)
		r.Post("/api/monitor/config/test", monH.TestTelegram)
		r.Get("/api/servers/{id}/monitor/containers", monH.ListMonitored)
		r.Post("/api/servers/{id}/monitor/containers", monH.AddMonitored)
		r.Delete("/api/servers/{id}/monitor/containers/{containerId}", monH.RemoveMonitored)
		r.Get("/api/servers/{id}/alerts", monH.GetServerAlerts)
		r.Put("/api/servers/{id}/alerts", monH.UpdateServerAlerts)

		r.Get("/api/templates", tplH.List)
		r.Post("/api/templates/custom", tplH.CreateCustom)
		r.Get("/api/templates/custom/{id}", tplH.GetCustom)
		r.Put("/api/templates/custom/{id}", tplH.UpdateCustom)
		r.Delete("/api/templates/custom/{id}", tplH.DeleteCustom)
		r.Get("/api/servers/{id}/apps", tplH.ListDeployed)
		r.Post("/api/servers/{id}/apps/deploy", tplH.Deploy)
		r.Delete("/api/servers/{id}/apps/{appId}", tplH.Remove)

		r.Get("/api/servers/{id}/cron", cronH.List)
		r.Post("/api/servers/{id}/cron", cronH.Add)
		r.Delete("/api/servers/{id}/cron", cronH.Delete)

		r.Get("/api/servers/{id}/tasks", tasksH.List)
		r.Post("/api/servers/{id}/tasks", tasksH.Create)
		r.Put("/api/servers/{id}/tasks/{tid}", tasksH.Update)
		r.Delete("/api/servers/{id}/tasks/{tid}", tasksH.Delete)
		r.Post("/api/servers/{id}/tasks/{tid}/run", tasksH.RunNow)
		r.Get("/api/servers/{id}/tasks/{tid}/runs", runsH.List)
		r.Get("/api/servers/{id}/tasks/{tid}/runs/{rid}", runsH.Read)
		r.Post("/api/servers/{id}/tasks/{tid}/runs/{rid}/inspect", runsH.Inspect)
		r.Post("/api/servers/{id}/tasks/{tid}/runs/{rid}/cancel", runsH.Cancel)
		r.Delete("/api/servers/{id}/tasks/{tid}/runs/{rid}/artifacts", runsH.Release)

		r.Get("/api/servers/{id}/firewall", fwH.Status)
		r.Post("/api/servers/{id}/firewall/enable", fwH.Enable)
		r.Post("/api/servers/{id}/firewall/disable", fwH.Disable)
		r.Post("/api/servers/{id}/firewall/rules", fwH.AddRule)
		r.Delete("/api/servers/{id}/firewall/rules/{n}", fwH.DeleteRule)

		r.Get("/ws/terminal/{id}", termH.Handle)
		r.Get("/ws/logs/{id}/{cid}", logsH.Handle)
		r.Get("/ws/metrics/{id}", metricsH.Stream)
	})

	if h := static.DefaultHandler(cfg.StaticDir); h != nil {
		r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "Not found.", "code": "not_found", "request_id": w.Header().Get("X-Request-ID")})
				return
			}
			h.ServeHTTP(w, r)
		}))
	}
	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && httpx.SameOrigin(r) {
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
