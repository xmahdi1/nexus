package api

import (
	"net/http"

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
	"github.com/xmahdi1/nexus/internal/proxy"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/static"
	"github.com/xmahdi1/nexus/internal/templates"
	"github.com/xmahdi1/nexus/internal/terminal"
	"gorm.io/gorm"
)

func NewRouter(db *gorm.DB, cfg *config.Config, pool *nexusssh.Pool, mon *monitor.Monitor) http.Handler {
	nexusMW.SetTrustProxy(cfg.TrustProxy)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.CleanPath)
	r.Use(corsMiddleware)

	authH := handlers.NewAuthHandler(cfg, db)
	serversH := handlers.NewServersHandler(db, cfg.EncryptionKey, pool, mon)
	metricsH := metrics.NewHandler(db, cfg.EncryptionKey, pool)
	dockerH := handlers.NewDockerHandler(db, cfg.EncryptionKey, pool)
	composeH := handlers.NewComposeHandler(db, cfg.EncryptionKey, pool)
	filesH := filemanager.NewHandler(db, cfg.EncryptionKey, pool)
	termH := terminal.NewHandler(db, cfg.EncryptionKey, pool, cfg.EncryptionKey)
	logsH := docker.NewLogsHandler(db, cfg.EncryptionKey, pool, cfg.EncryptionKey)
	proxyH := proxy.NewHandler(db, cfg.EncryptionKey, pool)
	svcH := handlers.NewServicesHandler(db)
	monH := handlers.NewMonitorHandler(db, mon)
	tplH := templates.NewHandler(db, cfg.EncryptionKey, pool)
	cronH := handlers.NewCronHandler(db, cfg.EncryptionKey, pool)
	execH := handlers.NewExecHandler(db, cfg.EncryptionKey, pool)
	tasksH := handlers.NewTasksHandler(db)
	fwH := handlers.NewFirewallHandler(db, []byte(cfg.EncryptionKey), pool)

	r.With(nexusMW.LoginRateLimit).Post("/api/auth/login", authH.Login)
	r.With(nexusMW.LoginRateLimit).Post("/api/auth/mfa/verify", authH.MFAVerify)

	r.Group(func(r chi.Router) {
		r.Use(nexusMW.Require(cfg.EncryptionKey))

		r.Post("/api/auth/logout", authH.Logout)
		r.Get("/api/auth/me", authH.Me)
		r.Post("/api/auth/password", authH.ChangePassword)
		r.Get("/api/auth/audit", authH.AuditLog)
		r.Get("/api/auth/mfa/status", authH.MFAStatus)
		r.Post("/api/auth/mfa/setup", authH.MFASetup)
		r.Post("/api/auth/mfa/enable", authH.MFAEnable)
		r.Post("/api/auth/mfa/disable", authH.MFADisable)

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
		r.Handle("/*", h)
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
