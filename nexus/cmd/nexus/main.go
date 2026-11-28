package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xmahdi1/nexus/internal/ansible"
	"github.com/xmahdi1/nexus/internal/api"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/backups"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/inventory"
	"github.com/xmahdi1/nexus/internal/monitor"
	"github.com/xmahdi1/nexus/internal/operations"
	"github.com/xmahdi1/nexus/internal/scheduler"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/static"
)

var mountFrontend = func(r http.Handler, cfg *config.Config) http.Handler { return r }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "key-rotate" {
		if err := runKeyRotate(os.Args[2:], os.Stdout); err != nil {
			log.Fatalf("key rotation failed: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "audit-prune" {
		if err := runAuditPrune(os.Args[2:], os.Stdout); err != nil {
			log.Fatalf("audit retention failed: %v", err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "account-recovery" {
		if err := runAccountRecovery(os.Args[2:], os.Stdout); err != nil {
			log.Fatalf("local account recovery failed: %v", err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "owner-activate" {
		if len(os.Args) != 3 {
			log.Fatal("usage: nexus owner-activate USERNAME")
		}
		cfg, err := config.Load()
		if err != nil {
			log.Fatal(err)
		}
		database, err := db.Init(cfg.DBPath, cfg.EncryptionKey)
		if err != nil {
			log.Fatal(err)
		}
		connection, err := database.DB()
		if err != nil {
			log.Fatal(err)
		}
		defer connection.Close()
		if err := auth.ActivateOwner(database, cfg, os.Args[2]); err != nil {
			log.Fatalf("owner activation failed: %v", err)
		}
		fmt.Println("Owner account login activated using current configured credentials and MFA. Existing sessions revoked. No workers started.")
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "owner-bootstrap" {
		if err := runOwnerBootstrap(os.Args[2:], terminalPassword, os.Stdout); err != nil {
			log.Fatalf("owner bootstrap failed: %v", err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "db-migrate" {
		if err := runDBMigrate(os.Args[2:], os.Stdout); err != nil {
			log.Fatalf("migration failed: %v", err)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "db-backup" {
		if len(os.Args) != 4 {
			log.Fatal("usage: nexus db-backup SOURCE.db NEW-BACKUP.db")
		}
		if err := db.Backup(os.Args[2], os.Args[3]); err != nil {
			log.Fatalf("backup failed: %v", err)
		}
		fmt.Println("Database backup created. Store the matching .env securely and separately.")
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if err := runInitialSetup(os.Args[2:], terminalPassword, os.Stdout); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v\n\nRun 'nexus setup' to initialize.", err)
	}

	database, err := db.Init(cfg.DBPath, cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool := nexusssh.NewPool()
	defer pool.Close()
	pool.SetHostKeyCallback(nexusssh.TOFUVerifier(database))

	mon := monitor.New(database, []byte(cfg.EncryptionKey), pool)
	mon.Start(ctx)

	sched := scheduler.New(database, []byte(cfg.EncryptionKey), pool, cfg.JobSupervisionEnabled)
	sched.Start()
	if cfg.InventoryEnabled {
		(&inventory.Service{DB: database, Adapter: &inventory.SSHAdapter{DB: database, Key: cfg.EncryptionKey, Pool: pool}}).Run(ctx)
	}
	operations.New(database, cfg.EncryptionKey, pool, auth.NewService(database, cfg), cfg.OperationSupervisionEnabled, cfg.AutomationEnabled).Run(ctx)
	ansible.NewRuntime(&ansible.Service{DB: database, Key: cfg.EncryptionKey, Sessions: auth.NewService(database, cfg), Enabled: cfg.AutomationEnabled, VaultEnabled: cfg.VaultEnabled}, pool, cfg.OperationSupervisionEnabled).Run(ctx)

	backups.Configured(database, cfg, pool).Run(ctx)
	router := api.NewRouter(database, cfg, pool, mon)
	handler := mountFrontend(router, cfg)

	addr := net.JoinHostPort(cfg.BindAddress, cfg.Port)
	log.Printf("nexus listening on %s", addr)
	if cfg.StaticDir != "" {
		log.Printf("static dir: %s", cfg.StaticDir)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}
	shutdown := make(chan struct{})
	go func() {
		defer close(shutdown)
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(deadline); err != nil {
			_ = srv.Close()
		}
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
	<-shutdown
}

func init() { _ = static.Handler }
