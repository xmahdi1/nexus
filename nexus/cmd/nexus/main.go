package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/xmahdi1/nexus/internal/api"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/monitor"
	"github.com/xmahdi1/nexus/internal/scheduler"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/static"
)

var mountFrontend = func(r http.Handler, cfg *config.Config) http.Handler { return r }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		runSetup()
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v\n\nRun 'nexus setup' to initialize.", err)
	}

	database, err := db.Init(cfg.DBPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	pool := nexusssh.NewPool()
	pool.SetHostKeyCallback(nexusssh.TOFUVerifier(database))

	mon := monitor.New(database, []byte(cfg.EncryptionKey), pool)
	mon.Start()

	sched := scheduler.New(database, []byte(cfg.EncryptionKey), pool)
	sched.Start()

	router := api.NewRouter(database, cfg, pool, mon)
	handler := mountFrontend(router, cfg)

	addr := ":" + cfg.Port
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
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func runSetup() {
	fmt.Println("Nexus — first-time setup")
	fmt.Println("─────────────────────────")

	fmt.Print("Enter password (min 8 chars): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("read password: %v", err)
	}
	if len(pw) < 8 {
		log.Fatal("password must be at least 8 characters")
	}

	fmt.Print("Confirm password: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("read password: %v", err)
	}
	if string(pw) != string(pw2) {
		log.Fatal("passwords do not match")
	}

	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		log.Fatalf("bcrypt: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("generate key: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ Add these to your .env file:")
	fmt.Println()
	fmt.Printf("NEXUS_PASSWORD_HASH='%s'\n", hash)
	fmt.Printf("NEXUS_ENCRYPTION_KEY=%s\n", base64.StdEncoding.EncodeToString(key))
	fmt.Println()
	fmt.Println("Never commit these values to version control.")
}

func init() { _ = static.Handler }
