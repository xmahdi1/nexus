package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
)

func runAccountRecovery(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("account-recovery", flag.ContinueOnError)
	flags.SetOutput(out)
	reason := flags.String("reason", "", "required recovery reason (do not include secrets)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || *reason == "" {
		return fmt.Errorf("usage: nexus account-recovery --reason REASON USERNAME")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	database, err := db.Init(cfg.DBPath, cfg.EncryptionKey)
	if err != nil {
		return err
	}
	connection, err := database.DB()
	if err != nil {
		return err
	}
	defer connection.Close()
	result, err := auth.NewService(database, cfg).LocalRecovery(flags.Arg(0), *reason)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Account recovery requested locally and audited. Existing sessions are revoked. Fresh password and MFA enrollment are required.")
	fmt.Fprintf(out, "Open this path on your private Nexus endpoint (one-time secret; do not log or share publicly):\n/recover#token=%s\nExpires: %s\n", result.Token, result.Reset.ExpiresAt.Format(time.RFC3339))
	return nil
}
