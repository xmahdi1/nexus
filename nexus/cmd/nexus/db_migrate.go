package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/db"
)

func runDBMigrate(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("db-migrate", flag.ContinueOnError)
	flags.SetOutput(out)
	fromEnv := flags.Bool("from-env", false, "load the matching configuration encryption key for protected data migration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: nexus db-migrate [--from-env] DATABASE.db")
	}
	var key []byte
	if *fromEnv {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		key = cfg.EncryptionKey
	}
	database, err := db.Init(flags.Arg(0), key)
	if err != nil {
		return err
	}
	connection, err := database.DB()
	if err != nil {
		return err
	}
	if err := connection.Close(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Database migrations complete. Preserve private pre-migration snapshots and the matching encryption key. No workers or HTTP listener started.")
	return err
}
