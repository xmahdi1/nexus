package main

import (
	"flag"
	"fmt"
	"gorm.io/gorm"
	"io"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/db"
)

// Local only: explicit retention, minimum 30 days, backup before deletion.
func runAuditPrune(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit-prune", flag.ContinueOnError)
	flags.SetOutput(out)
	days := flags.Int("days", 365, "retain at least this many days (minimum 30)")
	backup := flags.String("backup", "", "required new private backup path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || *days < 30 || *days > 36500 || *backup == "" {
		return fmt.Errorf("usage: nexus audit-prune --days 365 --backup NEW-BACKUP.db DATABASE.db")
	}
	database, err := db.Init(flags.Arg(0))
	if err != nil {
		return err
	}
	conn, err := database.DB()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := db.Backup(flags.Arg(0), *backup); err != nil {
		return err
	}
	var count int64
	err = database.Transaction(func(tx *gorm.DB) error {
		var err error
		count, err = audit.Prune(tx, time.Now().AddDate(0, 0, -*days))
		if err != nil {
			return err
		}
		id, err := audit.NewID()
		if err != nil {
			return err
		}
		return audit.Append(tx, audit.Event{OperationID: id, ActorID: "local-cli", Action: "audit.retention", ResourceType: "audit_store", ResourceID: "operation_events", Source: "local-cli", Outcome: "succeeded"})
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed %d expired operation audit rows; backup retained. No workers started.\n", count)
	return nil
}
