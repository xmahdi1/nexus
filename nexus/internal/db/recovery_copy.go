package db

import (
	"errors"
	"net/url"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// recoveryAuthority is only used on a separately created recovery database.
// Existing run identities remain for inspection/cancellation; no new schedule
// or incoming bearer authority is retained in a promoted recovery copy.
func recoveryAuthority(tx *gorm.DB) error {
	if err := tx.Exec("UPDATE github_webhooks SET disabled=1;UPDATE ansible_queue SET state='cancelled',detail='recovery_copy' WHERE state='waiting';UPDATE ansible_schedules SET enabled=0,last_state='recovery_copy';UPDATE scheduled_tasks SET enabled=0;UPDATE backup_policies SET enabled=0,last_state='recovery_copy'").Error; err != nil {
		return err
	}
	if err := tx.Exec("UPDATE inventory_policies SET enabled=0,claim_id='',lease_until=NULL,last_status='recovery_copy'").Error; err != nil {
		return err
	}
	if err := tx.Exec("UPDATE alert_configs SET telegram_enabled=0").Error; err != nil {
		return err
	}
	for _, table := range []string{"auth_sessions", "auth_challenges", "account_reset_enrollments", "account_resets", "account_invitations", "ansible_inventory_tokens"} {
		if err := tx.Exec("DELETE FROM " + table).Error; err != nil {
			return err
		}
	}
	return nil
}

// RecoverySnapshot exports a consistent copy and removes copied runtime
// authority without changing its key. The destination must not already exist.
func RecoverySnapshot(source, destination string, key []byte) error {
	if err := Backup(source, destination); err != nil {
		return err
	}
	uri := url.URL{Scheme: "file", Path: destination, RawQuery: "_busy_timeout=5000&_txlock=immediate"}
	database, err := gorm.Open(sqlite.Open(uri.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return err
	}
	connection, err := database.DB()
	if err != nil {
		return err
	}
	defer connection.Close()
	var ledger []schemaMigration
	if err := database.Order("version").Find(&ledger).Error; err != nil {
		return err
	}
	if len(ledger) != len(schemaMigrations) {
		return errors.New("backup requires current schema")
	}
	for i, row := range ledger {
		if row.Version != schemaMigrations[i].Version || row.Name != schemaMigrations[i].Name {
			return errors.New("backup schema ledger mismatch")
		}
	}
	if err := validateExistingDataKey(database, key); err != nil {
		return err
	}
	if err := database.Transaction(recoveryAuthority); err != nil {
		return err
	}
	if err := database.Exec("VACUUM").Error; err != nil {
		return err
	}
	var integrity string
	if err := database.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil {
		return err
	}
	if integrity != "ok" {
		return errors.New("backup integrity failed")
	}
	if err := connection.Close(); err != nil {
		return err
	}
	return syncPrivateFile(destination)
}
