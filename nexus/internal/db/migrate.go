package db

import (
	"fmt"
	"time"

	"github.com/xmahdi1/nexus/internal/db/migrations"
	"gorm.io/gorm"
)

type migration struct {
	Version int
	Name    string
	Up      func(*gorm.DB) error
}

var schemaMigrations = []migration{
	{1, "legacy_baseline", migrations.Baseline},
	{2, "local_identity", migrations.Identity},
	{3, "revocable_sessions", migrations.Sessions},
	{4, "scoped_authorization", migrations.Authorization},
	{5, "invitation_accounts", migrations.Accounts},
	{6, "operation_audit", migrations.OperationAudit},
	{7, "high_risk_policy", migrations.HighRisk},
	{8, "read_only_inventory", migrations.Inventory},
	{9, "encrypted_deployment_variables", func(tx *gorm.DB) error { return migrations.DeploymentSecrets(tx, nil) }},
	{10, "encrypted_template_definitions", func(tx *gorm.DB) error { return migrations.TemplateSecrets(tx, nil) }},
	{11, "supervised_job_runs", migrations.SupervisedRuns},
	{12, "vault_connections", migrations.VaultConnections},
	{13, "interactive_operations", migrations.InteractiveOperations},
	{14, "inventory_details", migrations.InventoryDetails},
	{15, "ansible_inventory", migrations.AnsibleInventory},
}

type schemaMigration struct {
	Version   int       `gorm:"primaryKey;autoIncrement:false"`
	Name      string    `gorm:"not null"`
	AppliedAt time.Time `gorm:"not null"`
}

// migrate uses BEGIN IMMEDIATE (configured by Init's SQLite DSN), serializing
// competing startup migrations before reading the version ledger. All pending
// changes and their ledger entries commit together, or roll back together.
func migrate(database *gorm.DB, steps []migration, backup func() error) error {
	for i, step := range steps {
		if step.Version != i+1 || step.Name == "" || step.Up == nil {
			return fmt.Errorf("invalid migration registry at version %d", step.Version)
		}
	}
	return database.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
   version integer PRIMARY KEY, name text NOT NULL, applied_at datetime NOT NULL
  )`).Error; err != nil {
			return fmt.Errorf("migration ledger: %w", err)
		}
		var applied []schemaMigration
		if err := tx.Order("version").Find(&applied).Error; err != nil {
			return err
		}
		for i, entry := range applied {
			if i >= len(steps) || entry.Version != i+1 || entry.Name != steps[i].Name {
				return fmt.Errorf("unsupported or inconsistent database schema at version %d; restore the matching binary or recovery set", entry.Version)
			}
		}
		if len(applied) == len(steps) {
			return nil
		}
		var tables int64
		if err := tx.Raw("SELECT count(*) FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'").Scan(&tables).Error; err != nil {
			return err
		}
		if tables > 0 {
			if backup == nil {
				return fmt.Errorf("existing database requires a pre-migration backup")
			}
			if err := backup(); err != nil {
				return fmt.Errorf("pre-migration backup failed: %w", err)
			}
		}
		for _, step := range steps[len(applied):] {
			if err := step.Up(tx); err != nil {
				return fmt.Errorf("migration %04d %s: %w", step.Version, step.Name, err)
			}
			if err := tx.Create(&schemaMigration{Version: step.Version, Name: step.Name, AppliedAt: time.Now().UTC()}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
