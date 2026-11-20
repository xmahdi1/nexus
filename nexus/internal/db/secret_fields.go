package db

import (
	"errors"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
)

// Static registry: no caller-supplied SQL identifiers. Plaintext hashes, recovery
// codes and config-only legacy TOTP values are not encryption-key ciphertext.
type secretField struct {
	table, id, column, extra string
	kind                     string
}

var secretFields = []secretField{
	{"servers", "id", "private_key_enc", "", "legacy"},
	{"auth_credentials", "user_id", "totp_secret_enc", "", "legacy"},
	{"auth_challenges", "token_hash", "secret_enc", "", "legacy"},
	{"account_reset_enrollments", "token_hash", "secret_enc", "", "legacy"},
	{"deployed_apps", "id", "vars_enc", "server_id", "deployment"},
	{"custom_templates", "id", "definition_enc", "", "template"},
	{"supervised_runs", "id", "output_enc", "server_id", "job"},
}

func validateExistingDataKey(database *gorm.DB, key []byte) error {
	if len(key) != 32 {
		return errors.New("encryption key must contain 32 bytes")
	}
	for _, field := range secretFields {
		if !database.Migrator().HasTable(field.table) || !database.Migrator().HasColumn(field.table, field.column) {
			continue
		}
		if err := walkSecretField(database, field, func(id, extra, value string) error {
			err := validateSecret(field, key, id, extra, value)
			if err != nil {
				return errors.New("stored secret validation failed; restore the matching key or recovery set")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
func walkSecretField(database *gorm.DB, field secretField, visit func(string, string, string) error) error {
	// One row at a time bounds plaintext lifetimes and avoids depending on ID
	// conventions (several credential tables use token_hash rather than id).
	var last string
	first := true
	for {
		var row struct{ Identity, Extra, Value string }
		selectSQL := field.id + " AS identity," + field.column + " AS value"
		if field.extra != "" {
			selectSQL += "," + field.extra + " AS extra"
		}
		query := database.Table(field.table).Select(selectSQL).Where(field.column + " <> ''")
		if !first {
			query = query.Where(field.id+" > ?", last)
		}
		result := query.Order(field.id).Limit(1).Scan(&row)
		first = false
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}
		if err := visit(row.Identity, row.Extra, row.Value); err != nil {
			return err
		}
		last = row.Identity
	}
}
func validateSecret(field secretField, key []byte, id, extra, value string) error {
	switch field.kind {
	case "job":
		data, err := nexuscrypto.DecryptJobOutput(key, id, extra, value)
		clear(data)
		return err
	case "template":
		_, err := nexuscrypto.DecryptTemplateDefinition(key, id, value)
		return err
	case "deployment":
		data, err := nexuscrypto.DecryptDeploymentVariables(key, id, extra, value)
		clear(data)
		return err
	default:
		data, err := nexuscrypto.Decrypt(key, value)
		clear(data)
		return err
	}
}
