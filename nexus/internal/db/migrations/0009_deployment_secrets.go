package migrations

import (
	"errors"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
)

// DeploymentSecrets runs inside the normal backed-up schema transaction. Legacy
// snapshots/freelist pages can still contain plaintext; this is not secure erase.
func DeploymentSecrets(tx *gorm.DB, key []byte) error {
	var count int64
	if err := tx.Table("deployed_apps").Where("vars_json IS NOT NULL AND vars_json <> ''").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 && len(key) != 32 {
		return errors.New("deployment variables require the matching encryption key; use db-migrate --from-env with the matching configuration")
	}
	if count > 0 {
		// Detect a wrong configuration key against existing SSH ciphertext before
		// sealing legacy values under it. No plaintext or decryption error is logged.
		var servers []struct{ PrivateKeyEnc string }
		if err := tx.Table("servers").Select("private_key_enc").Where("private_key_enc <> ''").Find(&servers).Error; err != nil {
			return err
		}
		for _, server := range servers {
			value, err := nexuscrypto.Decrypt(key, server.PrivateKeyEnc)
			clear(value)
			if err != nil {
				return errors.New("configured encryption key cannot decrypt existing credentials")
			}
		}
	}
	if err := tx.Exec("ALTER TABLE deployed_apps ADD COLUMN vars_enc text NOT NULL DEFAULT ''").Error; err != nil {
		return err
	}
	var batch []struct{ ID, ServerID, VarsJSON string }
	if err := tx.Table("deployed_apps").Order("id").FindInBatches(&batch, 25, func(batchTX *gorm.DB, _ int) error {
		for _, app := range batch {
			if app.VarsJSON == "" {
				continue
			}
			encrypted, err := nexuscrypto.EncryptDeploymentVariables(key, app.ID, app.ServerID, []byte(app.VarsJSON))
			if err != nil {
				return errors.New("could not encrypt deployment variables")
			}
			if err := tx.Table("deployed_apps").Where("id=?", app.ID).Update("vars_enc", encrypted).Error; err != nil {
				return errors.New("could not persist encrypted deployment variables")
			}
		}
		return nil
	}).Error; err != nil {
		return err
	}
	// Drop the plaintext column rather than retaining a dual-format read fallback.
	return tx.Exec("ALTER TABLE deployed_apps DROP COLUMN vars_json").Error
}
