package migrations

import (
	"errors"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
)

func TemplateSecrets(tx *gorm.DB, key []byte) error {
	var count int64
	if err := tx.Table("custom_templates").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 && len(key) != 32 {
		return errors.New("custom template migration requires the matching encryption key; use db-migrate --from-env")
	}
	if err := tx.Exec("ALTER TABLE custom_templates ADD COLUMN definition_enc text NOT NULL DEFAULT ''").Error; err != nil {
		return err
	}
	var batch []struct{ ID, Compose, VarsJSON, PostDeploy string }
	if err := tx.Table("custom_templates").Order("id").FindInBatches(&batch, 25, func(_ *gorm.DB, _ int) error {
		for _, row := range batch {
			encrypted, err := nexuscrypto.EncryptTemplateDefinition(key, row.ID, nexuscrypto.TemplateDefinition{Compose: row.Compose, VarsJSON: row.VarsJSON, PostDeploy: row.PostDeploy})
			if err != nil {
				return errors.New("could not encrypt template definition")
			}
			if err := tx.Table("custom_templates").Where("id=?", row.ID).Update("definition_enc", encrypted).Error; err != nil {
				return errors.New("could not persist protected template definition")
			}
		}
		return nil
	}).Error; err != nil {
		return err
	}
	for _, column := range []string{"compose", "vars_json", "post_deploy"} {
		if err := tx.Exec("ALTER TABLE custom_templates DROP COLUMN " + column).Error; err != nil {
			return err
		}
	}
	return nil
}
