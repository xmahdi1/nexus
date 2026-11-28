package migrations

import (
	"errors"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
)

// NotificationSecrets removes the live plaintext column. Existing private
// pre-migration backups can still contain plaintext; this is not secure erasure.
func NotificationSecrets(tx *gorm.DB, key []byte) error {
	var rows []struct{ ID, TelegramToken string }
	if err := tx.Table("alert_configs").Select("id,telegram_token").Find(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		if row.TelegramToken != "" && len(key) != 32 {
			return errors.New("notification migration requires the matching encryption key; use db-migrate --from-env")
		}
	}
	if err := tx.Exec("ALTER TABLE alert_configs ADD COLUMN telegram_token_enc text NOT NULL DEFAULT ''").Error; err != nil {
		return err
	}
	for _, row := range rows {
		if row.TelegramToken == "" {
			continue
		}
		sealed, err := nexuscrypto.EncryptNotificationToken(key, row.ID, []byte(row.TelegramToken))
		if err != nil {
			return errors.New("could not encrypt notification credential")
		}
		if err := tx.Table("alert_configs").Where("id=?", row.ID).Update("telegram_token_enc", sealed).Error; err != nil {
			return errors.New("could not persist notification credential")
		}
	}
	return tx.Exec("ALTER TABLE alert_configs DROP COLUMN telegram_token").Error
}
