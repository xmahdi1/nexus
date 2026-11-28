package db

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// RotateRecoverySet never promotes the copy or modifies the source configuration.
// Stop Nexus before taking the snapshot: later writes are not part of this set.
// A failed set is deliberately retained without READY for private investigation.
func RotateRecoverySet(source, destination string, oldKey []byte) (resultErr error) {
	if len(oldKey) != 32 {
		return errors.New("a matching 32-byte current key is required")
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	destination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			_ = os.Remove(filepath.Join(destination, "READY"))
		}
	}()
	path := filepath.Join(destination, "nexus.db")
	if err := Backup(source, path); err != nil {
		return err
	}
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "_busy_timeout=5000&_txlock=immediate"}
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
		return errors.New("rotation requires the current schema; migrate separately first")
	}
	for i, row := range ledger {
		if row.Version != schemaMigrations[i].Version || row.Name != schemaMigrations[i].Name {
			return errors.New("rotation requires a consistent current schema")
		}
	}
	if err := validateExistingDataKey(database, oldKey); err != nil {
		return err
	}
	newKey := make([]byte, 32)
	defer clear(newKey)
	if _, err := rand.Read(newKey); err != nil {
		return err
	}
	err = database.Transaction(func(tx *gorm.DB) error {
		for _, field := range secretFields {
			if err := walkSecretField(tx, field, func(id, extra, value string) error {
				sealed, err := rewrapSecret(field, oldKey, newKey, id, extra, value)
				if err != nil {
					return errors.New("secret re-encryption failed")
				}
				return tx.Table(field.table).Where(field.id+" = ?", id).Update(field.column, sealed).Error
			}); err != nil {
				return err
			}
		}
		if err := recoveryAuthority(tx); err != nil {
			return err
		}
		return validateExistingDataKey(tx, newKey)
	})
	if err != nil {
		return err
	}
	var integrity string
	if err := database.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil {
		return err
	}
	if integrity != "ok" {
		return errors.New("rotated database integrity validation failed")
	}
	// VACUUM removes freed pages containing old ciphertext or deleted bearer data.
	if err := database.Exec("VACUUM").Error; err != nil {
		return err
	}
	if err := connection.Close(); err != nil {
		return err
	}
	if err := syncPrivateFile(path); err != nil {
		return err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(newKey) + "\n")
	defer clear(encoded)
	if err := writePrivateFile(filepath.Join(destination, "encryption-key.base64"), encoded); err != nil {
		return err
	}
	manifest, err := json.MarshalIndent(struct {
		Schema       int       `json:"schema"`
		CreatedAt    time.Time `json:"createdAt"`
		Instructions string    `json:"instructions"`
	}{len(schemaMigrations), time.Now().UTC(), "Stop Nexus before snapshot and promotion. Preserve the original database, configuration and key as one rollback set. Install nexus.db and set NEXUS_ENCRYPTION_KEY from encryption-key.base64 together. Sessions, invitations and pending resets are revoked. Other configuration remains required. Never mix keys and databases."}, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(destination, "manifest.json"), manifest); err != nil {
		return err
	}
	// Persist the complete pair before publishing its completion marker.
	if err := syncDirectory(destination); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(destination, "READY"), []byte("Complete recovery set; manual promotion required.\n")); err != nil {
		return err
	}
	if err := syncDirectory(destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func rewrapSecret(field secretField, oldKey, newKey []byte, id, extra, value string) (string, error) {
	switch field.kind {
	case "notification":
		data, err := nexuscrypto.DecryptNotificationToken(oldKey, id, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptNotificationToken(newKey, id, data)
	case "backup-retention":
		data, err := nexuscrypto.DecryptBackupRetention(oldKey, id, extra, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptBackupRetention(newKey, id, extra, data)
	case "backup-policy":
		data, err := nexuscrypto.DecryptBackupPolicy(oldKey, id, extra, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptBackupPolicy(newKey, id, extra, data)
	case "github-connection", "github-dispatch", "github-change", "github-webhook", "github-organization", "github-organization-change":
		kind := strings.TrimPrefix(field.kind, "github-")
		data, err := nexuscrypto.DecryptGitHubPayload(oldKey, kind, id, extra, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptGitHubPayload(newKey, kind, id, extra, data)
	case "ansible-revision", "ansible-plan", "ansible-template", "ansible-preset", "ansible-schedule":
		kind := strings.TrimPrefix(field.kind, "ansible-")
		data, err := nexuscrypto.DecryptAnsiblePayload(oldKey, kind, id, extra, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptAnsiblePayload(newKey, kind, id, extra, data)
	case "job":
		data, err := nexuscrypto.DecryptJobOutput(oldKey, id, extra, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptJobOutput(newKey, id, extra, data)
	case "template":
		data, err := nexuscrypto.DecryptTemplateDefinition(oldKey, id, value)
		if err != nil {
			return "", err
		}
		return nexuscrypto.EncryptTemplateDefinition(newKey, id, data)
	case "deployment":
		data, err := nexuscrypto.DecryptDeploymentVariables(oldKey, id, extra, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.EncryptDeploymentVariables(newKey, id, extra, data)
	default:
		data, err := nexuscrypto.Decrypt(oldKey, value)
		if err != nil {
			return "", err
		}
		defer clear(data)
		return nexuscrypto.Encrypt(newKey, data)
	}
}
func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return file.Close()
}
func syncPrivateFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync recovery database: %w", err)
	}
	return nil
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
