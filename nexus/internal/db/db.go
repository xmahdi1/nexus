package db

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Init completes checked, versioned migrations before returning a database to
// handlers or background workers. Existing installations are snapshotted before
// the first pending migration. A failure prevents application startup.
func Init(path string) (*gorm.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Create with private permissions before SQLite opens it (rather than chmod
	// after migrations). Never truncate an existing installation.
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(absolute, 0600); err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: absolute, RawQuery: "_busy_timeout=5000&_txlock=immediate"}
	database, err := gorm.Open(sqlite.Open(uri.String()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	conn, err := database.DB()
	if err != nil {
		return nil, err
	}
	err = migrate(database, schemaMigrations, func() error {
		random := make([]byte, 8)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		destination := absolute + ".pre-migration-" + hex.EncodeToString(random) + ".db"
		if err := Backup(absolute, destination); err != nil {
			return err
		}
		log.Printf("database pre-migration backup created: %s", destination)
		return nil
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("database initialization: %w", err)
	}
	return database, nil
}
