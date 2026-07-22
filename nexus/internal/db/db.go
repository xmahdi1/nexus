package db

import (
	"os"

	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Init(path string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&models.Server{},
	); err != nil {
		return nil, err
	}

	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}

	return db, nil
}
