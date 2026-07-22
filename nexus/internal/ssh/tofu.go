package ssh

import (
	"fmt"

	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func TOFUVerifier(db *gorm.DB) HostKeyCallback {
	return func(serverID, fingerprint string) error {
		var server models.Server
		if err := db.First(&server, "id = ?", serverID).Error; err != nil {
			return fmt.Errorf("server not found: %w", err)
		}
		if server.KnownHostKey == "" {
			if err := db.Model(&server).Update("known_host_key", fingerprint).Error; err != nil {
				return fmt.Errorf("could not store host key: %w", err)
			}
			return nil
		}
		if server.KnownHostKey != fingerprint {
			return fmt.Errorf(
				"HOST KEY MISMATCH for %s — expected %s, got %s\n"+
					"If the server was reinstalled, remove and re-add it in Nexus.",
				server.Host, server.KnownHostKey, fingerprint,
			)
		}
		return nil
	}
}
