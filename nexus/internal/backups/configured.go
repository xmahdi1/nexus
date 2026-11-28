package backups

import (
	"path/filepath"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

func Configured(database *gorm.DB, cfg *config.Config, pool *nexusssh.Pool) *Runtime {
	source, _ := filepath.Abs(cfg.DBPath)
	root := cfg.BackupWorkRoot
	if root == "" {
		root = filepath.Join(filepath.Dir(source), "backup-work")
	}
	root, _ = filepath.Abs(root)
	service := &Service{DB: database, Key: cfg.EncryptionKey, Sessions: auth.NewService(database, cfg), Enabled: cfg.BackupsEnabled, DBPath: source, WorkRoot: root}
	runtime := NewRuntime(service, pool, cfg.OperationSupervisionEnabled)
	runtime.RecoveryAuth = cfg.AuthSnapshot
	return runtime
}
