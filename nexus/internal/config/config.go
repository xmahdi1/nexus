package config

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	ACME                  ACMEConfig
	InventoryEnabled      bool
	VaultEnabled          bool
	JobSupervisionEnabled bool

	authMu             sync.RWMutex
	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration
	PasswordHash       string
	EncryptionKey      []byte
	Port               string
	DBPath             string
	StaticDir          string
	TOTPSecret         string
	TOTPEnabled        bool
	TrustProxy         bool
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	hash := os.Getenv("NEXUS_PASSWORD_HASH")
	if hash == "" {
		return nil, errors.New("NEXUS_PASSWORD_HASH is not set — run 'nexus setup' first")
	}

	keyB64 := os.Getenv("NEXUS_ENCRYPTION_KEY")
	if keyB64 == "" {
		return nil, errors.New("NEXUS_ENCRYPTION_KEY is not set — run 'nexus setup' first")
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return nil, errors.New("NEXUS_ENCRYPTION_KEY must be a base64-encoded 32-byte value")
	}

	port := os.Getenv("NEXUS_PORT")
	if port == "" {
		port = "8080"
	}
	dbPath := os.Getenv("NEXUS_DB_PATH")
	if dbPath == "" {
		dbPath = "nexus.db"
	}

	idle, absolute := 12*time.Hour, 7*24*time.Hour
	for name, target := range map[string]*time.Duration{"NEXUS_SESSION_IDLE_TTL": &idle, "NEXUS_SESSION_ABSOLUTE_TTL": &absolute} {
		if value := os.Getenv(name); value != "" {
			duration, err := time.ParseDuration(value)
			if err != nil || duration < time.Minute || duration > 30*24*time.Hour {
				return nil, errors.New(name + " must be between 1m and 720h")
			}
			*target = duration
		}
	}
	if idle > absolute {
		return nil, errors.New("session idle TTL must not exceed absolute TTL")
	}
	acme := ACMEConfig{DirectoryURL: os.Getenv("NEXUS_ACME_DIRECTORY_URL"), CAFile: os.Getenv("NEXUS_ACME_CA_FILE")}
	if err := acme.Validate(); err != nil {
		return nil, err
	}
	return &Config{
		ACME:                  acme,
		VaultEnabled:          os.Getenv("NEXUS_ENABLE_VAULT") == "true",
		InventoryEnabled:      os.Getenv("NEXUS_ENABLE_INVENTORY") == "true",
		JobSupervisionEnabled: os.Getenv("NEXUS_ENABLE_JOB_SUPERVISION") == "true",
		SessionIdleTTL:        idle, SessionAbsoluteTTL: absolute,
		PasswordHash:  hash,
		EncryptionKey: key,
		Port:          port,
		DBPath:        dbPath,
		StaticDir:     os.Getenv("NEXUS_STATIC_DIR"),
		TOTPSecret:    os.Getenv("NEXUS_TOTP_SECRET"),
		TOTPEnabled:   os.Getenv("NEXUS_TOTP_ENABLED") == "true",
		TrustProxy:    os.Getenv("NEXUS_TRUST_PROXY") == "true",
	}, nil
}

func (c *Config) UpdatePasswordHash(newHash string) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if err := setEnvValues(map[string]string{"NEXUS_PASSWORD_HASH": "'" + newHash + "'"}); err != nil {
		return err
	}
	c.PasswordHash = newHash
	return nil
}

func (c *Config) UpdateTOTP(secret string, enabled bool) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	if err := setEnvValues(map[string]string{"NEXUS_TOTP_SECRET": secret, "NEXUS_TOTP_ENABLED": enabledStr}); err != nil {
		return err
	}
	c.TOTPSecret = secret
	c.TOTPEnabled = enabled
	return nil
}

func setEnvValues(values map[string]string) error {
	const envFile = ".env"
	data, err := os.ReadFile(envFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for key, value := range values {
		found := false
		for i, line := range lines {
			if strings.HasPrefix(line, key+"=") {
				lines[i] = key + "=" + value
				found = true
			}
		}
		if !found {
			lines = append(lines, key+"="+value)
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(envFile), ".nexus-env-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), envFile)
}

func (c *Config) AuthSnapshot() (string, string, bool) {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.PasswordHash, c.TOTPSecret, c.TOTPEnabled
}
