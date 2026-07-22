package config

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	PasswordHash  string
	EncryptionKey []byte
	Port          string
	DBPath        string
	StaticDir     string
	TOTPSecret    string
	TOTPEnabled   bool
	TrustProxy    bool
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

	return &Config{
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
	if err := setEnvValue("NEXUS_PASSWORD_HASH", "'"+newHash+"'"); err != nil {
		return err
	}
	c.PasswordHash = newHash
	return nil
}

func (c *Config) UpdateTOTP(secret string, enabled bool) error {
	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	if err := setEnvValue("NEXUS_TOTP_SECRET", secret); err != nil {
		return err
	}
	if err := setEnvValue("NEXUS_TOTP_ENABLED", enabledStr); err != nil {
		return err
	}
	c.TOTPSecret = secret
	c.TOTPEnabled = enabled
	return nil
}

func setEnvValue(key, value string) error {
	const envFile = ".env"
	content := ""
	if data, err := os.ReadFile(envFile); err == nil {
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") || strings.HasPrefix(line, key+"='") {
			lines[i] = key + "=" + value
			found = true
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return os.WriteFile(envFile, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}
