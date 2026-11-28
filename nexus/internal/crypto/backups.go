package crypto

import (
	"errors"
	"strings"
)

func backupBinding(id, server string) ([]byte, error) {
	if id == "" || strings.ContainsRune(id+server, 0) {
		return nil, errors.New("invalid backup context")
	}
	return []byte("nexus:backup-policy:v1\x00" + id + "\x00" + server), nil
}
func EncryptBackupPolicy(key []byte, id, server string, data []byte) (string, error) {
	context, err := backupBinding(id, server)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid backup context")
	}
	value, err := EncryptBound(key, data, context)
	return "v1:" + value, err
}
func DecryptBackupPolicy(key []byte, id, server, value string) ([]byte, error) {
	context, err := backupBinding(id, server)
	if err != nil || len(key) != 32 || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid backup context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), context)
}

func retentionBinding(id, binding string) ([]byte, error) {
	if id == "" || binding == "" || strings.ContainsRune(id+binding, 0) {
		return nil, errors.New("invalid backup retention context")
	}
	return []byte("nexus:backup-retention:v1\x00" + id + "\x00" + binding), nil
}
func EncryptBackupRetention(key []byte, id, binding string, data []byte) (string, error) {
	context, err := retentionBinding(id, binding)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid backup retention context")
	}
	value, err := EncryptBound(key, data, context)
	return "v1:" + value, err
}
func DecryptBackupRetention(key []byte, id, binding, value string) ([]byte, error) {
	context, err := retentionBinding(id, binding)
	if err != nil || len(key) != 32 || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid backup retention context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), context)
}
