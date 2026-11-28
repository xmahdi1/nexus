package crypto

import (
	"errors"
	"strings"
)

func EncryptNotificationToken(key []byte, id string, value []byte) (string, error) {
	if len(key) != 32 || id == "" || strings.ContainsRune(id, 0) {
		return "", errors.New("invalid notification context")
	}
	sealed, err := EncryptBound(key, value, []byte("nexus:notification-token:v1\x00"+id))
	if err != nil {
		return "", err
	}
	return "v1:" + sealed, nil
}

func DecryptNotificationToken(key []byte, id, value string) ([]byte, error) {
	if len(key) != 32 || id == "" || strings.ContainsRune(id, 0) || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid notification context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), []byte("nexus:notification-token:v1\x00"+id))
}
