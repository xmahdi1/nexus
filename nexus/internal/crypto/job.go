package crypto

import (
	"errors"
	"strings"
)

func EncryptJobOutput(key []byte, id, server string, plaintext []byte) (string, error) {
	if len(key) != 32 || id == "" || server == "" || strings.ContainsAny(id+server, "\x00") {
		return "", errors.New("invalid job output context")
	}
	sealed, err := EncryptBound(key, plaintext, []byte("nexus:job-output:v1\x00"+id+"\x00"+server))
	if err != nil {
		return "", err
	}
	return "v1:" + sealed, nil
}
func DecryptJobOutput(key []byte, id, server, value string) ([]byte, error) {
	if len(key) != 32 || id == "" || server == "" || strings.ContainsAny(id+server, "\x00") || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid job output context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), []byte("nexus:job-output:v1\x00"+id+"\x00"+server))
}
