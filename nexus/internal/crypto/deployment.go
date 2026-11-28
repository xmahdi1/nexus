package crypto

import (
	"errors"
	"strings"
)

// Bind ciphertext to its purpose and stable deployment/server identity. Existing
// SSH/MFA encryption remains compatible with the earlier unbound format.
func deploymentBinding(id, server string) []byte {
	return []byte("nexus:deployment-variables:v1\x00" + id + "\x00" + server)
}
func EncryptDeploymentVariables(key []byte, id, server string, plaintext []byte) (string, error) {
	if len(key) != 32 || id == "" || server == "" || strings.ContainsAny(id+server, "\x00") {
		return "", errors.New("invalid deployment encryption context")
	}
	value, err := EncryptBound(key, plaintext, deploymentBinding(id, server))
	if err != nil {
		return "", err
	}
	return "v1:" + value, nil
}
func DecryptDeploymentVariables(key []byte, id, server, value string) ([]byte, error) {
	if len(key) != 32 || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid deployment encryption context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), deploymentBinding(id, server))
}
