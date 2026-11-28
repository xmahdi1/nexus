package crypto

import (
	"errors"
	"strings"
)

func githubBinding(kind, id, server string) ([]byte, error) {
	if (kind != "connection" && kind != "dispatch" && kind != "change" && kind != "webhook" && kind != "organization" && kind != "organization-change") || id == "" || server == "" || strings.ContainsRune(id+server, 0) {
		return nil, errors.New("invalid GitHub encryption context")
	}
	return []byte("nexus:github-" + kind + ":v1\x00" + id + "\x00" + server), nil
}
func EncryptGitHubPayload(key []byte, kind, id, server string, data []byte) (string, error) {
	bound, err := githubBinding(kind, id, server)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid GitHub encryption context")
	}
	value, err := EncryptBound(key, data, bound)
	if err != nil {
		return "", err
	}
	return "v1:" + value, nil
}
func DecryptGitHubPayload(key []byte, kind, id, server, value string) ([]byte, error) {
	bound, err := githubBinding(kind, id, server)
	if err != nil || len(key) != 32 || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid GitHub encryption context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), bound)
}
