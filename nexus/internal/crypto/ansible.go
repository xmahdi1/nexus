package crypto

import (
	"errors"
	"strings"
)

func ansibleBinding(kind, id, server string) ([]byte, error) {
	if (kind != "revision" && kind != "plan" && kind != "template" && kind != "preset" && kind != "schedule") || id == "" || server == "" || strings.ContainsRune(id+server, 0) {
		return nil, errors.New("invalid Ansible encryption context")
	}
	return []byte("nexus:ansible-" + kind + ":v1\x00" + id + "\x00" + server), nil
}
func EncryptAnsiblePayload(key []byte, kind, id, server string, data []byte) (string, error) {
	bound, err := ansibleBinding(kind, id, server)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid Ansible encryption context")
	}
	value, err := EncryptBound(key, data, bound)
	if err != nil {
		return "", err
	}
	return "v1:" + value, nil
}
func DecryptAnsiblePayload(key []byte, kind, id, server, value string) ([]byte, error) {
	bound, err := ansibleBinding(kind, id, server)
	if err != nil || len(key) != 32 || !strings.HasPrefix(value, "v1:") {
		return nil, errors.New("invalid Ansible encryption context")
	}
	return DecryptBound(key, strings.TrimPrefix(value, "v1:"), bound)
}
