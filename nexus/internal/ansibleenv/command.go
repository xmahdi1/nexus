// Package ansibleenv supplies only fixed, reviewed controller environment actions.
package ansibleenv

import (
	_ "embed"
	"errors"
	"strings"
)

//go:generate python3 ../../../scripts/generate_ansible_bundle.py
//go:embed remote.py
var remote string

func Command(action string) (string, error) {
	switch action {
	case "install", "update", "health", "remove":
	default:
		return "", errors.New("invalid environment action")
	}
	code := "ACTION=" + "'" + action + "'\nBUNDLE='" + bundle + "'\n" + remote
	command := "exec /usr/bin/python3 -I -c '" + strings.ReplaceAll(code, "'", `'"'"'`) + "'"
	if len(command) > 16384 {
		return "", errors.New("reviewed environment bundle exceeds supervisor command limit")
	}
	return command, nil
}
