// Package remoteaction defines the fixed server operations that may use the
// persistent process supervisor. It accepts targets, never caller shell code.
package remoteaction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/xmahdi1/nexus/internal/ansibleenv"
	"path"
	"regexp"
	"strings"
)

type Spec struct {
	ID, Route, Label string
	Permissions      []string
	ReadPermission   string
}

var catalog = []Spec{
	{"ansible-environment-install", "ansible/environment/install", "Install Ansible environment", strings.Fields("ansible.environment.manage servers.execute secrets.use"), "ansible.environment.read"},
	{"ansible-environment-update", "ansible/environment/update", "Update Ansible environment", strings.Fields("ansible.environment.manage servers.execute secrets.use"), "ansible.environment.read"},
	{"ansible-environment-health", "ansible/environment/health", "Check Ansible environment", strings.Fields("ansible.environment.read servers.execute secrets.use"), "ansible.environment.read"},
	{"ansible-environment-remove", "ansible/environment/remove", "Remove Ansible environment", strings.Fields("ansible.environment.manage servers.execute secrets.use"), "ansible.environment.read"},
	{"compose-up", "compose/up", "Start Compose services", strings.Fields("compose.write deployments.execute servers.execute secrets.use"), "compose.read"},
	{"compose-down", "compose/down", "Stop Compose services", strings.Fields("compose.write deployments.execute servers.execute secrets.use"), "compose.read"},
	{"container-start", "containers/{cid}/start", "Start container", strings.Fields("docker.manage servers.execute secrets.use"), "docker.read"},
	{"container-stop", "containers/{cid}/stop", "Stop container", strings.Fields("docker.manage servers.execute secrets.use"), "docker.read"},
	{"container-restart", "containers/{cid}/restart", "Restart container", strings.Fields("docker.manage servers.execute secrets.use"), "docker.read"},
	{"container-remove", "containers/{cid}/remove", "Remove stopped container", strings.Fields("docker.remove servers.execute secrets.use"), "docker.read"},
}

func Catalog() []Spec {
	out := append([]Spec{}, catalog...)
	for i := range out {
		out[i].Permissions = append([]string{}, out[i].Permissions...)
	}
	return out
}
func Find(id string) (Spec, bool) {
	for _, s := range Catalog() {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

var requestID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var containerID = regexp.MustCompile(`^[a-fA-F0-9]{12,64}$`)
var ErrInput = errors.New("invalid supervised operation target or request ID")

func ValidID(id string) bool { return requestID.MatchString(id) }

// Build pins operations to this registered host's local engine. Source files
// and volumes are preserved; container removal is deliberately never forced.
func Build(id, composePath, cid string) (command, targetHash string, err error) {
	spec, ok := Find(id)
	if !ok {
		return "", "", ErrInput
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }
	const prefix = `export PATH="$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/bin:/sbin"; `
	const docker = "docker --host unix:///var/run/docker.sock "
	target := ""
	if strings.HasPrefix(spec.ID, "ansible-environment-") {
		if composePath != "" || cid != "" {
			return "", "", ErrInput
		}
		command, err := ansibleenv.Command(strings.TrimPrefix(spec.ID, "ansible-environment-"))
		if err != nil {
			return "", "", err
		}
		digest := sha256.Sum256([]byte(command))
		return command, hex.EncodeToString(digest[:]), nil
	}
	if strings.HasPrefix(spec.ID, "compose-") {
		if cid != "" || len(composePath) > 4096 || !path.IsAbs(composePath) || path.Clean(composePath) != composePath || strings.ContainsAny(composePath, "\r\n\x00") {
			return "", "", ErrInput
		}
		target = composePath
		action := "up -d"
		if spec.ID == "compose-down" {
			action = "down"
		}
		command = prefix + "cd -- " + quote(path.Dir(composePath)) + " && exec " + docker + "compose -f " + quote(path.Base(composePath)) + " " + action
	} else {
		if composePath != "" || !containerID.MatchString(cid) {
			return "", "", ErrInput
		}
		target = strings.ToLower(cid)
		action := strings.TrimPrefix(spec.ID, "container-")
		if action == "remove" {
			action = "rm"
		}
		if action == "stop" || action == "restart" {
			action += " --time 30"
		}
		command = prefix + "exec " + docker + action + " -- " + quote(target)
	}
	digest := sha256.Sum256([]byte(spec.ID + "\x00" + target))
	return command, hex.EncodeToString(digest[:]), nil
}
