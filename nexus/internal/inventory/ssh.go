package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type SSHAdapter struct {
	DB   *gorm.DB
	Key  []byte
	Pool *nexusssh.Pool
}
type boundedOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.b.Len()+len(p) > 1<<20 {
		return 0, errors.New("collector output limit")
	}
	return w.b.Write(p)
}
func run(ctx context.Context, client *ssh.Client, command string) (string, error) {
	session, err := nexusssh.OpenSession(ctx, client)
	if err != nil {
		return "", err
	}
	defer session.Close()
	output := &boundedOutput{}
	session.Stdout = output
	session.Stderr = &boundedOutput{}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			session.Close()
		case <-done:
		}
	}()
	if err := session.Run(command); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return output.b.String(), nil
}
func (a *SSHAdapter) Collect(ctx context.Context, serverID string) (Observation, error) {
	var obs Observation
	var server models.Server
	if err := a.DB.First(&server, "id=?", serverID).Error; err != nil {
		return obs, err
	}
	key, err := nexuscrypto.Decrypt(a.Key, server.PrivateKeyEnc)
	if err != nil {
		return obs, err
	}
	defer clear(key)
	client, err := a.Pool.GetContext(ctx, nexusssh.ServerConfig{ID: server.ID, Host: server.Host, Port: server.Port, User: server.Username, PrivKey: key})
	if err != nil {
		return obs, err
	}
	raw, err := run(ctx, client, `printf '%s\n' "$(hostname)" "$(uname -r)" "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -c 512)"`)
	if err != nil {
		return obs, err
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 || len(lines) > 3 || len(lines[0]) > 255 || len(lines[1]) > 255 {
		return obs, errors.New("invalid host observation")
	}
	obs.Host = Host{Hostname: clean(lines[0]), Kernel: clean(lines[1])}
	if len(lines) > 2 {
		obs.Host.OS = clean(lines[2])
	}
	obs.HostOK = obs.Host.Hostname != "" && obs.Host.Kernel != ""
	if raw, err := run(ctx, client, "ss -H -lntu"); err == nil {
		ports, parseErr := parseSockets(raw)
		if parseErr == nil {
			obs.Ports = ports
			obs.SocketsOK = true
		}
	}
	if raw, err := run(ctx, client, serviceCommand); err == nil {
		if units, err := parseServices(raw); err == nil {
			obs.Services = units
			obs.ServicesOK = true
		}
	}
	ids, err := run(ctx, client, "command -v docker >/dev/null 2>&1 && docker --host unix:///var/run/docker.sock ps -aq --no-trunc")
	if err != nil {
		return obs, nil
	}
	list := strings.Fields(ids)
	if len(list) > 500 {
		return obs, nil
	}
	for _, id := range list {
		if !containerID.MatchString(id) {
			return obs, nil
		}
	}
	if len(list) == 0 {
		obs.DockerOK = true
		return obs, nil
	}
	raw, err = run(ctx, client, `docker --host unix:///var/run/docker.sock inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"state":{{json .State.Status}},"exposed":{{json .Config.ExposedPorts}},"published":{{json .NetworkSettings.Ports}}}' `+strings.Join(list, " "))
	if err != nil {
		return obs, nil
	}
	containers, ports, err := parseDocker(raw)
	if err != nil {
		return obs, nil
	}
	obs.Containers = containers
	obs.Ports = append(obs.Ports, ports...)
	obs.DockerOK = true
	return obs, nil
}

var containerID = regexp.MustCompile(`^[a-fA-F0-9]{12,64}$`)

const serviceCommand = "LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0 systemctl show --all --no-pager --property=Id,LoadState,ActiveState,SubState '*.service'"

var serviceUnitPattern = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+\.service$`)
var serviceStatePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func validService(unit ServiceUnit) bool {
	return len(unit.Unit) <= 255 && serviceUnitPattern.MatchString(unit.Unit) && serviceStatePattern.MatchString(unit.Load) && serviceStatePattern.MatchString(unit.Active) && serviceStatePattern.MatchString(unit.Sub)
}
func parseServices(raw string) ([]ServiceUnit, error) {
	if len(raw) > 1<<20 {
		return nil, errors.New("invalid service collection")
	}
	rows := []ServiceUnit{}
	seen := map[string]bool{}
	for _, block := range strings.Split(strings.TrimSpace(raw), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		values := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return nil, errors.New("invalid service properties")
			}
			if _, exists := values[key]; exists {
				return nil, errors.New("duplicate service property")
			}
			switch key {
			case "Id", "LoadState", "ActiveState", "SubState":
				values[key] = value
			default:
				return nil, errors.New("unexpected service property")
			}
		}
		unit := ServiceUnit{Unit: values["Id"], Load: values["LoadState"], Active: values["ActiveState"], Sub: values["SubState"]}
		if len(values) != 4 || !validService(unit) || seen[unit.Unit] || len(rows) >= 1000 {
			return nil, errors.New("invalid service unit")
		}
		seen[unit.Unit] = true
		rows = append(rows, unit)
	}
	return rows, nil
}

func parseSockets(raw string) ([]Port, error) {
	result := []Port{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 {
			return nil, errors.New("unsupported socket format")
		}
		protocol := f[0]
		if protocol != "tcp" && protocol != "udp" {
			return nil, errors.New("unsupported socket protocol")
		}
		local := f[4]
		index := strings.LastIndex(local, ":")
		if index < 0 {
			return nil, errors.New("unsupported address")
		}
		address := strings.Trim(local[:index], "[]")
		port, err := strconv.Atoi(local[index+1:])
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid socket port")
		}
		if address != "*" && net.ParseIP(strings.Split(address, "%")[0]) == nil {
			return nil, errors.New("invalid socket address")
		}
		result = append(result, Port{Protocol: protocol, Address: address, Port: port, Exposure: "listener"})
		if len(result) > 10000 {
			return nil, errors.New("too many listeners")
		}
	}
	return result, nil
}
func parseDocker(raw string) ([]Container, []Port, error) {
	containers := []Container{}
	ports := []Port{}
	type binding struct{ HostIP, HostPort string }
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row struct {
			ID, Name, Image, State string
			Exposed                map[string]json.RawMessage
			Published              map[string][]binding
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, nil, err
		}
		if !containerID.MatchString(row.ID) {
			return nil, nil, errors.New("invalid Docker ID")
		}
		containers = append(containers, Container{ID: row.ID, Name: strings.TrimPrefix(row.Name, "/"), Image: row.Image, State: row.State})
		for key := range row.Exposed {
			port, protocol, err := portKey(key)
			if err != nil {
				return nil, nil, err
			}
			ports = append(ports, Port{ContainerID: row.ID, Protocol: protocol, Port: port, TargetPort: port, Exposure: "container_internal"})
		}
		for key, bindings := range row.Published {
			target, protocol, err := portKey(key)
			if err != nil {
				return nil, nil, err
			}
			for _, binding := range bindings {
				port, err := strconv.Atoi(binding.HostPort)
				if err != nil || port < 1 || port > 65535 {
					return nil, nil, errors.New("invalid published port")
				}
				if binding.HostIP != "" && net.ParseIP(binding.HostIP) == nil {
					return nil, nil, errors.New("invalid published address")
				}
				ports = append(ports, Port{ContainerID: row.ID, Protocol: protocol, Address: binding.HostIP, Port: port, TargetPort: target, Exposure: "container_published"})
			}
		}
		if len(containers) > 500 || len(ports) > 10000 {
			return nil, nil, errors.New("Docker observation limit")
		}
	}
	return containers, ports, nil
}
func portKey(value string) (int, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid port key")
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil || port < 1 || port > 65535 || (parts[1] != "tcp" && parts[1] != "udp" && parts[1] != "sctp") {
		return 0, "", errors.New("invalid port key")
	}
	return port, parts[1], nil
}
