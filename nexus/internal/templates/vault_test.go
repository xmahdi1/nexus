package templates

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestVaultVariablesCannotChangeListenerExposure(t *testing.T) {
	for _, port := range []string{"0.0.0.0:8200", "8200\n    privileged: true", "08200", "443", "65536"} {
		if validateVaultVariables(map[string]string{"PORT": port}) == nil {
			t.Fatal("unsafe Vault port accepted")
		}
	}
	if err := validateVaultVariables(map[string]string{"PORT": "8200"}); err != nil {
		t.Fatal(err)
	}
	compose := renderCompose(vaultTemplate().Compose, map[string]string{"PORT": "8200"})
	for _, unsafe := range []string{"-dev", "VAULT_DEV_ROOT_TOKEN_ID", "/var/run/docker.sock", "privileged: true"} {
		if strings.Contains(compose, unsafe) {
			t.Fatal("unsafe Vault deployment behavior", unsafe)
		}
	}
	if !strings.Contains(compose, "127.0.0.1:8200:8200") || !strings.Contains(compose, "create_host_path: false") {
		t.Fatal("Vault exposure/config guards missing")
	}
}

func TestVaultComposeConfiguration(t *testing.T) {
	if os.Getenv("NEXUS_VAULT_LAB_COMPOSE") != "1" {
		t.Skip("run scripts/vault_lab.py")
	}
	command := exec.Command("docker", "compose", "--project-directory", t.TempDir(), "-f", "-", "config", "--format", "json")
	command.Stdin = strings.NewReader(renderCompose(vaultTemplate().Compose, map[string]string{"PORT": "8200"}))
	output, err := command.Output()
	if err != nil {
		t.Fatal("Vault recipe rejected by Docker Compose", err)
	}
	var parsed struct {
		Services map[string]struct {
			User     string `json:"user"`
			ReadOnly bool   `json:"read_only"`
			Ports    []struct {
				HostIP string `json:"host_ip"`
			} `json:"ports"`
			Volumes []struct {
				Type     string `json:"type"`
				ReadOnly bool   `json:"read_only"`
				Bind     struct {
					CreateHostPath bool `json:"create_host_path"`
				} `json:"bind"`
			} `json:"volumes"`
		} `json:"services"`
	}
	if json.Unmarshal(output, &parsed) != nil {
		t.Fatal("invalid Compose output")
	}
	service := parsed.Services["vault"]
	if service.User != "100:1000" || !service.ReadOnly || len(service.Ports) != 1 || service.Ports[0].HostIP != "127.0.0.1" {
		t.Fatal("Compose altered Vault isolation")
	}
	for _, mount := range service.Volumes {
		if mount.Type == "bind" && (!mount.ReadOnly || mount.Bind.CreateHostPath) {
			t.Fatal("unsafe bind expansion")
		}
	}
}
