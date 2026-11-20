package proxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyConfigurationTransactionRestoresFilesAndLinks(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("POSIX flock required for remote config transaction test")
	}
	for _, failure := range []string{"validation", "reload", "none"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			config := filepath.Join(directory, "site.conf")
			link := filepath.Join(directory, "enabled")
			if err := os.WriteFile(config, []byte("previous complete config"), 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(config, link); err != nil {
				t.Fatal(err)
			}
			validate := "true"
			reload := "true"
			if failure == "validation" {
				validate = "false"
			}
			if failure == "reload" {
				marker := shellQuote(filepath.Join(directory, "reload-attempted"))
				reload = "test -f " + marker + " || { touch " + marker + "; false; }"
			}
			change := "printf 'replacement config' > " + shellQuote(config) + " || exit 1\nrm -f -- " + shellQuote(link) + " || exit 1"
			script := configurationTransaction([]string{config, link}, change, validate, reload, filepath.Join(directory, "lock"), filepath.Join(directory, "backup.XXXXXXXXXX"))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "-c", script)
			output, err := cmd.CombinedOutput()
			if failure == "none" {
				if err != nil {
					t.Fatalf("commit failed: %v %s", err, output)
				}
				content, _ := os.ReadFile(config)
				if string(content) != "replacement config" {
					t.Fatal("new configuration not committed")
				}
				if _, err := os.Lstat(link); !os.IsNotExist(err) {
					t.Fatal("new link state not committed")
				}
			} else {
				if err == nil {
					t.Fatal("failed validation/reload reported success")
				}
				content, err := os.ReadFile(config)
				if err != nil || string(content) != "previous complete config" {
					t.Fatal("original configuration lost", err)
				}
				target, err := os.Readlink(link)
				if err != nil || target != config {
					t.Fatal("original symlink lost", err)
				}
				info, err := os.Stat(config)
				if err != nil || info.Mode().Perm() != 0640 {
					t.Fatal("original mode not preserved", err)
				}
			}
			remaining, _ := filepath.Glob(filepath.Join(directory, "backup.*"))
			if len(remaining) != 0 {
				t.Fatal("private temporary backup was not cleaned")
			}
		})
	}
}
func TestProxyRollbackFailureRetainsPrivateRecoverySet(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("POSIX flock required")
	}
	directory := t.TempDir()
	config := filepath.Join(directory, "site.conf")
	if err := os.WriteFile(config, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	script := configurationTransaction([]string{config}, "printf changed > "+shellQuote(config), "true", "false", filepath.Join(directory, "lock"), filepath.Join(directory, "backup.XXXXXXXXXX"))
	cmd := exec.Command("sh", "-c", script)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "private backup retained") {
		t.Fatal("rollback failure hidden", err)
	}
	retained, _ := filepath.Glob(filepath.Join(directory, "backup.*"))
	if len(retained) != 1 {
		t.Fatal("missing recovery set")
	}
	info, err := os.Stat(retained[0])
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("recovery set is not private", err)
	}
	content, err := os.ReadFile(filepath.Join(retained[0], "0"))
	if err != nil || string(content) != "original" {
		t.Fatal("recovery set lost original", err)
	}
}
func TestProxyTargetValidationBoundsPortsAndSupportsIPv6(t *testing.T) {
	for _, target := range []string{"127.0.0.1:0", "127.0.0.1:65536", "backend:+80", "bad host:80", "-bad:80", "a..b:80"} {
		if validTarget(target) {
			t.Fatal("invalid target accepted", target)
		}
	}
	for _, target := range []string{"127.0.0.1:8080", "backend:80", "backend.internal:65535", "[::1]:8080"} {
		if !validTarget(target) {
			t.Fatal("valid target rejected", target)
		}
	}
}

func TestNginxUpstreamEditPreservesCertificateDirectives(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "tls.conf")
	original := "server {\n listen 443 ssl;\n ssl_certificate /private/fixture.crt;\n ssl_certificate_key /private/fixture.key;\n location / {\n  proxy_pass http://127.0.0.1:80;\n }\n}\n"
	if err := os.WriteFile(config, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", nginxTargetChange(config, "[::1]:8080"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("upstream edit failed: %v %s", err, out)
	}
	actual, err := os.ReadFile(config)
	expected := strings.Replace(original, "127.0.0.1:80", "[::1]:8080", 1)
	if err != nil || string(actual) != expected {
		t.Fatal("certificate/directive data changed during upstream edit", err)
	}
}
