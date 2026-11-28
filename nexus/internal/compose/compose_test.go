package compose

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/testdocker"
	"github.com/xmahdi1/nexus/internal/testssh"
	"golang.org/x/crypto/ssh"
)

func TestDisposableComposeStatefulUpgradeRollback(t *testing.T) {
	lab := testdocker.New(t)
	lab.Write("one", "alpine:3.21")
	// A decoy default file must never be selected instead of the supplied path.
	if err := os.WriteFile(filepath.Join(lab.Directory, "docker-compose.yml"), []byte("invalid: default-file-must-not-run\n"), 0600); err != nil {
		t.Fatal(err)
	}

	dockerBinary, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(lab.Directory, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\nexec " + shellescape(dockerBinary) + " --host unix:///var/run/docker.sock \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	prefix := "cd " + shellescape(lab.Directory) + " && " + dockerPath + " compose -f " + shellescape(filepath.Base(lab.Recipe)) + " "
	allowed := map[string]bool{prefix + "up -d 2>&1": true, prefix + "down 2>&1": true}
	client := testssh.Client(t, func(channel ssh.Channel, command string) uint32 {
		if !allowed[command] {
			io.WriteString(channel.Stderr(), "fixture rejected command")
			return 126
		}
		// Execute the actual adapter shell command, confined by the exact
		// allowlist, owned recipe and local-socket-only Docker wrapper.
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "DOCKER_CONFIG=" + lab.Directory, "COMPOSE_DISABLE_ENV_FILE=1"}
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()
		if err := cmd.Run(); err != nil {
			return 1
		}
		return 0
	})

	ctx := context.Background()
	if out, err := Up(ctx, client, lab.Recipe); err != nil {
		t.Fatalf("initial deploy: %s %v", out, err)
	}
	lab.Must("exec", "-T", "stateful", "sh", "-c", "printf volume-sentinel > /state/marker; printf bind-sentinel > /bind/marker")
	verify := func(version string) {
		t.Helper()
		out := lab.Must("exec", "-T", "stateful", "sh", "-c", "printf '%s|' \"$FIXTURE_VERSION\"; cat /state/marker /bind/marker")
		if out != version+"|volume-sentinelbind-sentinel" {
			t.Fatalf("state changed: %q", out)
		}
	}
	lab.Write("two", "alpine:3.21")
	if out, err := Up(ctx, client, lab.Recipe); err != nil {
		t.Fatalf("upgrade: %s %v", out, err)
	}
	verify("two")
	lab.Write("failed", "nexus-invalid-fixture-"+lab.Project+":never-pull")
	if _, err := Up(ctx, client, lab.Recipe); err == nil {
		t.Fatal("failed deploy reported success")
	}
	lab.Write("one", "alpine:3.21")
	if out, err := Up(ctx, client, lab.Recipe); err != nil {
		t.Fatalf("explicit rollback: %s %v", out, err)
	}
	verify("one")
	if out, err := Down(ctx, client, lab.Recipe); err != nil {
		t.Fatalf("shutdown: %s %v", out, err)
	}
	if out, err := lab.Docker("volume", "inspect", lab.Project+"_state"); err != nil {
		t.Fatalf("named volume deleted: %s %v", out, err)
	}
	if _, err := os.Stat(lab.Recipe); err != nil {
		t.Fatal("recipe deleted", err)
	}
	if content, err := os.ReadFile(filepath.Join(lab.Directory, "bind", "marker")); err != nil || string(content) != "bind-sentinel" {
		t.Fatal("bind state lost", err)
	}
	if out, err := Up(ctx, client, lab.Recipe); err != nil {
		t.Fatalf("reopen preserved data: %s %v", out, err)
	}
	verify("one")
	t.Log("Real local daemon: explicit recipe, initial deployment, upgrade, failed deployment, explicit rollback, down and data-preserving restart passed")
}

func TestComposeRecipeUsesStdinAndPrivatePermissions(t *testing.T) {
	directory := t.TempDir()
	recipe := filepath.Join(directory, "quoted ' recipe\n.yml")
	secret := "fixture-value-from-stdin"
	client := testssh.Client(t, func(channel ssh.Channel, command string) uint32 {
		if (command != writeCommand && command != readCommand) ||
			strings.Contains(command, recipe) || strings.Contains(command, secret) {
			return 126
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		cmd.Stdin = channel
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()
		if err := cmd.Run(); err != nil {
			return 1
		}
		return 0
	})
	if err := WriteFile(context.Background(), client, recipe, secret); err != nil {
		t.Fatal(err)
	}
	content, err := ReadFile(context.Background(), client, recipe)
	if err != nil || content != secret {
		t.Fatalf("roundtrip: %q %v", content, err)
	}
	info, err := os.Stat(recipe)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("recipe not private: %v %v", info, err)
	}
}

func TestComposeInterruptedWritePreservesPreviousRecipe(t *testing.T) {
	directory := t.TempDir()
	recipe := filepath.Join(directory, "compose.yml")
	if err := os.WriteFile(recipe, []byte("previous complete recipe"), 0644); err != nil {
		t.Fatal(err)
	}
	content := "new complete recipe"
	client := testssh.Client(t, func(channel ssh.Channel, command string) uint32 {
		if command != writeCommand {
			return 126
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		// Simulate an interrupted SSH upload: the remote process sees only a prefix.
		cmd.Stdin = io.LimitReader(channel, int64(len(pathInput(recipe))+65+5))
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()
		if err := cmd.Run(); err != nil {
			return 1
		}
		return 0
	})
	if err := WriteFile(context.Background(), client, recipe, content); err == nil {
		t.Fatal("truncated recipe was accepted")
	}
	previous, err := os.ReadFile(recipe)
	if err != nil || string(previous) != "previous complete recipe" {
		t.Fatal("previous recipe was replaced", err)
	}
	matches, err := filepath.Glob(recipe + ".nexus.*")
	if err != nil || len(matches) > 0 {
		t.Fatal("temporary recipe not cleaned", err)
	}
}
