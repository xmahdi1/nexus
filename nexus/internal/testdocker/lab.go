// Package testdocker owns uniquely named, local-only disposable daemon resources.
package testdocker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type Lab struct {
	T                          testing.TB
	Directory, Recipe, Project string
}

func New(t testing.TB) *Lab {
	t.Helper()
	if os.Getenv("NEXUS_DISPOSABLE_DOCKER") != "1" {
		t.Skip("set NEXUS_DISPOSABLE_DOCKER=1 for owned local Docker integration")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	lab := &Lab{T: t, Directory: directory, Recipe: filepath.Join(directory, "fixture recipe.yml"), Project: "nexus-release-" + hex.EncodeToString(nonce)}
	if out, err := lab.Docker("image", "inspect", "alpine:3.21"); err != nil {
		t.Fatalf("local alpine:3.21 required (no image pulls): %s %v", out, err)
	}
	t.Cleanup(func() {
		// Explicit project/recipe only: no global prune, user image removal or external volumes.
		if out, err := lab.Compose("down", "--volumes", "--remove-orphans"); err != nil {
			t.Errorf("owned fixture cleanup failed: %s %v", out, err)
		}
	})
	return lab
}
func (l *Lab) Docker(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
	// Avoid user Docker contexts, registry credentials and Compose environment files.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "DOCKER_CONFIG=" + l.Directory, "COMPOSE_DISABLE_ENV_FILE=1"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func (l *Lab) Compose(args ...string) (string, error) {
	return l.Docker(append([]string{"compose", "--project-name", l.Project, "--file", l.Recipe}, args...)...)
}
func (l *Lab) Write(version, image string) {
	l.T.Helper()
	if err := os.MkdirAll(filepath.Join(l.Directory, "bind"), 0700); err != nil {
		l.T.Fatal(err)
	}
	// Fixture paths cannot contain quotes under testing.TempDir on this platform.
	if err := os.Chmod(filepath.Join(l.Directory, "bind"), 0777); err != nil {
		l.T.Fatal(err)
	}
	recipe := fmt.Sprintf(`name: %s
services:
  stateful:
    image: %s
    pull_policy: never
    command: ["sleep", "3600"]
    environment:
      FIXTURE_VERSION: %s
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 32
    mem_limit: 32m
    volumes:
      - state:/state
      - '%s/bind:/bind'
volumes:
  state:
`, l.Project, image, version, l.Directory)
	if err := os.WriteFile(l.Recipe, []byte(recipe), 0600); err != nil {
		l.T.Fatal(err)
	}
}
func (l *Lab) Must(args ...string) string {
	l.T.Helper()
	out, err := l.Compose(args...)
	if err != nil {
		l.T.Fatalf("fixture compose %v: %s %v", args, out, err)
	}
	return out
}
