package remoteaction

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionsRejectShellInputsAndPinLocalEngine(t *testing.T) {
	for _, input := range []struct{ action, path, cid string }{
		{"arbitrary", "/x", ""}, {"compose-up", "relative.yml", ""}, {"compose-up", "/tmp/a\nreboot", ""}, {"compose-up", "/tmp/../a", ""}, {"compose-up", "/tmp/a", "abcdef123456"}, {"container-start", "", "$(reboot)"}, {"container-remove", "/tmp/a", "abcdef123456"},
	} {
		if _, _, err := Build(input.action, input.path, input.cid); err == nil {
			t.Fatal("unsafe target accepted")
		}
	}
	for _, spec := range Catalog() {
		if strings.HasPrefix(spec.ID, "ansible-environment-") || spec.ID == "github-runner" {
			command, hash, err := Build(spec.ID, "", "")
			if err != nil || len(hash) != 64 || strings.Contains(command, "docker.sock") {
				t.Fatal("unbound environment action", spec.ID, err)
			}
			if _, _, err := Build(spec.ID, "/tmp/override", ""); err == nil {
				t.Fatal("caller environment path accepted")
			}
			continue
		}
		p, cid := "", "abcdef123456"
		if strings.HasPrefix(spec.ID, "compose-") {
			p, cid = "/tmp/compose '$(printf unsafe)'/app.yml", ""
		}
		command, hash, err := Build(spec.ID, p, cid)
		if err != nil || len(hash) != 64 || !strings.Contains(command, "--host unix:///var/run/docker.sock") {
			t.Fatal("unbound action", spec.ID, err)
		}
		if strings.Contains(command, "down -v") || strings.Contains(command, "rm -f") {
			t.Fatal("destructive flags slipped into operation")
		}
	}
}
func TestFailedComposeDirectoryCannotInvokeDocker(t *testing.T) {
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\ntouch \"$OPERATION_FIXTURE_MARKER\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	command, _, err := Build("compose-up", filepath.Join(dir, "missing", "app.yml"), "")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin", "OPERATION_FIXTURE_MARKER="+called)
	if cmd.Run() == nil {
		t.Fatal("missing directory accepted")
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatal("Docker ran after directory selection failed")
	}
}
