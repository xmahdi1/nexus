package templates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentDoesNotRetryFailedMutationOrEscapeDirectory(t *testing.T) {
	directory := t.TempDir()
	docker := `#!/bin/sh
if [ "$*" = 'compose version' ]; then exit 0; fi
printf 'v2-mutation\n' >> "$FIXTURE_CALLS"
exit 42
`
	fallback := `#!/bin/sh
printf 'unexpected-v1\n' >> "$FIXTURE_CALLS"
exit 0
`
	for name, script := range map[string]string{"docker": docker, "docker-compose": fallback} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(directory, "calls")
	run := func(target string) {
		t.Helper()
		cmd := exec.Command("sh", "-c", deploymentCommand(target, "down"))
		cmd.Env = []string{"PATH=" + directory + ":/usr/bin:/bin", "FIXTURE_CALLS=" + calls}
		if err := cmd.Run(); err == nil {
			t.Fatal("failed mutation reported success")
		}
	}
	run(directory)
	content, err := os.ReadFile(calls)
	if err != nil || strings.TrimSpace(string(content)) != "v2-mutation" {
		t.Fatalf("mutation was retried: %q %v", content, err)
	}
	run(filepath.Join(directory, "missing"))
	after, err := os.ReadFile(calls)
	if err != nil || string(after) != string(content) {
		t.Fatal("mutation escaped failed directory change")
	}
}
