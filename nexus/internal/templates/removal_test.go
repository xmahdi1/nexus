package templates

import (
	"errors"
	"strings"
	"testing"
)

func TestAppRemovalPreservesVolumesRecipesAndRefusesUnsafePaths(t *testing.T) {
	for _, directory := range []string{"/", "/opt/nexus-apps/", "/opt/nexus-apps/../other", "/opt/nexus-apps/$(bad)", "/tmp/other"} {
		called := false
		if _, err := stopDeployment(func(string) (string, error) { called = true; return "", nil }, directory); err == nil || called {
			t.Fatal("unsafe app directory executed", directory)
		}
	}
	if _, err := stopDeployment(func(command string) (string, error) {
		if strings.Contains(command, "down -v") || strings.Contains(command, "rm ") || !strings.Contains(command, " && {") {
			t.Fatal("destructive or unbound shutdown", command)
		}
		return "", errors.New("fixture shutdown failure")
	}, "/opt/nexus-apps/database"); err == nil {
		t.Fatal("failed shutdown ignored")
	}
	if appNameRe.MatchString(sanitizeName("💥")) {
		t.Fatal("empty sanitized name admitted")
	}
}
