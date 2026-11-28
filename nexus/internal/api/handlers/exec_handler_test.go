package handlers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseCredentialsAndQueriesUseStdin(t *testing.T) {
	for _, image := range []string{"postgres:16", "mysql:8", "redis:7", "mongo:6"} {
		t.Run(image, func(t *testing.T) {
			directory := t.TempDir()
			password := "fixture-password-'-$()-value"
			query := "SELECT 'fixture-query-private-value';"
			command, input, err := databaseCommand(image, strings.Repeat("a", 64), "quoted'user", password, query)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(command, password) || strings.Contains(command, query) {
				t.Fatal("private input appeared in command line")
			}
			// The fake container/client runs the actual generated shell script, verifying
			// that one input line becomes a credential and remaining bytes become query.
			scripts := map[string]string{
				"docker":    "#!/bin/sh\nshift 3\nexec \"$@\"\n",
				"psql":      "#!/bin/sh\nprintf '%s' \"$PGPASSWORD\" > \"$FIXTURE_PASSWORD\"\ncat > \"$FIXTURE_QUERY\"\n",
				"mysql":     "#!/bin/sh\nprintf '%s' \"$MYSQL_PWD\" > \"$FIXTURE_PASSWORD\"\ncat > \"$FIXTURE_QUERY\"\n",
				"redis-cli": "#!/bin/sh\nprintf '%s' \"$REDISCLI_AUTH\" > \"$FIXTURE_PASSWORD\"\ncat > \"$FIXTURE_QUERY\"\n",
				"mongosh":   "#!/bin/sh\ncat > \"$FIXTURE_QUERY\"\n",
			}
			for name, script := range scripts {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", command)
			cmd.Stdin = strings.NewReader(input)
			cmd.Env = []string{"PATH=" + directory + ":/usr/bin:/bin", "FIXTURE_PASSWORD=" + filepath.Join(directory, "password"), "FIXTURE_QUERY=" + filepath.Join(directory, "query")}
			if err := cmd.Run(); err != nil {
				t.Fatal("generated command failed", err)
			}
			if content, err := os.ReadFile(filepath.Join(directory, "query")); err != nil || string(content) != query+"\n" {
				t.Fatal("query was not preserved", err)
			}
			if !strings.Contains(image, "mongo") {
				if content, err := os.ReadFile(filepath.Join(directory, "password")); err != nil || string(content) != password {
					t.Fatal("password was not preserved", err)
				}
			}
		})
	}
	if _, _, err := databaseCommand("postgres", "bad-id", "", "", "select 1"); err == nil {
		t.Fatal("invalid container accepted")
	}
	if _, _, err := databaseCommand("postgres", strings.Repeat("a", 12), "", "line\ninjection", "select 1"); err == nil {
		t.Fatal("password line injection accepted")
	}
}
