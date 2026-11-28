package proxy

import (
	"errors"
	"github.com/xmahdi1/nexus/internal/models"
	"strings"
	"testing"
)

func TestProxyRemovalPropagatesWriteAndReloadFailures(t *testing.T) {
	for _, remove := range []func(func(string) (string, error)) error{
		func(run func(string) (string, error)) error { return deleteNginxRule(run, "fixture", "example.test") },
		func(run func(string) (string, error)) error { return deleteCaddyRule(run, "example.test") },
	} {
		for _, failAt := range []int{1} {
			calls := 0
			err := remove(func(command string) (string, error) {
				calls++
				if strings.Contains(command, "|| true") {
					t.Fatal("failure suppressed")
				}
				if calls == failAt {
					return "", errors.New("fixture failure")
				}
				return "", nil
			})
			if err == nil {
				t.Fatal("failure reported as success")
			}
		}
	}
}
func TestWildcardCredentialsUseStdinPrivateTempAndCleanup(t *testing.T) {
	const secret = "fixture-api-token-never-in-command"
	commands := []string{}
	sent := false
	run := func(command string) (string, error) {
		commands = append(commands, command)
		if strings.Contains(command, secret) {
			t.Fatal("credential in command")
		}
		if strings.Contains(command, "mktemp") {
			return "/tmp/nexus-cf.a1b2c3d4e5", nil
		}
		if strings.Contains(command, "certbot certonly") {
			return "fixture cert failure", errors.New("fixture")
		}
		return "", nil
	}
	send := func(command, input string) (string, error) {
		if strings.Contains(command, secret) || !strings.Contains(input, secret) {
			t.Fatal("unsafe credential transport")
		}
		if !strings.Contains(command, "chmod 600") {
			t.Fatal("missing private file mode")
		}
		sent = true
		return "", nil
	}
	if _, err := enableWildcardSSL(run, send, models.ProxyRule{ID: "fixture", Domain: "example.test"}, "owner@example.test", secret); err == nil {
		t.Fatal("cert failure suppressed")
	}
	if !sent || !strings.HasPrefix(commands[len(commands)-1], "rm -f -- ") {
		t.Fatal("credential not cleaned up")
	}
	if _, err := enableWildcardSSL(run, send, models.ProxyRule{}, "owner@example.test", "token\ninjected=config"); err == nil {
		t.Fatal("credential config injection accepted")
	}
}

func TestWildcardRenewalPreservesLineageAndRedactsReflectedCredentials(t *testing.T) {
	const token = "disposable-reflection-fixture"
	commands := []string{}
	run := func(command string) (string, error) {
		commands = append(commands, command)
		if strings.Contains(command, token) {
			t.Fatal("token in argv")
		}
		if strings.Contains(command, "mktemp") {
			return "/tmp/nexus-cf.a1b2c3d4e5", nil
		}
		if strings.Contains(command, "certbot renew") {
			return "provider reflected " + token, errors.New("failed " + token)
		}
		return "", nil
	}
	output, err := enableWildcardSSLWithRenewal(run, func(command, input string) (string, error) { return "", nil }, models.ProxyRule{Domain: "example.test"}, "owner@example.test", token, true, run)
	if err == nil || strings.Contains(output, token) || strings.Contains(err.Error(), token) {
		t.Fatal("reflection not redacted")
	}
	renewal := ""
	for _, command := range commands {
		if strings.Contains(command, "certbot renew") {
			renewal = command
		}
	}
	if !strings.Contains(renewal, "--cert-name 'example.test'") || strings.Contains(renewal, " -d ") {
		t.Fatal("renewal replaced domain coverage", renewal)
	}
	if !strings.HasPrefix(commands[len(commands)-1], "rm -f -- ") {
		t.Fatal("credential cleanup skipped after renewal failure")
	}
}

func TestDNSCleanupReportedFailure(t *testing.T) {
	for _, output := range []string{"Encountered CloudFlareAPIError deleting TXT record: fixture", "Error during cleanup", "cleanup failed"} {
		if !dnsCleanupReportedFailure(output) {
			t.Fatal("reported cleanup failure hidden")
		}
	}
	if dnsCleanupReportedFailure("Successfully received certificate. Successfully deleted TXT record.") {
		t.Fatal("success misclassified")
	}
}
