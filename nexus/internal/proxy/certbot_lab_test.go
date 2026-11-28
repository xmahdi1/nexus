package proxy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/config"
	"github.com/xmahdi1/nexus/internal/models"
)

// Real Certbot/plugin/ACME/DNS inside owned disposable containers. The provider
// HTTP API is a strict local fake; no Cloudflare account behavior is certified.
func TestDisposableCertbotAdapter(t *testing.T) {
	target := os.Getenv("NEXUS_CERTBOT_LAB_TARGET")
	if target == "" {
		t.Skip("run through scripts/certbot_lab.py")
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(target) || len(os.Getenv("NEXUS_CERTBOT_LAB_NONCE")) != 32 {
		t.Fatal("invalid disposable target identity")
	}
	tokensData, err := os.ReadFile(os.Getenv("NEXUS_CERTBOT_LAB_TOKENS"))
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	if err := json.Unmarshal(tokensData, &tokens); err != nil {
		t.Fatal(err)
	}
	credentials := map[string]string{}
	for token, scope := range tokens {
		credentials[scope] = token
	}
	scrub := func(value string) string {
		for token := range tokens {
			value = strings.ReplaceAll(value, token, "[redacted]")
		}
		return value
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	raw := func(command, input string) (string, error) {
		for token := range tokens {
			if strings.Contains(command, token) {
				t.Fatal("credential in command")
			}
		}
		call, stop := context.WithTimeout(ctx, 60*time.Second)
		defer stop()
		process := exec.CommandContext(call, "docker", "--host", "unix:///var/run/docker.sock", "exec", "-i", target, "sh", "-c", command)
		process.Stdin = strings.NewReader(input)
		output, err := process.CombinedOutput()
		return strings.TrimSpace(scrub(string(output))), err
	}
	marker, err := raw("cat /fixture/nonce", "")
	if err != nil || marker != os.Getenv("NEXUS_CERTBOT_LAB_NONCE") {
		t.Fatal("target marker mismatch")
	}
	policy, err := acmeCommandPolicy(config.ACMEConfig{DirectoryURL: "https://pebble:14000/dir", CAFile: "/fixture/ca.pem"})
	if err != nil {
		t.Fatal(err)
	}
	send := func(command, input string) (string, error) { return raw(policy(command), input) }
	run := func(command string) (string, error) {
		if strings.Contains(command, "--dns-cloudflare-credentials") {
			path := regexp.MustCompile(`'/tmp/nexus-cf\.[A-Za-z0-9]{10}'`).FindString(command)
			if path == "" {
				return "", fmt.Errorf("missing private fixture credential path")
			}
			mode, err := raw("stat -c '%a' -- "+path, "")
			if err != nil || mode != "600" {
				return "", fmt.Errorf("DNS credentials were not private")
			}
		}
		return send(command, "")
	}
	type record struct{ ID, Name, Content string }
	type event struct{ Operation, Reason, ID string }
	type state struct {
		Records []record
		Events  []event
	}
	management := func(t testing.TB, mode string, names ...string) state {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"mode": mode, "sentinels": names})
		code := `import json,sys,urllib.request; data=sys.stdin.buffer.read(); urllib.request.urlopen(urllib.request.Request('http://provider:8056/__fixture/config',data=data,headers={'Content-Type':'application/json'})).read(); print(urllib.request.urlopen('http://provider:8056/__fixture/state').read().decode())`
		output, err := raw("python3 -c "+shellQuote(code), string(body))
		if err != nil {
			t.Fatal("fixture configuration", output, err)
		}
		var response struct{ Result state }
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			t.Fatal(err, output)
		}
		return response.Result
	}
	assertClean := func(t testing.TB, mode, host string) {
		t.Helper()
		snapshot := management(t, mode)
		sentinel := false
		for _, row := range snapshot.Records {
			if row.Name == host && strings.HasPrefix(row.ID, "sentinel-") {
				sentinel = true
			}
			if !strings.HasPrefix(row.ID, "sentinel-") {
				t.Fatal("challenge record leaked", row.Name)
			}
		}
		for _, event := range snapshot.Events {
			if event.Operation == "delete-denied" && strings.HasPrefix(event.ID, "sentinel-") {
				t.Fatal("attempted to delete unrelated TXT record")
			}
		}
		if !sentinel {
			t.Fatal("same-name unrelated TXT lost")
		}
		output, err := run(`find /tmp -maxdepth 1 -name 'nexus-cf.*' -print`)
		if err != nil || output != "" {
			t.Fatal("private credential file leaked", output, err)
		}
	}
	certificate := func(t testing.TB, domain string) *x509.Certificate {
		t.Helper()
		output, err := run("cat " + shellQuote("/etc/letsencrypt/live/"+domain+"/cert.pem"))
		if err != nil {
			t.Fatal(output, err)
		}
		block, _ := pem.Decode([]byte(output))
		if block == nil {
			t.Fatal("missing certificate")
		}
		result, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	t.Run("issue-and-install", func(t *testing.T) {
		rule := models.ProxyRule{ID: "certbot-issue", Domain: "issue.nexus.test", Target: "127.0.0.1:9999", ProxyType: "nginx"}
		management(t, "normal", "_acme-challenge."+rule.Domain)
		if err := createNginxRule(run, rule.ID, rule.Domain, rule.Target, false); err != nil {
			t.Fatal(err)
		}
		output, err := enableWildcardSSL(run, send, rule, "fixture@example.test", credentials["edit"], run)
		if err != nil {
			t.Fatal("issuance failed", output, err)
		}
		cert := certificate(t, rule.Domain)
		for _, host := range []string{rule.Domain, "tenant." + rule.Domain} {
			if err := cert.VerifyHostname(host); err != nil {
				t.Fatal(err)
			}
		}
		verify := fmt.Sprintf(`import socket,ssl,urllib.request; root=urllib.request.urlopen('https://pebble:15000/roots/0',context=ssl.create_default_context(cafile='/fixture/ca.pem')).read().decode(); context=ssl.create_default_context(cadata=root); connection=context.wrap_socket(socket.create_connection(('127.0.0.1',443)),server_hostname=%s); connection.close()`, "'"+rule.Domain+"'")
		if output, err := run("python3 -c " + shellQuote(verify)); err != nil {
			t.Fatal("served certificate did not verify", output, err)
		}
		assertClean(t, "normal", "_acme-challenge."+rule.Domain)
		// The adapter removes the credential file; plain unattended renew must fail.
		if output, err := run("certbot renew --cert-name " + shellQuote(rule.Domain) + " --force-renewal --no-random-sleep-on-renew --non-interactive 2>&1"); err == nil || !strings.Contains(output, "File not found: /tmp/nexus-cf.") {
			t.Fatal("renewal did not fail for missing credentials", output, err)
		}
		assertClean(t, "normal", "_acme-challenge."+rule.Domain)
		output, err = enableWildcardSSLWithRenewal(run, send, rule, "fixture@example.test", credentials["edit"], true, run)
		if err != nil {
			t.Fatal("manual renewal with fresh credentials failed", output, err)
		}
		renewed := certificate(t, rule.Domain)
		if renewed.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			t.Fatal("renewal did not replace certificate")
		}
		if strings.Join(renewed.DNSNames, ",") != strings.Join(cert.DNSNames, ",") {
			t.Fatal("renewal changed certificate domain coverage")
		}
		if output, err := run("python3 -c " + shellQuote(verify)); err != nil {
			t.Fatal("renewed TLS listener did not verify", output, err)
		}
		assertClean(t, "normal", "_acme-challenge."+rule.Domain)
	})
	for _, scenario := range []struct{ name, scope, mode string }{
		{"invalid-token", "invalid", "normal"}, {"read-only-token", "read", "normal"}, {"wrong-zone", "other-zone", "normal"}, {"propagation-failure", "edit", "propagation"}, {"dns-servfail", "edit", "servfail"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			rule := models.ProxyRule{Domain: scenario.name + ".nexus.test"}
			host := "_acme-challenge." + rule.Domain
			before := management(t, scenario.mode, host)
			token := credentials[scenario.scope]
			if token == "" {
				token = "invalid-disposable-token"
			}
			output, err := enableWildcardSSL(run, send, rule, "fixture@example.test", token, run)
			if err == nil {
				t.Fatal("failed scenario reported success", output)
			}
			after := management(t, scenario.mode)
			reason := ""
			switch scenario.scope {
			case "invalid":
				reason = "invalid-token"
			case "read":
				reason = "scope"
			}
			if reason != "" {
				found := false
				for _, event := range after.Events[len(before.Events):] {
					if event.Operation == "denied" && event.Reason == reason {
						found = true
					}
				}
				if !found {
					t.Fatal("scenario did not reach expected provider denial")
				}
			}
			if scenario.mode != "normal" {
				created := 0
				for _, event := range after.Events[len(before.Events):] {
					if event.Operation == "create" {
						created++
					}
				}
				if created == 0 {
					t.Fatal("DNS failure did not reach challenge creation")
				}
			}
			assertClean(t, "normal", host)
		})
	}
	t.Run("install-failure-cleans-up-without-retry", func(t *testing.T) {
		rule := models.ProxyRule{ID: "certbot-install-failure", Domain: "install-failure.nexus.test", Target: "127.0.0.1:9999", ProxyType: "nginx"}
		host := "_acme-challenge." + rule.Domain
		management(t, "normal", host)
		if err := createNginxRule(run, rule.ID, rule.Domain, rule.Target, false); err != nil {
			t.Fatal(err)
		}
		if output, err := run("printf 'invalid_fixture_directive;\\n' > /etc/nginx/conf.d/fixture-invalid.conf"); err != nil {
			t.Fatal(output, err)
		}
		defer run("rm -f /etc/nginx/conf.d/fixture-invalid.conf")
		installs := 0
		counted := func(command string) (string, error) {
			if strings.Contains(command, "certbot install") {
				installs++
			}
			return run(command)
		}
		output, err := enableWildcardSSL(counted, send, rule, "fixture@example.test", credentials["edit"], run)
		if err == nil || installs != 1 {
			t.Fatal("installer failure suppressed or retried", installs, output, err)
		}
		certificate(t, rule.Domain) // Issuance can succeed before installation fails.
		assertClean(t, "normal", host)
	})
	t.Run("interrupted-certbot-cleans-up", func(t *testing.T) {
		rule := models.ProxyRule{Domain: "interrupted.nexus.test"}
		host := "_acme-challenge." + rule.Domain
		management(t, "propagation", host)
		if output, err := run("printf 'dns-cloudflare-propagation-seconds = 5\\n' > /etc/letsencrypt/cli.ini"); err != nil {
			t.Fatal(output, err)
		}
		interrupt := `import os,signal; from pathlib import Path; count=0
for file in Path('/proc').glob('[0-9]*/cmdline'):
 try:
  args=file.read_bytes().split(b'\0')
  if b'/usr/bin/certbot' in args and b'interrupted.nexus.test' in args:
   os.kill(int(file.parent.name),signal.SIGINT); count+=1
 except (FileNotFoundError,ProcessLookupError): pass
print(count)`
		defer run("python3 -c " + shellQuote(interrupt))
		defer run("printf 'dns-cloudflare-propagation-seconds = 0\\n' > /etc/letsencrypt/cli.ini")
		type result struct {
			output string
			err    error
		}
		done := make(chan result, 1)
		go func() {
			output, err := enableWildcardSSL(run, send, rule, "fixture@example.test", credentials["edit"], run)
			done <- result{output, err}
		}()
		ready := false
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			snapshot := management(t, "propagation")
			count := 0
			for _, row := range snapshot.Records {
				if row.Name == host && !strings.HasPrefix(row.ID, "sentinel-") {
					count++
				}
			}
			if count == 2 {
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			t.Fatal("Certbot did not publish both DNS challenges before interruption")
		}
		if output, err := run("python3 -c " + shellQuote(interrupt)); err != nil || output != "1" {
			t.Fatal("failed to interrupt owned Certbot process", output, err)
		}
		select {
		case result := <-done:
			if result.err == nil {
				t.Fatal("interrupted issuance reported success", result.output)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("Certbot did not exit after graceful interruption")
		}
		assertClean(t, "normal", host)
	})
	t.Run("reported-cleanup-failure", func(t *testing.T) {
		rule := models.ProxyRule{Domain: "cleanup-failure.nexus.test"}
		host := "_acme-challenge." + rule.Domain
		management(t, "delete-denied", host)
		output, err := enableWildcardSSL(run, send, rule, "fixture@example.test", credentials["edit"], run)
		if err != nil {
			t.Fatal("issuance failed before cleanup test", output, err)
		}
		if !dnsCleanupReportedFailure(output) {
			t.Fatal("plugin's cleanup failure was not detected", output)
		}
		snapshot := management(t, "normal")
		pending := 0
		for _, row := range snapshot.Records {
			if !strings.HasPrefix(row.ID, "sentinel-") {
				pending++
			}
		}
		if pending == 0 {
			t.Fatal("cleanup failure scenario left no records to detect")
		}
		// Remove only the owned challenge IDs using the fake API after access is restored.
		code := `import json,urllib.request; tokens=json.load(open('/fixture/tokens.json')); token=next(key for key,value in tokens.items() if value=='edit'); state=json.load(urllib.request.urlopen('http://provider:8056/__fixture/state'))['result']; [urllib.request.urlopen(urllib.request.Request('http://provider:8056/client/v4/zones/zone-fixture/dns_records/'+row['id'],headers={'Authorization':'Bearer '+token},method='DELETE')).read() for row in state['records'] if not row['id'].startswith('sentinel-') and row['name']=='_acme-challenge.cleanup-failure.nexus.test']`
		if output, err := run("python3 -c " + shellQuote(code)); err != nil {
			t.Fatal("fixture recovery failed", output, err)
		}
		assertClean(t, "normal", host)
	})
}
