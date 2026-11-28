package proxy

import (
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/config"
)

func TestCertbotDirectoryPolicy(t *testing.T) {
	settings := config.ACMEConfig{DirectoryURL: "https://ca.nexus.test:14000/dir", CAFile: "/private/ca bundle.pem"}
	policy, err := acmeCommandPolicy(settings)
	if err != nil {
		t.Fatal(err)
	}
	command := `PATH="$PATH:/usr/bin" certbot install --nginx || certbot install --nginx`
	result := policy(command)
	if strings.Count(result, "--server 'https://ca.nexus.test:14000/dir'") != 2 || strings.Count(result, "env REQUESTS_CA_BUNDLE='/private/ca bundle.pem'") != 2 {
		t.Fatal("CA policy missing from fallback", result)
	}
	unchanged := "apt-get install python3-certbot-dns-cloudflare"
	if policy(unchanged) != unchanged {
		t.Fatal("unrelated command changed")
	}
	fallback, err := acmeCommandPolicy(config.ACMEConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fallback("certbot --nginx"), config.DefaultACMEDirectory) {
		t.Fatal("default directory not explicit")
	}
	if _, err := acmeCommandPolicy(config.ACMEConfig{DirectoryURL: "http://ca.test/dir"}); err == nil {
		t.Fatal("insecure directory accepted")
	}
}
