package githubrunner

import (
	"strings"
	"testing"
)

func TestSetupRejectsBroadTokensAndUntrustedURLs(t *testing.T) {
	base := Setup{Profile: Profile{URL: "https://github.com/example/repository", Name: "build", Labels: []string{"trusted"}, LifetimeSeconds: 900}, RequestID: strings.Repeat("a", 32), RegistrationToken: strings.Repeat("T", 26)}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"https://evil.example/repo", "https://user:pass@github.com/example/repo", "https://github.com/example/repo?token=bad", "https://github.com/example/../repo", "http://github.com/example/repo"} {
		s := base
		s.URL = value
		if s.Validate() == nil {
			t.Fatal("untrusted scope", value)
		}
	}
	for _, token := range []string{"ghp_" + strings.Repeat("a", 30), "github_pat_" + strings.Repeat("a", 30), "ghs_" + strings.Repeat("a", 30), "token\nvalue", "short"} {
		s := base
		s.RegistrationToken = token
		if s.Validate() == nil {
			t.Fatal("broad or invalid token admitted")
		}
	}
	if strings.Contains(base.PublicJSON(), base.RegistrationToken) || strings.Contains(base.PublicJSON(), "registrationToken") {
		t.Fatal("credential entered saved profile")
	}
	if len(Command()) > 16384 || strings.Contains(Command(), base.RegistrationToken) {
		t.Fatal("invalid command bundle")
	}
	org := base
	org.URL = "https://github.com/example"
	if org.Validate() == nil {
		t.Fatal("organization without explicit runner group")
	}
	org.Group = "Restricted builds"
	if org.Validate() != nil {
		t.Fatal("valid group rejected")
	}
}
