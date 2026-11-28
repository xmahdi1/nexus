package githubactions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSignedDownloadDestinationsAndIPs(t *testing.T) {
	for _, value := range []string{"http://logs.blob.core.windows.net/a", "https://evil.invalid/a", "https://logs.blob.core.windows.net.attacker.invalid/a", "https://user@logs.blob.core.windows.net/a", "https://logs.blob.core.windows.net:443/a", "https://logs.blob.core.windows.net/a#fragment", "https://127.0.0.1/a", "https://bad.account.blob.core.windows.net/a", "https://logs.blob.core.windows.net./a"} {
		if _, err := signedDownloadURL(value); err == nil {
			t.Fatal("unsafe destination accepted", value)
		}
	}
	for _, value := range []string{"https://fixture.blob.core.windows.net/log?sig=fixture", "https://results-receiver.actions.githubusercontent.com/fixture"} {
		if _, err := signedDownloadURL(value); err != nil {
			t.Fatal("supported destination denied", err)
		}
	}
	for _, value := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.0.2.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "fec0::1", "2001:db8::1", "64:ff9b::7f00:1", "2002:7f00:1::1"} {
		if publicDownloadIP(netip.MustParseAddr(value)) {
			t.Fatal("nonpublic address accepted", value)
		}
	}
	if !publicDownloadIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address denied")
	}
}
func TestLogDownloadStripsCredentialsAndRejectsCrossRunOrOversize(t *testing.T) {
	c, _, repo, _ := fixture(t)
	token := &Token{value: "ghs_fixture_token_only", ExpiresAt: c.now().Add(time.Hour), repository: repo}
	for _, scenario := range []string{"success", "wrong-run", "wrong-host", "redirect", "oversize", "invalid-utf8"} {
		t.Run(scenario, func(t *testing.T) {
			apiCalls, storageCalls := 0, 0
			c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				apiCalls++
				if strings.HasSuffix(r.URL.Path, "/jobs/101") {
					id := 99
					if scenario == "wrong-run" {
						id = 100
					}
					return response(200, fmt.Sprintf(`{"id":101,"run_id":%d}`, id)), nil
				}
				if !strings.HasSuffix(r.URL.Path, "/jobs/101/logs") {
					t.Fatal("wrong log endpoint")
				}
				out := response(302, "")
				target := "https://fixture.blob.core.windows.net/log?sig=fixture"
				if scenario == "wrong-host" {
					target = "https://localhost/log"
				}
				out.Header.Set("Location", target)
				return out, nil
			})
			c.downloadTransport = roundTrip(func(r *http.Request) (*http.Response, error) {
				storageCalls++
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-GitHub-Api-Version") != "" {
					t.Fatal("credentials crossed download boundary")
				}
				switch scenario {
				case "redirect":
					out := response(302, "")
					out.Header.Set("Location", "https://attacker.invalid")
					return out, nil
				case "oversize":
					return response(200, strings.Repeat("x", MaxLogBytes+1)), nil
				case "invalid-utf8":
					return response(200, string([]byte{255})), nil
				}
				return response(200, "<script>untrusted log</script>\n"), nil
			})
			data, err := c.JobLog(context.Background(), repo, token, 99, 101)
			if scenario == "success" {
				if err != nil || !strings.Contains(string(data), "untrusted log") {
					t.Fatal("log unavailable", err)
				}
			} else if err == nil || len(data) != 0 {
				t.Fatal("invalid log accepted", scenario)
			}
			if scenario == "wrong-run" {
				if apiCalls != 1 || storageCalls != 0 {
					t.Fatal("cross-run download contacted storage")
				}
			} else if scenario == "wrong-host" {
				if storageCalls != 0 {
					t.Fatal("unsafe host contacted")
				}
			} else if storageCalls != 1 {
				t.Fatal("storage redirect/retry followed", storageCalls)
			}
		})
	}
}
func TestArtifactDownloadBindsRepositoryAndRun(t *testing.T) {
	c, _, repo, _ := fixture(t)
	token := &Token{value: "fixture", ExpiresAt: c.now().Add(time.Hour), repository: repo}
	for _, scenario := range []string{"success", "wrong-repo", "wrong-run", "expired", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if strings.HasSuffix(r.URL.Path, "/zip") {
					out := response(302, "")
					out.Header.Set("Location", "https://fixture.blob.core.windows.net/zip?sig=fixture")
					return out, nil
				}
				repoID, run, size := 123, 99, 4
				expired := false
				switch scenario {
				case "wrong-repo":
					repoID = 456
				case "wrong-run":
					run = 100
				case "expired":
					expired = true
				case "oversize":
					size = MaxArtifactBytes + 1
				}
				return response(200, fmt.Sprintf(`{"id":5,"name":"build","size_in_bytes":%d,"expired":%t,"workflow_run":{"id":%d,"repository_id":%d}}`, size, expired, run, repoID)), nil
			})
			c.downloadTransport = roundTrip(func(*http.Request) (*http.Response, error) { return response(200, "PK\x05\x06"), nil })
			data, err := c.ArtifactZIP(context.Background(), repo, token, 99, 5)
			if scenario == "success" {
				if err != nil || len(data) != 4 || calls != 2 {
					t.Fatal("artifact unavailable", err)
				}
			} else if err == nil || len(data) != 0 || calls != 1 {
				t.Fatal("unsafe artifact fetched", scenario, err, calls)
			}
		})
	}
}
func TestCancelOnceNeverRetriesOrClaimsTermination(t *testing.T) {
	c, _, repo, _ := fixture(t)
	token := &Token{value: "fixture", ExpiresAt: c.now().Add(time.Hour), repository: repo, write: true}
	for _, code := range []int{202, 409, 500, 302} {
		calls := 0
		c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/runs/99/cancel") {
				t.Fatal("wrong cancellation endpoint")
			}
			return response(code, "private provider error"), nil
		})
		err := c.CancelOnce(context.Background(), repo, token, 99, func() bool { return true })
		if calls != 1 || (code == 202 && err != nil) || (code == 409 && !errors.Is(err, ErrConflict)) || (code != 202 && code != 409 && !errors.Is(err, ErrUnknown)) {
			t.Fatal("invalid cancel outcome", code, err, calls)
		}
	}
}
