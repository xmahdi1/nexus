package githubactions

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
)

func TestCancellationDeduplicationAndAttemptChecks(t *testing.T) {
	for _, scenario := range []string{"accepted", "lost-ack", "changed-attempt"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, input, _ := serviceFixture(t)
			connection, err := s.Create(context.Background(), a, "build", input)
			if err != nil {
				t.Fatal(err)
			}
			grant := authorization.Grant{ID: "cancel", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "github-actions-controller", ScopeType: "server", ScopeID: "build", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
			if err := s.DB.Create(&grant).Error; err != nil {
				t.Fatal(err)
			}
			original := s.Client.transport
			writes := 0
			s.Client.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/runs/99") {
					attempt := "1"
					if scenario == "changed-attempt" {
						attempt = "2"
					}
					return response(200, `{"id":99,"workflow_id":7,"run_attempt":`+attempt+`,"status":"in_progress","head_sha":"`+strings.Repeat("a", 40)+`","repository":{"id":123}}`), nil
				}
				if strings.HasSuffix(r.URL.Path, "/runs/99/cancel") {
					writes++
					if scenario == "lost-ack" {
						return nil, errors.New("private failure")
					}
					return response(202, ""), nil
				}
				return original.RoundTrip(r)
			})
			id := strings.Repeat("c", 32)
			row, err := s.Cancel(context.Background(), a, "build", connection.ID, id, 99, 1)
			want := "requested"
			count := 1
			if scenario == "lost-ack" {
				want = "unknown"
			}
			if scenario == "changed-attempt" {
				want = "not_submitted"
				count = 0
			}
			if row.State != want || writes != count {
				t.Fatal("incorrect cancellation state", row.State, err, writes)
			}
			if scenario == "lost-ack" && !errors.Is(err, ErrUnknown) {
				t.Fatal("lost ACK invented result", err)
			}
			same, err := s.Cancel(context.Background(), a, "build", connection.ID, id, 99, 1)
			if err != nil || same.State != want || writes != count {
				t.Fatal("cancellation replayed", err, writes)
			}
			if _, err := s.Cancel(context.Background(), a, "build", connection.ID, id, 99, 2); !errors.Is(err, ErrConflict) {
				t.Fatal("changed request accepted")
			}
			history, err := s.Cancellations(a, "build")
			if err != nil || len(history) != 1 || history[0].State != want || writes != count {
				t.Fatal("history changed outcome", err)
			}
			if err := s.DB.Delete(&grant).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := s.Cancel(context.Background(), a, "build", connection.ID, strings.Repeat("d", 32), 99, 1); !errors.Is(err, ErrDenied) || writes != count {
				t.Fatal("revocation ignored", err)
			}
		})
	}
}
func TestSensitiveReadNeedsExplicitGrantAndDiscardsRevokedResponse(t *testing.T) {
	s, a, input, _ := serviceFixture(t)
	connection, err := s.Create(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Content(context.Background(), a, "build", connection.ID, 99, 101, false); !errors.Is(err, ErrDenied) {
		t.Fatal("implicit log authority", err)
	}
	grant := authorization.Grant{ID: "logs", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "github-actions-logs", ScopeType: "server", ScopeID: "build", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	if err := s.DB.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	original := s.Client.transport
	s.Client.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/jobs/101") {
			return response(200, `{"id":101,"run_id":99}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/jobs/101/logs") {
			out := response(302, "")
			out.Header.Set("Location", "https://fixture.blob.core.windows.net/log?sig=fixture")
			return out, nil
		}
		return original.RoundTrip(r)
	})
	s.Client.downloadTransport = roundTrip(func(*http.Request) (*http.Response, error) {
		if err := s.DB.Delete(&grant).Error; err != nil {
			t.Fatal(err)
		}
		return response(200, "private fixture log"), nil
	})
	data, err := s.Content(context.Background(), a, "build", connection.ID, 99, 101, false)
	if !errors.Is(err, ErrDenied) || len(data) != 0 {
		t.Fatal("revoked plaintext returned", err)
	}
}
