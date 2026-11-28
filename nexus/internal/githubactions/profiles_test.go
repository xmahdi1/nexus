package githubactions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOperationTokensUseSeparatePermissions(t *testing.T) {
	for _, scope := range []string{"runners", "workflows"} {
		t.Run(scope, func(t *testing.T) {
			c, app, repo, _ := fixture(t)
			calls := 0
			c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					var input struct {
						Permissions map[string]string `json:"permissions"`
					}
					if json.NewDecoder(r.Body).Decode(&input) != nil {
						t.Fatal("invalid token request")
					}
					if scope == "runners" {
						if input.Permissions["administration"] != "write" || len(input.Permissions) != 2 {
							t.Fatal("runner permissions broadened")
						}
					} else if input.Permissions["contents"] != "write" || input.Permissions["workflows"] != "write" || input.Permissions["pull_requests"] != "write" || len(input.Permissions) != 4 {
						t.Fatal("workflow permissions changed")
					}
					encoded, _ := json.Marshal(map[string]any{"token": "ghs_fixture_scoped_token", "expires_at": c.now().Add(time.Hour), "permissions": input.Permissions, "repositories": []map[string]int{{"id": 123}}})
					return response(201, string(encoded)), nil
				}
				return response(200, `{"id":123,"full_name":"fixture/repository"}`), nil
			})
			var token *Token
			var err error
			if scope == "runners" {
				token, err = c.RunnerToken(context.Background(), app, repo, true)
			} else {
				token, err = c.WorkflowToken(context.Background(), app, repo, true)
			}
			if err != nil || calls != 2 {
				t.Fatal("scoped token failed", err)
			}
			defer token.Clear()
			if _, err := c.DispatchOnce(context.Background(), repo, token, Dispatch{WorkflowID: 7, Ref: "main"}, func() bool { return true }); !errors.Is(err, ErrDenied) {
				t.Fatal("non-Actions token dispatched")
			}
			if calls != 2 {
				t.Fatal("cross-purpose denial contacted provider")
			}
		})
	}
}
func TestWorkflowReadUsesCommitAndDoesNotForwardProviderURLs(t *testing.T) {
	c, _, repo, _ := fixture(t)
	token := &Token{value: "fixture", ExpiresAt: c.now().Add(time.Hour), repository: repo, scope: "workflows"}
	sha := strings.Repeat("a", 40)
	blob := strings.Repeat("b", 40)
	content := "name: Fixture\njobs: {}\n"
	calls := 0
	c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha+`"}}`), nil
		}
		if r.URL.Query().Get("ref") != sha {
			t.Fatal("read did not use commit SHA")
		}
		data, _ := json.Marshal(map[string]any{"path": ".github/workflows/build.yml", "type": "file", "sha": blob, "size": len(content), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content)), "download_url": "http://127.0.0.1/private"})
		return response(200, string(data)), nil
	})
	file, err := c.ReadWorkflow(context.Background(), repo, token, "main", ".github/workflows/build.yml")
	if err != nil || file.Content != content || file.BaseSHA != sha || file.BlobSHA != blob || calls != 2 {
		t.Fatal("workflow read failed", err)
	}
	encoded, _ := json.Marshal(file)
	if strings.Contains(string(encoded), "download_url") || strings.Contains(string(encoded), "127.0.0.1") {
		t.Fatal("provider URL forwarded")
	}
}
