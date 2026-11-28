package githubactions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
)

const originalWorkflow = "name: Original\non: [workflow_dispatch]\njobs: {}\n"

func editFixture() WorkflowEdit {
	return WorkflowEdit{BaseBranch: "main", BaseSHA: strings.Repeat("a", 40), BlobSHA: strings.Repeat("b", 40), Path: ".github/workflows/build.yml", Content: "name: Edited\non: [workflow_dispatch]\njobs: {}\n", Title: "Update build workflow"}
}
func jsonResponse(value any) *http.Response {
	data, _ := json.Marshal(value)
	return response(200, string(data))
}
func repositoryTransport(t *testing.T, c *Client, scenario string, writes map[string]int) http.RoundTripper {
	t.Helper()
	branch := ""
	written := false
	baseReads := 0
	return roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.github.com" {
			t.Fatal("provider escaped GitHub")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			var input struct {
				Permissions map[string]string `json:"permissions"`
				IDs         []int64           `json:"repository_ids"`
			}
			if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.IDs) != 1 || input.IDs[0] != 123 {
				t.Fatal("bad token scope")
			}
			if _, ok := input.Permissions["administration"]; ok {
				if len(input.Permissions) != 2 {
					t.Fatal("runner token inherited other permissions")
				}
			}
			out := jsonResponse(map[string]any{"token": "ghs_fixture_repository_token", "expires_at": c.now().Add(time.Hour).Format(time.RFC3339), "permissions": input.Permissions, "repositories": []map[string]int{{"id": 123}}})
			out.StatusCode = 201
			return out, nil
		case r.URL.Path == "/repos/fixture/repository":
			return response(200, `{"id":123,"full_name":"fixture/repository"}`), nil
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			name := strings.SplitN(r.URL.Path, "/git/ref/heads/", 2)[1]
			sha := strings.Repeat("a", 40)
			if name == "main" {
				baseReads++
				if scenario == "stale-base" || scenario == "base-moved-after-write" && baseReads > 1 {
					sha = strings.Repeat("d", 40)
				}
			} else if name != branch {
				t.Fatal("unreserved branch fetched", name)
			} else if written {
				sha = strings.Repeat("c", 40)
			}
			return jsonResponse(map[string]any{"ref": "refs/heads/" + name, "object": map[string]string{"type": "commit", "sha": sha}}), nil
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/contents/"):
			if r.URL.Query().Get("ref") != strings.Repeat("a", 40) && scenario != "stale-base" {
				t.Fatal("file read used mutable ref")
			}
			return jsonResponse(map[string]any{"path": editFixture().Path, "type": "file", "sha": strings.Repeat("b", 40), "size": len(originalWorkflow), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(originalWorkflow))}), nil
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/git/refs"):
			writes["branch"]++
			var input map[string]string
			json.NewDecoder(r.Body).Decode(&input)
			branch = strings.TrimPrefix(input["ref"], "refs/heads/")
			if !editBranchPattern.MatchString(branch) || input["sha"] != strings.Repeat("a", 40) {
				t.Fatal("branch did not use reviewed base")
			}
			if scenario == "lost-branch" {
				return nil, errors.New("lost branch acknowledgement")
			}
			out := jsonResponse(map[string]any{"ref": input["ref"], "object": map[string]string{"sha": input["sha"]}})
			out.StatusCode = 201
			return out, nil
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/contents/"):
			writes["file"]++
			var input map[string]string
			json.NewDecoder(r.Body).Decode(&input)
			content, _ := base64.StdEncoding.DecodeString(input["content"])
			if string(content) != editFixture().Content || input["branch"] != branch || input["sha"] != strings.Repeat("b", 40) {
				t.Fatal("file write escaped reviewed branch/blob")
			}
			written = true
			if scenario == "lost-file" {
				return nil, errors.New("lost file acknowledgement")
			}
			parent := strings.Repeat("a", 40)
			if scenario == "unexpected-parent" {
				parent = strings.Repeat("d", 40)
			}
			return jsonResponse(map[string]any{"content": map[string]string{"path": editFixture().Path, "sha": strings.Repeat("e", 40)}, "commit": map[string]any{"sha": strings.Repeat("c", 40), "parents": []map[string]string{{"sha": parent}}}}), nil
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pulls"):
			writes["pull"]++
			var input struct {
				Head, Base string
				Draft      bool
			}
			json.NewDecoder(r.Body).Decode(&input)
			if input.Head != branch || input.Base != "main" || !input.Draft {
				t.Fatal("pull was not a reviewed draft")
			}
			if scenario == "lost-pull" {
				return nil, errors.New("lost pull acknowledgement")
			}
			baseSHA := strings.Repeat("a", 40)
			if scenario == "pull-base-moved" {
				baseSHA = strings.Repeat("d", 40)
			}
			out := jsonResponse(map[string]any{"number": 42, "draft": true, "head": map[string]any{"ref": branch, "sha": strings.Repeat("c", 40), "repo": map[string]int{"id": 123}}, "base": map[string]any{"ref": "main", "sha": baseSHA, "repo": map[string]int{"id": 123}}})
			out.StatusCode = 201
			return out, nil
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/actions/runners/9"):
			status := "offline"
			busy := false
			if scenario == "online" {
				status = "online"
			}
			if scenario == "busy" {
				busy = true
			}
			return jsonResponse(map[string]any{"id": 9, "name": "fixture-runner", "os": "linux", "status": status, "busy": busy, "labels": []any{}}), nil
		case r.Method == "DELETE" && strings.HasSuffix(r.URL.Path, "/actions/runners/9"):
			writes["delete"]++
			if scenario == "lost-delete" {
				return nil, errors.New("lost delete acknowledgement")
			}
			return response(204, ""), nil
		default:
			t.Fatal("unexpected provider request", r.Method, r.URL.Path)
			return nil, ErrUnavailable
		}
	})
}
func grantRepositoryRole(t *testing.T, s *Service, user, role string) {
	t.Helper()
	if err := s.DB.Create(&authorization.Grant{ID: role, PrincipalID: user, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "build", CreatedBy: user, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
}
func TestRunnerTokensCannotDispatchWorkflows(t *testing.T) {
	c, app, repo, _ := fixture(t)
	writes := map[string]int{}
	c.transport = repositoryTransport(t, c, "success", writes)
	token, err := c.RunnerToken(context.Background(), app, repo, true)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Clear()
	if _, err := c.DispatchOnce(context.Background(), repo, token, Dispatch{WorkflowID: 7, Ref: "main"}, func() bool { return true }); !errors.Is(err, ErrDenied) {
		t.Fatal("runner token could dispatch", err)
	}
	action := &Token{value: "fixture", ExpiresAt: c.now().Add(time.Hour), repository: repo, write: true}
	if _, err := c.Runners(context.Background(), repo, action, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("Actions token could read runners")
	}
}
func TestWorkflowChangesNeverReplayPartialProviderWrites(t *testing.T) {
	for _, scenario := range []string{"success", "lost-branch", "lost-file", "lost-pull", "stale-base", "base-moved-after-write", "unexpected-parent", "pull-base-moved"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, input, _ := serviceFixture(t)
			connection, err := s.Create(context.Background(), a, "build", input)
			if err != nil {
				t.Fatal(err)
			}
			grantRepositoryRole(t, s, a.User.ID, "github-workflow-editor")
			writes := map[string]int{}
			s.Client.transport = repositoryTransport(t, s.Client, scenario, writes)
			edit := editFixture()
			id := strings.Repeat("e", 32)
			row, err := s.PublishWorkflow(context.Background(), a, "build", connection.ID, id, edit)
			want := "unknown"
			if scenario == "success" {
				want = "applied"
			}
			if scenario == "stale-base" {
				want = "not_submitted"
			}
			if scenario == "base-moved-after-write" {
				want = "incomplete"
			}
			if row.State != want {
				t.Fatal("incorrect change outcome", row.State, err)
			}
			if scenario == "success" && (row.PullNumber != 42 || row.CommitSHA != strings.Repeat("c", 40)) {
				t.Fatal("wrong published identity")
			}
			if scenario == "stale-base" && len(writes) != 0 {
				t.Fatal("stale review changed provider")
			}
			if scenario == "lost-branch" && (writes["file"] != 0 || writes["pull"] != 0) {
				t.Fatal("continued after uncertain branch")
			}
			if (scenario == "lost-file" || scenario == "base-moved-after-write" || scenario == "unexpected-parent") && writes["pull"] != 0 {
				t.Fatal("created pull after incomplete edit")
			}
			before := fmt.Sprint(writes)
			repeated, err := s.PublishWorkflow(context.Background(), a, "build", connection.ID, id, edit)
			if err != nil || repeated.State != want || fmt.Sprint(writes) != before {
				t.Fatal("partial workflow change replayed", err)
			}
			edit.Content += "# changed\n"
			if _, err := s.PublishWorkflow(context.Background(), a, "build", connection.ID, id, edit); !errors.Is(err, ErrConflict) {
				t.Fatal("request inputs changed", err)
			}
			encoded, _ := json.Marshal(row)
			if strings.Contains(string(encoded), editFixture().Content) || strings.Contains(string(encoded), "inputEnc") || strings.Contains(string(encoded), "sourceSession") {
				t.Fatal("private workflow content exposed")
			}
		})
	}
}
func TestOnlyOfflineIdleRunnerCanBeRemovedOnce(t *testing.T) {
	for _, scenario := range []string{"success", "lost-delete", "online", "busy"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, input, _ := serviceFixture(t)
			connection, err := s.Create(context.Background(), a, "build", input)
			if err != nil {
				t.Fatal(err)
			}
			grantRepositoryRole(t, s, a.User.ID, "github-provider-runners-manager")
			writes := map[string]int{}
			s.Client.transport = repositoryTransport(t, s.Client, scenario, writes)
			request := RemoveRunner{RunnerID: 9, Name: "fixture-runner"}
			id := strings.Repeat("f", 32)
			row, err := s.RemoveProviderRunner(context.Background(), a, "build", connection.ID, id, request)
			want := "applied"
			if scenario == "lost-delete" {
				want = "unknown"
			}
			if scenario == "online" || scenario == "busy" {
				want = "not_submitted"
			}
			if row.State != want {
				t.Fatal("wrong runner removal state", row.State, err)
			}
			before := writes["delete"]
			if want == "not_submitted" && before != 0 {
				t.Fatal("active runner was removed")
			}
			if _, err := s.RemoveProviderRunner(context.Background(), a, "build", connection.ID, id, request); err != nil || writes["delete"] != before {
				t.Fatal("runner removal replayed", err)
			}
		})
	}
}

func TestProviderRunnerPageValidationAndRepositoryBinding(t *testing.T) {
	c, _, repo, _ := fixture(t)
	token := &Token{value: "fixture", ExpiresAt: c.now().Add(time.Hour), repository: repo, scope: "runners"}
	for _, scenario := range []string{"valid", "bad-label", "too-many"} {
		t.Run(scenario, func(t *testing.T) {
			c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.RawQuery != "per_page=50&page=1" {
					t.Fatal("unbounded runner page")
				}
				runner := map[string]any{"id": 9, "name": "fixture", "os": "linux", "status": "online", "busy": true, "labels": []map[string]string{{"name": "Linux", "type": "read-only"}}}
				if scenario == "bad-label" {
					runner["labels"] = []map[string]string{{"name": "bad", "type": "unknown"}}
				}
				rows := []any{runner}
				if scenario == "too-many" {
					rows = make([]any, 51)
					for i := range rows {
						rows[i] = runner
					}
				}
				return jsonResponse(map[string]any{"total_count": len(rows), "runners": rows}), nil
			})
			result, err := c.Runners(context.Background(), repo, token, 1)
			if scenario == "valid" {
				if err != nil || len(result.Runners) != 1 {
					t.Fatal("runner metadata missing", err)
				}
			} else if err == nil {
				t.Fatal("invalid runner response accepted")
			}
		})
	}
	other := repo
	other.ID++
	if _, err := c.Runners(context.Background(), other, token, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("runner token escaped repository")
	}
}
func TestChangeFinalWriteFailureNeverReportsApplied(t *testing.T) {
	s, a, input, _ := serviceFixture(t)
	connection, err := s.Create(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	grantRepositoryRole(t, s, a.User.ID, "github-provider-runners-manager")
	if err := s.DB.Exec(`CREATE TRIGGER fail_change BEFORE UPDATE OF state ON github_changes WHEN NEW.state='applied' BEGIN SELECT RAISE(ABORT,'fixture'); END`).Error; err != nil {
		t.Fatal(err)
	}
	writes := map[string]int{}
	s.Client.transport = repositoryTransport(t, s.Client, "success", writes)
	request := RemoveRunner{RunnerID: 9, Name: "fixture-runner"}
	id := strings.Repeat("f", 32)
	row, err := s.RemoveProviderRunner(context.Background(), a, "build", connection.ID, id, request)
	if !errors.Is(err, ErrUnknown) || row.State != "unknown" || writes["delete"] != 1 {
		t.Fatal("failed persistence claimed confirmed result", row.State, err)
	}
	row, err = s.RemoveProviderRunner(context.Background(), a, "build", connection.ID, id, request)
	if err != nil || row.State != "submitting" || writes["delete"] != 1 {
		t.Fatal("failed persistence replayed provider change", row.State, err)
	}
}
func TestWorkflowRevocationStopsAfterBranchCreation(t *testing.T) {
	s, a, input, _ := serviceFixture(t)
	connection, err := s.Create(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	grantRepositoryRole(t, s, a.User.ID, "github-workflow-editor")
	writes := map[string]int{}
	original := repositoryTransport(t, s.Client, "success", writes)
	s.Client.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		out, err := original.RoundTrip(r)
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/git/refs") {
			if err := s.DB.Where("id=?", "github-workflow-editor").Delete(&authorization.Grant{}).Error; err != nil {
				t.Fatal(err)
			}
		}
		return out, err
	})
	row, err := s.PublishWorkflow(context.Background(), a, "build", connection.ID, strings.Repeat("e", 32), editFixture())
	if !errors.Is(err, ErrDenied) || row.State != "incomplete" || writes["branch"] != 1 || writes["file"] != 0 || writes["pull"] != 0 {
		t.Fatal("revoked workflow change continued", row.State, err, writes)
	}
}
