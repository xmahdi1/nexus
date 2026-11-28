package githubactions

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProjectImportReadsOnlySelectedRegularFilesAtExactCommit(t *testing.T) {
	c, _, repo, _ := fixture(t)
	commit, tree := strings.Repeat("a", 40), strings.Repeat("b", 40)
	content := "- hosts: all\n  tasks:\n    - ansible.builtin.ping:\n"
	sum := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(content), content)))
	object := hex.EncodeToString(sum[:])
	token := &Token{value: "ghs_fixture_project_token", ExpiresAt: c.now().Add(time.Hour), repository: repo, scope: "projects"}
	mode := "100644"
	tamper := false
	calls := 0
	c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.Path {
		case repo.path() + "/git/commits/" + commit:
			return response(200, fmt.Sprintf(`{"sha":%q,"tree":{"sha":%q}}`, commit, tree)), nil
		case repo.path() + "/git/trees/" + tree:
			return response(200, fmt.Sprintf(`{"sha":%q,"truncated":false,"tree":[{"path":"main.yml","type":"blob","mode":%q,"sha":%q,"size":%d},{"path":"private.env","type":"blob","mode":"100644","sha":%q,"size":10}]}`, tree, mode, object, len(content), object)), nil
		case repo.path() + "/git/blobs/" + object:
			data := content
			if tamper {
				data = strings.Replace(data, "all", "bad", 1)
			}
			return response(200, fmt.Sprintf(`{"sha":%q,"encoding":"base64","size":%d,"content":%q}`, object, len(data), base64.StdEncoding.EncodeToString([]byte(data)))), nil
		default:
			t.Fatal("unrequested repository object fetched", r.URL.Path)
			return nil, nil
		}
	})
	result, err := c.ReadProject(context.Background(), repo, token, commit, []string{"main.yml"})
	if err != nil || result.CommitSHA != commit || len(result.Files) != 1 || result.Files["main.yml"] != content {
		t.Fatal("snapshot mismatch", err)
	}
	for _, bad := range []string{"../main.yml", ".github/file.yml", "ansible.cfg", "/etc/passwd", "roles/../main.yml"} {
		before := calls
		if _, err := c.ReadProject(context.Background(), repo, token, commit, []string{bad}); err == nil || calls != before {
			t.Fatal("unsafe path reached provider", bad)
		}
	}
	mode = "120000"
	if _, err := c.ReadProject(context.Background(), repo, token, commit, []string{"main.yml"}); err == nil {
		t.Fatal("symlink imported")
	}
	mode = "100644"
	tamper = true
	if _, err := c.ReadProject(context.Background(), repo, token, commit, []string{"main.yml"}); err == nil {
		t.Fatal("Git blob identity mismatch imported")
	}
	token.scope = "actions"
	before := calls
	if _, err := c.ReadProject(context.Background(), repo, token, commit, []string{"main.yml"}); err == nil || calls != before {
		t.Fatal("Actions token reused for source import")
	}
}
