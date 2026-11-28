package githubactions

import (
	"context"
	"crypto/sha1" // Git object IDs; not used for authentication or signatures.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/xmahdi1/nexus/internal/auth"
)

type ProjectSnapshot struct {
	Repository Repository
	CommitSHA  string
	Files      map[string]string
}

var projectPathPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$`)

func ValidCommitSHA(value string) bool { return shaPattern.MatchString(value) }
func ValidProjectPath(name string) bool {
	if !projectPathPattern.MatchString(name) || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") || part == "ansible.cfg" {
			return false
		}
	}
	return true
}
func (c *Client) ProjectToken(ctx context.Context, app App, repo Repository) (*Token, error) {
	return c.mint(ctx, app, repo, false, "projects", map[string]string{"contents": "read", "metadata": "read"})
}
func (c *Client) ReadProject(ctx context.Context, repo Repository, token *Token, sha string, paths []string) (ProjectSnapshot, error) {
	result := ProjectSnapshot{Repository: repo, CommitSHA: sha, Files: map[string]string{}}
	if repo.Validate() != nil || !shaPattern.MatchString(sha) || len(paths) < 1 || len(paths) > 32 {
		return ProjectSnapshot{}, ErrInput
	}
	if !c.validScope(token, "projects") || token.repository != repo {
		return ProjectSnapshot{}, ErrDenied
	}
	selected := map[string]bool{}
	for _, name := range paths {
		if !ValidProjectPath(name) || selected[name] {
			return ProjectSnapshot{}, ErrInput
		}
		selected[name] = true
	}
	var commit struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	code, err := c.request(ctx, "GET", repo.path()+"/git/commits/"+sha, token.value, nil, &commit)
	if err != nil {
		return ProjectSnapshot{}, err
	}
	if code != 200 || commit.SHA != sha || !shaPattern.MatchString(commit.Tree.SHA) {
		return ProjectSnapshot{}, ErrUnavailable
	}
	var tree struct {
		SHA       string `json:"sha"`
		Truncated bool   `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
			Size int64  `json:"size"`
		} `json:"tree"`
	}
	code, err = c.request(ctx, "GET", repo.path()+"/git/trees/"+commit.Tree.SHA+"?recursive=1", token.value, nil, &tree)
	if err != nil {
		return ProjectSnapshot{}, err
	}
	if code != 200 || tree.SHA != commit.Tree.SHA || tree.Truncated || len(tree.Tree) > 5000 {
		return ProjectSnapshot{}, ErrUnavailable
	}
	objects := map[string]string{}
	for _, entry := range tree.Tree {
		if !selected[entry.Path] {
			continue
		}
		if objects[entry.Path] != "" || entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") || !shaPattern.MatchString(entry.SHA) || entry.Size < 0 || entry.Size > 16384 {
			return ProjectSnapshot{}, ErrInput
		}
		objects[entry.Path] = entry.SHA
	}
	if len(objects) != len(selected) {
		return ProjectSnapshot{}, ErrInput
	}
	size := 0
	for _, name := range paths {
		object := objects[name]
		var blob struct {
			SHA      string `json:"sha"`
			Size     int64  `json:"size"`
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		}
		code, err = c.request(ctx, "GET", repo.path()+"/git/blobs/"+object, token.value, nil, &blob)
		if err != nil {
			return ProjectSnapshot{}, err
		}
		if code != 200 || blob.SHA != object || blob.Encoding != "base64" || blob.Size < 0 || blob.Size > 16384 || len(blob.Content) > 32768 {
			return ProjectSnapshot{}, ErrUnavailable
		}
		data, err := base64.StdEncoding.DecodeString(blob.Content)
		if err != nil || int64(len(data)) != blob.Size || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			clear(data)
			return ProjectSnapshot{}, ErrUnavailable
		}
		content := append([]byte(fmt.Sprintf("blob %d\x00", len(data))), data...)
		digest := ""
		if len(object) == 40 {
			sum := sha1.Sum(content)
			digest = hex.EncodeToString(sum[:])
		} else {
			sum := sha256.Sum256(content)
			digest = hex.EncodeToString(sum[:])
		}
		clear(content)
		if digest != object {
			clear(data)
			return ProjectSnapshot{}, ErrUnavailable
		}
		size += len(name) + len(data)
		if size > 32768 {
			clear(data)
			return ProjectSnapshot{}, ErrInput
		}
		result.Files[name] = string(data)
		clear(data)
	}
	return result, nil
}
func (s *Service) ReadProject(ctx context.Context, a *auth.Access, server, id, sha string, paths []string) (ProjectSnapshot, error) {
	if !ValidCommitSHA(sha) || len(paths) < 1 || len(paths) > 32 {
		return ProjectSnapshot{}, ErrInput
	}
	for _, name := range paths {
		if !ValidProjectPath(name) {
			return ProjectSnapshot{}, ErrInput
		}
	}
	if err := s.require(a, server, true, "github.projects.read", "secrets.use"); err != nil {
		return ProjectSnapshot{}, err
	}
	row, data, err := s.connection(server, id)
	if err != nil {
		return ProjectSnapshot{}, err
	}
	key := []byte(data.PEM)
	defer clear(key)
	token, err := s.Client.ProjectToken(ctx, App{ClientID: data.ClientID, InstallationID: data.InstallationID, PrivateKey: key}, row.repository())
	if err != nil {
		return ProjectSnapshot{}, err
	}
	defer token.Clear()
	if ctx.Err() != nil || s.currentConnection(a, row, true, "github.projects.read") != nil {
		return ProjectSnapshot{}, ErrDenied
	}
	result, err := s.Client.ReadProject(ctx, row.repository(), token, sha, paths)
	if ctx.Err() != nil || s.currentConnection(a, row, true, "github.projects.read") != nil {
		return ProjectSnapshot{}, ErrDenied
	}
	return result, err
}
