package githubactions

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxWorkflowBytes = 32768

var workflowPathPattern = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]{0,123}\.ya?ml$`)
var editBranchPattern = regexp.MustCompile(`^nexus/workflows/[a-f0-9]{32}$`)

func validWorkflowPath(path string) bool {
	return workflowPathPattern.MatchString(path) && !strings.Contains(path, "..")
}
func validBranch(branch string) bool {
	return (Dispatch{WorkflowID: 1, Ref: branch}).Validate() == nil && !strings.HasPrefix(branch, "refs/")
}

type WorkflowFile struct {
	BaseBranch string `json:"baseBranch"`
	BaseSHA    string `json:"baseSha"`
	BlobSHA    string `json:"blobSha"`
	Path       string `json:"path"`
	Content    string `json:"content"`
}
type WorkflowEdit struct {
	BaseBranch string `json:"baseBranch"`
	BaseSHA    string `json:"baseSha"`
	BlobSHA    string `json:"blobSha"`
	Path       string `json:"path"`
	Content    string `json:"content"`
	Title      string `json:"title"`
}

func (input WorkflowEdit) Validate() error {
	if !validBranch(input.BaseBranch) || !shaPattern.MatchString(input.BaseSHA) || !shaPattern.MatchString(input.BlobSHA) || !validWorkflowPath(input.Path) || len(input.Content) > MaxWorkflowBytes || len(input.Content) == 0 || !utf8.ValidString(input.Content) || strings.ContainsRune(input.Content, 0) || strings.TrimSpace(input.Title) == "" || len(input.Title) > 120 || strings.ContainsAny(input.Title, "\x00\r\n") {
		return ErrInput
	}
	return nil
}
func (c *Client) branchSHA(ctx context.Context, repo Repository, token *Token, branch string) (string, error) {
	if repo.Validate() != nil || !validBranch(branch) {
		return "", ErrInput
	}
	if !c.validScope(token, "workflows") || token.repository != repo {
		return "", ErrDenied
	}
	var out struct {
		Ref    string `json:"ref"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	code, err := c.request(ctx, "GET", repo.path()+"/git/ref/heads/"+url.PathEscape(branch), token.value, nil, &out)
	if err != nil {
		return "", err
	}
	if code != 200 || out.Ref != "refs/heads/"+branch || out.Object.Type != "commit" || !shaPattern.MatchString(out.Object.SHA) {
		return "", ErrUnavailable
	}
	return out.Object.SHA, nil
}
func (c *Client) fileAt(ctx context.Context, repo Repository, token *Token, path, sha string) (WorkflowFile, error) {
	var result WorkflowFile
	if repo.Validate() != nil || !validWorkflowPath(path) || !shaPattern.MatchString(sha) {
		return result, ErrInput
	}
	if !c.validScope(token, "workflows") || token.repository != repo {
		return result, ErrDenied
	}
	var out struct {
		Path     string `json:"path"`
		SHA      string `json:"sha"`
		Type     string `json:"type"`
		Size     int64  `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	code, err := c.request(ctx, "GET", repo.path()+"/contents/"+path+"?ref="+sha, token.value, nil, &out)
	if err != nil {
		return result, err
	}
	if code != 200 || out.Path != path || out.Type != "file" || out.Encoding != "base64" || !shaPattern.MatchString(out.SHA) || out.Size < 0 || out.Size > MaxWorkflowBytes || len(out.Content) > MaxWorkflowBytes*2 {
		return result, ErrUnavailable
	}
	data, err := base64.StdEncoding.DecodeString(out.Content)
	defer clear(data)
	if err != nil || int64(len(data)) != out.Size || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return result, ErrUnavailable
	}
	return WorkflowFile{BaseSHA: sha, BlobSHA: out.SHA, Path: path, Content: string(data)}, nil
}
func (c *Client) ReadWorkflow(ctx context.Context, repo Repository, token *Token, branch, path string) (WorkflowFile, error) {
	sha, err := c.branchSHA(ctx, repo, token, branch)
	if err != nil {
		return WorkflowFile{}, err
	}
	file, err := c.fileAt(ctx, repo, token, path, sha)
	file.BaseBranch = branch
	return file, err
}
func (c *Client) createWorkflowBranch(ctx context.Context, repo Repository, token *Token, branch, sha string, allowed func() bool) error {
	if !editBranchPattern.MatchString(branch) || !shaPattern.MatchString(sha) || repo.Validate() != nil {
		return ErrInput
	}
	if !c.validScope(token, "workflows") || token.repository != repo || !token.write || allowed == nil || !allowed() {
		return ErrDenied
	}
	var out struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	code, err := c.request(ctx, "POST", repo.path()+"/git/refs", token.value, map[string]any{"ref": "refs/heads/" + branch, "sha": sha}, &out)
	if err != nil || code != 201 || out.Ref != "refs/heads/"+branch || out.Object.SHA != sha {
		return ErrUnknown
	}
	return nil
}
func (c *Client) writeWorkflowOnce(ctx context.Context, repo Repository, token *Token, branch string, input WorkflowEdit, allowed func() bool) (string, error) {
	if input.Validate() != nil || !editBranchPattern.MatchString(branch) || repo.Validate() != nil {
		return "", ErrInput
	}
	if !c.validScope(token, "workflows") || token.repository != repo || !token.write || allowed == nil || !allowed() {
		return "", ErrDenied
	}
	var out struct {
		Content struct {
			SHA  string `json:"sha"`
			Path string `json:"path"`
		} `json:"content"`
		Commit struct {
			SHA     string `json:"sha"`
			Parents []struct {
				SHA string `json:"sha"`
			} `json:"parents"`
		} `json:"commit"`
	}
	code, err := c.request(ctx, "PUT", repo.path()+"/contents/"+input.Path, token.value, map[string]any{"message": input.Title, "content": base64.StdEncoding.EncodeToString([]byte(input.Content)), "sha": input.BlobSHA, "branch": branch}, &out)
	if err != nil || code != 200 || out.Content.Path != input.Path || !shaPattern.MatchString(out.Content.SHA) || !shaPattern.MatchString(out.Commit.SHA) || out.Commit.SHA == input.BaseSHA || out.Content.SHA == input.BlobSHA || len(out.Commit.Parents) != 1 || out.Commit.Parents[0].SHA != input.BaseSHA {
		return "", ErrUnknown
	}
	return out.Commit.SHA, nil
}
func (c *Client) workflowPullOnce(ctx context.Context, repo Repository, token *Token, branch, commit string, input WorkflowEdit, allowed func() bool) (int64, error) {
	if input.Validate() != nil || !editBranchPattern.MatchString(branch) || !shaPattern.MatchString(commit) || repo.Validate() != nil {
		return 0, ErrInput
	}
	if !c.validScope(token, "workflows") || token.repository != repo || !token.write || allowed == nil || !allowed() {
		return 0, ErrDenied
	}
	var out struct {
		Number int64 `json:"number"`
		Draft  bool  `json:"draft"`
		Head   struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			SHA  string `json:"sha"`
			Ref  string `json:"ref"`
			Repo struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"base"`
	}
	code, err := c.request(ctx, "POST", repo.path()+"/pulls", token.value, map[string]any{"title": input.Title, "head": branch, "base": input.BaseBranch, "draft": true, "body": fmt.Sprintf("Update %s. Review the diff and workflow checks before merging. This request does not merge or deploy.", input.Path)}, &out)
	if err != nil || code != 201 || !validID(out.Number) || !out.Draft || out.Head.Ref != branch || out.Head.SHA != commit || out.Head.Repo.ID != repo.ID || out.Base.Ref != input.BaseBranch || out.Base.SHA != input.BaseSHA || out.Base.Repo.ID != repo.ID {
		return 0, ErrUnknown
	}
	return out.Number, nil
}
