// Package githubactions implements a closed GitHub.com Actions API adapter.
package githubactions

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const APIVersion = "2026-03-10"

var ErrConflict = errors.New("GitHub request identity, run or connection changed")
var ErrInput = errors.New("invalid GitHub connection or workflow fields")
var ErrDenied = errors.New("GitHub denied the selected operation")
var ErrUnavailable = errors.New("GitHub response unavailable or invalid")
var ErrUnknown = errors.New("GitHub mutation outcome is unknown; inspect GitHub before any new request")
var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var issuerPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)
var inputPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)

type Repository struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
	ID    int64  `json:"repositoryId"`
}

func (r Repository) Validate() error {
	if !ownerPattern.MatchString(r.Owner) || !repoPattern.MatchString(r.Name) || r.Name == "." || r.Name == ".." || r.ID < 1 || r.ID > 9007199254740991 {
		return ErrInput
	}
	return nil
}
func (r Repository) path() string { return "/repos/" + r.Owner + "/" + r.Name }

type App struct {
	ClientID       string
	InstallationID int64
	PrivateKey     []byte `json:"-"`
}
type Token struct {
	value      string
	ExpiresAt  time.Time
	repository Repository
	write      bool
	scope      string
}

func (t *Token) Clear() { t.value = ""; t.ExpiresAt = time.Time{} }

type Client struct {
	transport         http.RoundTripper
	downloadTransport http.RoundTripper
	now               func() time.Time
}

func New() *Client { return &Client{transport: http.DefaultTransport, now: time.Now} }

func (app App) jwt(now time.Time) (string, error) {
	if !issuerPattern.MatchString(app.ClientID) || app.InstallationID < 1 || app.InstallationID > 9007199254740991 || len(app.PrivateKey) > 16384 {
		return "", ErrInput
	}
	block, rest := pem.Decode(app.PrivateKey)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", ErrInput
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.Validate() != nil {
		return "", ErrInput
	}
	enc := base64.RawURLEncoding.EncodeToString
	head := enc([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "iss": app.ClientID})
	body := head + "." + enc(claims)
	digest := sha256.Sum256([]byte(body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", ErrInput
	}
	return body + "." + enc(signature), nil
}

// request never follows redirects, retries, accepts caller URLs or returns raw
// upstream errors. The injectable transport remains private to fixture tests.
func (c *Client) request(ctx context.Context, method, path, bearer string, payload any, out any) (int, error) {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return 0, ErrInput
		}
		defer clear(data)
	}
	if len(data) > 65536 {
		return 0, ErrInput
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, bytes.NewReader(data))
	if err != nil {
		return 0, ErrInput
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", "Nexus-Actions")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Transport: c.transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 404 {
		return response.StatusCode, ErrDenied
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	defer clear(body)
	if err != nil || len(body) > 1048576 {
		return response.StatusCode, ErrUnavailable
	}
	if out != nil {
		if json.Unmarshal(body, out) != nil {
			return response.StatusCode, ErrUnavailable
		}
	}
	return response.StatusCode, nil
}

// InstallationToken requests exactly one repository and an explicit permission
// set. The private key/JWT/minted token are never public JSON or saved metadata.
func (c *Client) InstallationToken(ctx context.Context, app App, repo Repository, write bool) (*Token, error) {
	actions := "read"
	if write {
		actions = "write"
	}
	return c.mint(ctx, app, repo, write, "actions", map[string]string{"actions": actions, "contents": "read", "metadata": "read"})
}
func (c *Client) RunnerToken(ctx context.Context, app App, repo Repository, write bool) (*Token, error) {
	level := "read"
	if write {
		level = "write"
	}
	return c.mint(ctx, app, repo, write, "runners", map[string]string{"administration": level, "metadata": "read"})
}
func (c *Client) WorkflowToken(ctx context.Context, app App, repo Repository, write bool) (*Token, error) {
	permissions := map[string]string{"contents": "read", "metadata": "read"}
	if write {
		permissions["contents"] = "write"
		permissions["workflows"] = "write"
		permissions["pull_requests"] = "write"
	}
	return c.mint(ctx, app, repo, write, "workflows", permissions)
}
func (c *Client) mint(ctx context.Context, app App, repo Repository, write bool, scope string, permissions map[string]string) (*Token, error) {
	if repo.Validate() != nil {
		return nil, ErrInput
	}
	jwt, err := app.jwt(c.now())
	if err != nil {
		return nil, err
	}
	var result struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			ID int64 `json:"id"`
		} `json:"repositories"`
	}
	code, err := c.request(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", app.InstallationID), jwt, map[string]any{"repository_ids": []int64{repo.ID}, "permissions": permissions}, &result)
	if err != nil {
		return nil, err
	}
	if code != 201 || !strings.HasPrefix(result.Token, "ghs_") || len(result.Token) > 8192 || !safeToken(result.Token) || !result.ExpiresAt.After(c.now().Add(30*time.Second)) || result.ExpiresAt.After(c.now().Add(70*time.Minute)) || len(result.Repositories) != 1 || result.Repositories[0].ID != repo.ID {
		return nil, ErrUnavailable
	}
	for permission, level := range result.Permissions {
		want := permissions[permission]
		if want == "" || level != want {
			return nil, ErrDenied
		}
	}
	for permission, level := range permissions {
		if permission != "metadata" && result.Permissions[permission] != level {
			return nil, ErrDenied
		}
	}
	token := &Token{value: result.Token, ExpiresAt: result.ExpiresAt, repository: repo, write: write, scope: scope}
	var identity struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	}
	code, err = c.request(ctx, "GET", repo.path(), token.value, nil, &identity)
	if err != nil || code != 200 || identity.ID != repo.ID || !strings.EqualFold(identity.FullName, repo.Owner+"/"+repo.Name) {
		token.Clear()
		return nil, ErrDenied
	}
	return token, nil
}
func safeToken(value string) bool {
	if len(value) < 20 {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func (c *Client) valid(token *Token) bool {
	return c.validScope(token, "actions")
}

func (c *Client) validScope(token *Token, scope string) bool {
	return token != nil && token.value != "" && token.ExpiresAt.After(c.now().Add(5*time.Second)) && (token.scope == scope || (scope == "actions" && token.scope == ""))
}

type Workflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}
type WorkflowPage struct {
	Total     int        `json:"total_count"`
	Workflows []Workflow `json:"workflows"`
}

func (c *Client) Workflows(ctx context.Context, repo Repository, token *Token, page int) (WorkflowPage, error) {
	var out WorkflowPage
	if repo.Validate() != nil || page < 1 || page > 1000 {
		return out, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/workflows?per_page=50&page=%d", repo.path(), page), token.value, nil, &out)
	if err != nil {
		return WorkflowPage{}, err
	}
	if code != 200 || out.Total < 0 || len(out.Workflows) > 50 {
		return WorkflowPage{}, ErrUnavailable
	}
	for _, w := range out.Workflows {
		if w.ID < 1 || w.ID > 9007199254740991 || len(w.Name) > 256 || len(w.Path) > 512 || !strings.HasPrefix(w.Path, ".github/workflows/") || strings.Contains(w.Path, "..") || len(w.State) > 40 {
			return WorkflowPage{}, ErrUnavailable
		}
	}
	return out, nil
}

type Dispatch struct {
	WorkflowID int64          `json:"workflowId"`
	Ref        string         `json:"ref"`
	Inputs     map[string]any `json:"inputs"`
}

func (d Dispatch) Validate() error {
	if d.WorkflowID < 1 || d.WorkflowID > 9007199254740991 || len(d.Ref) < 1 || len(d.Ref) > 200 || strings.HasPrefix(d.Ref, "-") || strings.ContainsAny(d.Ref, " ~^:?*[\\\x00\r\n") || strings.Contains(d.Ref, "..") || strings.Contains(d.Ref, "@{") || len(d.Inputs) > 25 {
		return ErrInput
	}
	for _, char := range d.Ref {
		if char < 33 || char == 127 {
			return ErrInput
		}
	}
	if strings.HasPrefix(d.Ref, "/") || strings.HasSuffix(d.Ref, "/") || strings.HasSuffix(d.Ref, ".") || strings.HasSuffix(d.Ref, ".lock") || strings.Contains(d.Ref, "//") {
		return ErrInput
	}
	for key, value := range d.Inputs {
		if !inputPattern.MatchString(key) {
			return ErrInput
		}
		switch v := value.(type) {
		case string:
			if len(v) > 4096 || strings.ContainsRune(v, 0) {
				return ErrInput
			}
		case bool:
		default:
			return ErrInput
		}
	}
	return nil
}

type DispatchResult struct {
	RunID int64 `json:"workflow_run_id"`
}

// DispatchOnce performs exactly one provider mutation. Callers must reserve a
// durable request identity before entering this method. A lost/invalid response
// cannot be retried or correlated by guessing the most recent run.
func (c *Client) DispatchOnce(ctx context.Context, repo Repository, token *Token, input Dispatch, beforeWrite func() bool) (DispatchResult, error) {
	var out DispatchResult
	if repo.Validate() != nil || input.Validate() != nil {
		return out, ErrInput
	}
	if !c.valid(token) || token.repository != repo || !token.write || beforeWrite == nil || !beforeWrite() {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "POST", fmt.Sprintf("%s/actions/workflows/%d/dispatches", repo.path(), input.WorkflowID), token.value, map[string]any{"ref": input.Ref, "inputs": input.Inputs}, &out)
	if err != nil || code != 200 || out.RunID < 1 || out.RunID > 9007199254740991 {
		return DispatchResult{}, ErrUnknown
	}
	return out, nil
}

type Run struct {
	RunAttempt int64   `json:"run_attempt"`
	ID         int64   `json:"id"`
	WorkflowID int64   `json:"workflow_id"`
	Status     string  `json:"status"`
	Conclusion *string `json:"conclusion"`
	HeadSHA    string  `json:"head_sha"`
	HeadBranch string  `json:"head_branch"`
	Event      string  `json:"event"`
}
type RunPage struct {
	Total int   `json:"total_count"`
	Runs  []Run `json:"workflow_runs"`
}

func (c *Client) Runs(ctx context.Context, repo Repository, token *Token, page int) (RunPage, error) {
	var out RunPage
	if repo.Validate() != nil || page < 1 || page > 1000 {
		return out, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runs?per_page=50&page=%d", repo.path(), page), token.value, nil, &out)
	if err != nil {
		return RunPage{}, err
	}
	if code != 200 || out.Total < 0 || len(out.Runs) > 50 {
		return RunPage{}, ErrUnavailable
	}
	for _, row := range out.Runs {
		if !validRun(row) {
			return RunPage{}, ErrUnavailable
		}
	}
	return out, nil
}
func validRun(row Run) bool {
	return row.ID > 0 && row.ID <= 9007199254740991 && row.WorkflowID > 0 && row.WorkflowID <= 9007199254740991 && len(row.Status) <= 40 && (row.Conclusion == nil || len(*row.Conclusion) <= 40) && shaPattern.MatchString(row.HeadSHA) && len(row.HeadBranch) <= 256 && len(row.Event) <= 80
}

type Job struct {
	ID         int64   `json:"id"`
	RunID      int64   `json:"run_id"`
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	Conclusion *string `json:"conclusion"`
}
type JobPage struct {
	Total int   `json:"total_count"`
	Jobs  []Job `json:"jobs"`
}

func (c *Client) Jobs(ctx context.Context, repo Repository, token *Token, run int64, page int) (JobPage, error) {
	var out JobPage
	if repo.Validate() != nil || run < 1 || run > 9007199254740991 || page < 1 || page > 1000 {
		return out, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runs/%d/jobs?per_page=50&page=%d", repo.path(), run, page), token.value, nil, &out)
	if err != nil {
		return JobPage{}, err
	}
	if code != 200 || out.Total < 0 || len(out.Jobs) > 50 {
		return JobPage{}, ErrUnavailable
	}
	for _, row := range out.Jobs {
		if row.ID < 1 || row.ID > 9007199254740991 || row.RunID != run || len(row.Name) > 256 || len(row.Status) > 40 || (row.Conclusion != nil && len(*row.Conclusion) > 40) {
			return JobPage{}, ErrUnavailable
		}
	}
	return out, nil
}
