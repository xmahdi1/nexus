package githubactions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxLogBytes = 1 << 20
const MaxArtifactBytes = 16 << 20

var ErrTooLarge = errors.New("GitHub download exceeds the supported size")

func validID(id int64) bool { return id > 0 && id <= 9007199254740991 }

func (c *Client) Run(ctx context.Context, repo Repository, token *Token, id int64) (Run, error) {
	var out struct {
		Run
		Repository struct {
			ID int64 `json:"id"`
		} `json:"repository"`
	}
	if repo.Validate() != nil || !validID(id) {
		return Run{}, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return Run{}, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runs/%d", repo.path(), id), token.value, nil, &out)
	if err != nil {
		return Run{}, err
	}
	if code != 200 || out.ID != id || out.Repository.ID != repo.ID || !validRun(out.Run) || !validID(out.RunAttempt) {
		return Run{}, ErrUnavailable
	}
	return out.Run, nil
}

// CancelOnce requests ordinary cancellation, not force cancellation or proof of
// termination. The caller must first reserve and claim a durable request ID.
func (c *Client) CancelOnce(ctx context.Context, repo Repository, token *Token, run int64, beforeWrite func() bool) error {
	if repo.Validate() != nil || !validID(run) {
		return ErrInput
	}
	if !c.valid(token) || token.repository != repo || !token.write || beforeWrite == nil || !beforeWrite() {
		return ErrDenied
	}
	code, err := c.request(ctx, "POST", fmt.Sprintf("%s/actions/runs/%d/cancel", repo.path(), run), token.value, nil, nil)
	if code == 409 {
		return ErrConflict
	}
	if err != nil || code != 202 {
		return ErrUnknown
	}
	return nil
}

type Artifact struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size_in_bytes"`
	Expired     bool   `json:"expired"`
	WorkflowRun struct {
		ID           int64 `json:"id"`
		RepositoryID int64 `json:"repository_id"`
	} `json:"workflow_run"`
}
type ArtifactPage struct {
	Total     int        `json:"total_count"`
	Artifacts []Artifact `json:"artifacts"`
}

func validArtifact(row Artifact, repo Repository, run int64) bool {
	return validID(row.ID) && row.WorkflowRun.ID == run && row.WorkflowRun.RepositoryID == repo.ID && row.Size >= 0 && row.Size <= 9007199254740991 && len(row.Name) > 0 && len(row.Name) <= 256 && !strings.ContainsAny(row.Name, "\x00\r\n")
}
func (c *Client) Artifacts(ctx context.Context, repo Repository, token *Token, run int64, page int) (ArtifactPage, error) {
	var out ArtifactPage
	if repo.Validate() != nil || !validID(run) || page < 1 || page > 1000 {
		return out, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runs/%d/artifacts?per_page=50&page=%d", repo.path(), run, page), token.value, nil, &out)
	if err != nil {
		return ArtifactPage{}, err
	}
	if code != 200 || out.Total < 0 || len(out.Artifacts) > 50 {
		return ArtifactPage{}, ErrUnavailable
	}
	for _, row := range out.Artifacts {
		if !validArtifact(row, repo, run) {
			return ArtifactPage{}, ErrUnavailable
		}
	}
	return out, nil
}
func (c *Client) JobLog(ctx context.Context, repo Repository, token *Token, run, job int64) ([]byte, error) {
	if repo.Validate() != nil || !validID(run) || !validID(job) {
		return nil, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return nil, ErrDenied
	}
	var identity Job
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/jobs/%d", repo.path(), job), token.value, nil, &identity)
	if err != nil {
		return nil, err
	}
	if code != 200 || identity.ID != job || identity.RunID != run {
		return nil, ErrDenied
	}
	data, err := c.download(ctx, fmt.Sprintf("%s/actions/jobs/%d/logs", repo.path(), job), token, MaxLogBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		clear(data)
		return nil, ErrUnavailable
	}
	return data, nil
}
func (c *Client) ArtifactZIP(ctx context.Context, repo Repository, token *Token, run, id int64) ([]byte, error) {
	if repo.Validate() != nil || !validID(run) || !validID(id) {
		return nil, ErrInput
	}
	if !c.valid(token) || token.repository != repo {
		return nil, ErrDenied
	}
	var row Artifact
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/artifacts/%d", repo.path(), id), token.value, nil, &row)
	if err != nil {
		return nil, err
	}
	if code != 200 || row.ID != id || !validArtifact(row, repo, run) || row.Expired {
		return nil, ErrDenied
	}
	if row.Size > MaxArtifactBytes {
		return nil, ErrTooLarge
	}
	data, err := c.download(ctx, fmt.Sprintf("%s/actions/artifacts/%d/zip", repo.path(), id), token, MaxArtifactBytes)
	if err != nil {
		return nil, err
	}
	// Never extract or render archive members. Retain only a bounded opaque ZIP.
	if len(data) < 4 || (string(data[:4]) != "PK\x03\x04" && string(data[:4]) != "PK\x05\x06") {
		clear(data)
		return nil, ErrUnavailable
	}
	return data, nil
}

func signedDownloadURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || len(value) > 8192 || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Port() != "" || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(value, "\x00\r\n") {
		return nil, ErrUnavailable
	}
	host := u.Hostname()
	allowed := host == "results-receiver.actions.githubusercontent.com"
	if strings.HasSuffix(host, ".blob.core.windows.net") {
		account := strings.TrimSuffix(host, ".blob.core.windows.net")
		allowed = len(account) >= 3 && len(account) <= 24
		for _, char := range account {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
				allowed = false
			}
		}
	}
	if !allowed {
		return nil, ErrUnavailable
	}
	return u, nil
}

func publicDownloadIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, value := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48"} {
		if netip.MustParsePrefix(value).Contains(ip) {
			return false
		}
	}
	return true
}
func newDownloadTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" {
			return nil, ErrUnavailable
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, ErrUnavailable
		}
		for _, ip := range ips {
			if !publicDownloadIP(ip) {
				return nil, ErrUnavailable
			}
		}
		dialer := net.Dialer{Timeout: 10 * time.Second}
		// Dial a validated numeric address, preserving the URL hostname for TLS SNI.
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return transport
}

var contentTransport http.RoundTripper = newDownloadTransport()

func (c *Client) download(ctx context.Context, path string, token *Token, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com"+path, nil)
	if err != nil {
		return nil, ErrInput
	}
	req.Header.Set("Authorization", "Bearer "+token.value)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", "Nexus-Actions")
	client := &http.Client{Transport: c.transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	response.Body.Close()
	if response.StatusCode != 302 {
		return nil, ErrUnavailable
	}
	destination, err := signedDownloadURL(response.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	// Signed storage requests carry no GitHub bearer, cookies or API headers and
	// may never redirect again. Neither signed URL nor provider errors are exposed.
	req, err = http.NewRequestWithContext(ctx, "GET", destination.String(), nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Accept-Encoding", "identity")
	transport := c.downloadTransport
	if transport == nil {
		transport = contentTransport
	}
	client = &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err = client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, ErrUnavailable
	}
	if response.ContentLength > limit {
		return nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if int64(len(data)) > limit {
		clear(data)
		return nil, ErrTooLarge
	}
	if err != nil {
		clear(data)
		return nil, ErrUnavailable
	}
	return data, nil
}
