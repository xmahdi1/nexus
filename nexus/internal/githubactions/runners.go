package githubactions

import (
	"context"
	"fmt"
	"strings"
)

type ProviderRunner struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	OS        string `json:"os"`
	Status    string `json:"status"`
	Busy      bool   `json:"busy"`
	Ephemeral bool   `json:"ephemeral"`
	Version   string `json:"version"`
	Labels    []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"labels"`
}
type RunnerPage struct {
	Total   int              `json:"total_count"`
	Runners []ProviderRunner `json:"runners"`
}

func validRunner(row ProviderRunner) bool {
	if !validID(row.ID) || len(row.Name) < 1 || len(row.Name) > 128 || strings.ContainsAny(row.Name, "\x00\r\n") || len(row.OS) > 32 || len(row.Version) > 64 || (row.Status != "online" && row.Status != "offline") || len(row.Labels) > 100 {
		return false
	}
	for _, label := range row.Labels {
		if len(label.Name) > 128 || strings.ContainsAny(label.Name, "\x00\r\n") || (label.Type != "custom" && label.Type != "read-only") {
			return false
		}
	}
	return true
}
func (c *Client) Runners(ctx context.Context, repo Repository, token *Token, page int) (RunnerPage, error) {
	var out RunnerPage
	if repo.Validate() != nil || page < 1 || page > 1000 {
		return out, ErrInput
	}
	if !c.validScope(token, "runners") || token.repository != repo {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runners?per_page=50&page=%d", repo.path(), page), token.value, nil, &out)
	if err != nil {
		return RunnerPage{}, err
	}
	if code != 200 || out.Total < 0 || len(out.Runners) > 50 {
		return RunnerPage{}, ErrUnavailable
	}
	for _, row := range out.Runners {
		if !validRunner(row) {
			return RunnerPage{}, ErrUnavailable
		}
	}
	return out, nil
}
func (c *Client) Runner(ctx context.Context, repo Repository, token *Token, id int64) (ProviderRunner, error) {
	var out ProviderRunner
	if repo.Validate() != nil || !validID(id) {
		return out, ErrInput
	}
	if !c.validScope(token, "runners") || token.repository != repo {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runners/%d", repo.path(), id), token.value, nil, &out)
	if err != nil {
		return ProviderRunner{}, err
	}
	if code != 200 || out.ID != id || !validRunner(out) {
		return ProviderRunner{}, ErrUnavailable
	}
	return out, nil
}
func (c *Client) RemoveRunnerOnce(ctx context.Context, repo Repository, token *Token, id int64, allowed func() bool) error {
	if repo.Validate() != nil || !validID(id) {
		return ErrInput
	}
	if !c.validScope(token, "runners") || token.repository != repo || !token.write || allowed == nil || !allowed() {
		return ErrDenied
	}
	code, err := c.request(ctx, "DELETE", fmt.Sprintf("%s/actions/runners/%d", repo.path(), id), token.value, nil, nil)
	if err != nil || code != 204 {
		return ErrUnknown
	}
	return nil
}
