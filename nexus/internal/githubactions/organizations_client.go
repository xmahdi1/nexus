package githubactions

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Organization struct {
	Login string `json:"login"`
	ID    int64  `json:"organizationId"`
}

func (o Organization) Validate() error {
	if !ownerPattern.MatchString(o.Login) || !validID(o.ID) {
		return ErrInput
	}
	return nil
}
func (o Organization) path() string { return "/orgs/" + o.Login }

// This credential type cannot be passed to repository operations.
type OrganizationToken struct {
	value        string
	ExpiresAt    time.Time
	organization Organization
	write        bool
}

func (t *OrganizationToken) Clear() { t.value = ""; t.ExpiresAt = time.Time{} }
func (c *Client) validOrganization(t *OrganizationToken, org Organization, write bool) bool {
	return org.Validate() == nil && t != nil && t.value != "" && t.organization == org && t.ExpiresAt.After(c.now().Add(5*time.Second)) && (!write || t.write)
}

// OrganizationToken verifies the installation's owning account with the App JWT
// before requesting only the organization runner permission, never Actions or Contents.
func (c *Client) OrganizationToken(ctx context.Context, app App, org Organization, write bool) (*OrganizationToken, error) {
	if org.Validate() != nil {
		return nil, ErrInput
	}
	jwt, err := app.jwt(c.now())
	if err != nil {
		return nil, err
	}
	var installation struct {
		ID      int64 `json:"id"`
		Account struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
		SuspendedAt *time.Time `json:"suspended_at"`
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("/app/installations/%d", app.InstallationID), jwt, nil, &installation)
	if err != nil {
		return nil, err
	}
	if code != 200 || installation.ID != app.InstallationID || installation.Account.ID != org.ID || !strings.EqualFold(installation.Account.Login, org.Login) || installation.Account.Type != "Organization" || installation.SuspendedAt != nil {
		return nil, ErrDenied
	}
	level := "read"
	if write {
		level = "write"
	}
	var result struct {
		Token       string            `json:"token"`
		ExpiresAt   time.Time         `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
	}
	code, err = c.request(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", app.InstallationID), jwt, map[string]any{"permissions": map[string]string{"organization_self_hosted_runners": level}}, &result)
	if err != nil {
		return nil, err
	}
	if code != 201 || !strings.HasPrefix(result.Token, "ghs_") || len(result.Token) > 8192 || !safeToken(result.Token) || !result.ExpiresAt.After(c.now().Add(30*time.Second)) || result.ExpiresAt.After(c.now().Add(70*time.Minute)) {
		return nil, ErrUnavailable
	}
	if result.Permissions["organization_self_hosted_runners"] != level {
		return nil, ErrDenied
	}
	for permission, granted := range result.Permissions {
		if permission == "organization_self_hosted_runners" && granted == level {
			continue
		}
		if permission == "metadata" && granted == "read" {
			continue
		}
		return nil, ErrDenied
	}
	return &OrganizationToken{value: result.Token, ExpiresAt: result.ExpiresAt, organization: org, write: write}, nil
}
func (c *Client) OrganizationRunners(ctx context.Context, org Organization, token *OrganizationToken, page int) (RunnerPage, error) {
	var out RunnerPage
	if page < 1 || page > 1000 {
		return out, ErrInput
	}
	if !c.validOrganization(token, org, false) {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runners?per_page=50&page=%d", org.path(), page), token.value, nil, &out)
	if err != nil {
		return RunnerPage{}, err
	}
	if code != 200 || out.Total < 0 || len(out.Runners) > 50 {
		return RunnerPage{}, ErrUnavailable
	}
	for _, runner := range out.Runners {
		if !validRunner(runner) {
			return RunnerPage{}, ErrUnavailable
		}
	}
	return out, nil
}
func (c *Client) OrganizationRunner(ctx context.Context, org Organization, token *OrganizationToken, id int64) (ProviderRunner, error) {
	var out ProviderRunner
	if !validID(id) {
		return out, ErrInput
	}
	if !c.validOrganization(token, org, false) {
		return out, ErrDenied
	}
	code, err := c.request(ctx, "GET", fmt.Sprintf("%s/actions/runners/%d", org.path(), id), token.value, nil, &out)
	if err != nil {
		return out, err
	}
	if code != 200 || out.ID != id || !validRunner(out) {
		return ProviderRunner{}, ErrUnavailable
	}
	return out, nil
}
func (c *Client) RemoveOrganizationRunnerOnce(ctx context.Context, org Organization, token *OrganizationToken, id int64, allowed func() bool) error {
	if !validID(id) {
		return ErrInput
	}
	if !c.validOrganization(token, org, true) || allowed == nil || !allowed() {
		return ErrDenied
	}
	code, err := c.request(ctx, "DELETE", fmt.Sprintf("%s/actions/runners/%d", org.path(), id), token.value, nil, nil)
	if err != nil || code != 204 {
		return ErrUnknown
	}
	return nil
}

type RegistrationCredential struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var registrationTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,256}$`)

func (c *Client) OrganizationRegistrationOnce(ctx context.Context, org Organization, token *OrganizationToken, allowed func() bool) (RegistrationCredential, error) {
	if !c.validOrganization(token, org, true) || allowed == nil || !allowed() {
		return RegistrationCredential{}, ErrDenied
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	code, err := c.request(ctx, "POST", org.path()+"/actions/runners/registration-token", token.value, nil, &out)
	if err != nil || code != 201 || !registrationTokenPattern.MatchString(out.Token) || !out.ExpiresAt.After(c.now().Add(30*time.Second)) || out.ExpiresAt.After(c.now().Add(70*time.Minute)) {
		return RegistrationCredential{}, ErrUnknown
	}
	for _, prefix := range []string{"ghs_", "ghp_", "gho_", "ghu_", "github_pat_"} {
		if strings.HasPrefix(out.Token, prefix) {
			return RegistrationCredential{}, ErrUnknown
		}
	}
	return RegistrationCredential{Token: out.Token, ExpiresAt: out.ExpiresAt}, nil
}
