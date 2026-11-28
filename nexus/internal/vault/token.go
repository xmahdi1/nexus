package vault

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// checkToken does not require mount-list privileges. Access inspection must
// remain usable with a token allowed to inspect policies but not secrets engines.
func checkToken(ctx context.Context, client *http.Client, p Profile, token string) (bool, error) {
	if token == "" || len(token) > 8192 || strings.ContainsAny(token, "\r\n\x00") {
		return false, errors.New("supply a valid short-lived Vault token")
	}
	var identity struct {
		Data struct {
			Policies []string `json:"policies"`
			TTL      int64    `json:"ttl"`
		} `json:"data"`
	}
	code, err := read(ctx, client, p, "/v1/auth/token/lookup-self", token, &identity)
	if err != nil {
		return false, err
	}
	if code == 401 || code == 403 {
		return false, nil
	}
	if code != 200 {
		return false, errors.New("Vault token verification unavailable")
	}
	if identity.Data.Policies == nil {
		return false, errors.New("Vault returned incomplete token metadata")
	}
	for _, policy := range identity.Data.Policies {
		if policy == "root" {
			return false, errors.New("use a short-lived non-root Vault token")
		}
	}
	if identity.Data.TTL <= 0 || identity.Data.TTL > 86400 {
		return false, errors.New("use a Vault token with at most 24 hours remaining")
	}
	return true, nil
}
