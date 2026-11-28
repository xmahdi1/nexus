// Package githubrunner defines the closed Marketplace runner setup contract.
package githubrunner

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

const Version = "2.338.2"

var ErrInput = errors.New("use a GitHub.com repository/organization URL, safe runner name/labels, a short-lived registration token and a 5–60 minute lifetime")
var requestPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$`)
var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var groupPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,256}$`)

type Profile struct {
	URL             string   `json:"url"`
	Name            string   `json:"name"`
	Labels          []string `json:"labels"`
	Group           string   `json:"group"`
	LifetimeSeconds int      `json:"lifetimeSeconds"`
}
type Setup struct {
	Profile
	RequestID         string `json:"requestId"`
	RegistrationToken string `json:"registrationToken"`
}
type PublicProfile struct {
	Profile
	Version string `json:"version"`
}

func (s Setup) Validate() error {
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return ErrInput
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || !ownerPattern.MatchString(parts[0]) {
		return ErrInput
	}
	if len(parts) == 2 && (!repoPattern.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." || s.Group != "") {
		return ErrInput
	}
	if len(parts) == 1 && (!groupPattern.MatchString(s.Group)) {
		return ErrInput
	}
	if !requestPattern.MatchString(s.RequestID) || !namePattern.MatchString(s.Name) || s.LifetimeSeconds < 300 || s.LifetimeSeconds > 3600 || len(s.Labels) > 8 || !tokenPattern.MatchString(s.RegistrationToken) {
		return ErrInput
	}
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "github_pat_"} {
		if strings.HasPrefix(s.RegistrationToken, prefix) {
			return ErrInput
		}
	}
	seen := map[string]bool{}
	for _, label := range s.Labels {
		if !namePattern.MatchString(label) || seen[strings.ToLower(label)] {
			return ErrInput
		}
		seen[strings.ToLower(label)] = true
	}
	return nil
}
func (s Setup) PublicJSON() string {
	data, _ := json.Marshal(PublicProfile{s.Profile, Version})
	return string(data)
}

//go:embed run.py
var script string

func Command() string {
	return "exec /usr/bin/python3 -I -c '" + strings.ReplaceAll(script, "'", `'"'"'`) + "'"
}
