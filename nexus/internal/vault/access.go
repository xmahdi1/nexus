package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type AccessRequest struct {
	Token string   `json:"token"`
	Name  string   `json:"name,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

var policyPattern = regexp.MustCompile(`^[A-Za-z0-9_@.-]{1,128}$`)
var capabilityPathPattern = regexp.MustCompile(`^[A-Za-z0-9_@./*+-]+$`)

func (r AccessRequest) Validate(action string) error {
	if r.Token == "" || len(r.Token) > 8192 || strings.ContainsAny(r.Token, "\r\n\x00") {
		return errors.New("a valid Vault token is required")
	}
	switch action {
	case "auth", "policies":
		if r.Name != "" || len(r.Paths) != 0 {
			return errors.New("unexpected access-inspection fields")
		}
	case "policy":
		if !policyPattern.MatchString(r.Name) || r.Name == "." || r.Name == ".." || len(r.Paths) != 0 {
			return errors.New("select a supported ACL policy name")
		}
	case "capabilities":
		if r.Name != "" || len(r.Paths) == 0 || len(r.Paths) > 32 {
			return errors.New("supply between one and 32 Vault paths")
		}
		for _, path := range r.Paths {
			if len(path) > 1024 || !capabilityPathPattern.MatchString(path) || strings.HasPrefix(path, "/") {
				return errors.New("invalid capability path")
			}
			for _, segment := range strings.Split(path, "/") {
				if segment == "." || segment == ".." {
					return errors.New("invalid capability path")
				}
			}
		}
	default:
		return errors.New("unsupported Vault access inspection")
	}
	return nil
}

type AuthMethod struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	DefaultTTL  *int64 `json:"defaultTTL,omitempty"`
	MaxTTL      *int64 `json:"maxTTL,omitempty"`
}
type AccessResult struct {
	Methods      []AuthMethod        `json:"methods,omitempty"`
	Policies     []string            `json:"policies,omitempty"`
	Name         string              `json:"name,omitempty"`
	Policy       *string             `json:"policy,omitempty"`
	Redacted     bool                `json:"redacted,omitempty"`
	Capabilities map[string][]string `json:"capabilities,omitempty"`
}

// Access reads only auth metadata, ACL policy source, or this caller's path
// capabilities. Even capabilities' POST is a read operation, not policy mutation.
func Access(ctx context.Context, client *http.Client, p Profile, action string, input AccessRequest) (AccessResult, error) {
	result := AccessResult{}
	if err := input.Validate(action); err != nil {
		return result, err
	}
	allowed, err := checkToken(ctx, client, p, input.Token)
	if err != nil {
		return result, err
	}
	if !allowed {
		return result, ErrDenied
	}
	method, path := "GET", "/v1/sys/auth"
	var payload []byte
	switch action {
	case "policies":
		path = "/v1/sys/policies/acl?list=true"
	case "policy":
		path = "/v1/sys/policies/acl/" + input.Name
	case "capabilities":
		method, path = "POST", "/v1/sys/capabilities-self"
		payload, _ = json.Marshal(map[string]any{"paths": input.Paths})
		defer clear(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+p.TLSName+path, bytes.NewReader(payload))
	if err != nil {
		return result, errors.New("Vault access request failed")
	}
	req.Header.Set("X-Vault-Token", input.Token)
	if p.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.Namespace)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(req)
	if err != nil {
		return result, errors.New("Vault access transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return result, ErrDenied
	}
	if response.StatusCode == 404 {
		return result, ErrNotFound
	}
	if response.StatusCode != 200 {
		return result, errors.New("Vault access inspection unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	defer clear(data)
	invalid := errors.New("invalid or oversized Vault access response")
	if err != nil || len(data) > 1048576 {
		return result, invalid
	}
	redact := func(value string) string { return strings.ReplaceAll(value, input.Token, "[redacted]") }
	switch action {
	case "auth":
		var value struct {
			Data map[string]struct {
				Type        string `json:"type"`
				Description string `json:"description"`
				Config      struct {
					DefaultTTL *int64 `json:"default_lease_ttl"`
					MaxTTL     *int64 `json:"max_lease_ttl"`
				} `json:"config"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil || value.Data == nil || len(value.Data) > 1024 {
			return result, invalid
		}
		result.Methods = []AuthMethod{}
		for name, entry := range value.Data {
			if len(name) > 1024 || entry.Type == "" || len(entry.Type) > 128 || len(entry.Description) > 2048 {
				return AccessResult{}, invalid
			}
			result.Methods = append(result.Methods, AuthMethod{Path: redact(name), Type: redact(entry.Type), Description: redact(entry.Description), DefaultTTL: entry.Config.DefaultTTL, MaxTTL: entry.Config.MaxTTL})
		}
		sort.Slice(result.Methods, func(i, j int) bool { return result.Methods[i].Path < result.Methods[j].Path })
	case "policies":
		var value struct {
			Keys []string `json:"keys"`
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil {
			return result, invalid
		}
		names := value.Data.Keys
		if names == nil {
			names = value.Keys
		}
		if names == nil || len(names) > 1000 {
			return result, invalid
		}
		for _, name := range names {
			if len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") {
				return AccessResult{}, invalid
			}
			result.Policies = append(result.Policies, redact(name))
		}
		sort.Strings(result.Policies)
	case "policy":
		var value struct {
			Policy *string `json:"policy"`
			Data   struct {
				Policy *string `json:"policy"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil {
			return result, invalid
		}
		source := value.Data.Policy
		if source == nil {
			source = value.Policy
		}
		if source == nil || len(*source) > 65536 {
			return result, invalid
		}
		clean := redact(*source)
		result.Name = input.Name
		result.Redacted = clean != *source
		result.Policy = &clean
	case "capabilities":
		var value map[string]json.RawMessage
		if json.Unmarshal(data, &value) != nil {
			return result, invalid
		}
		values := value
		if nested, ok := value["data"]; ok {
			values = nil
			if json.Unmarshal(nested, &values) != nil {
				return result, invalid
			}
		}
		result.Capabilities = map[string][]string{}
		for _, path := range input.Paths {
			var capabilities []string
			if json.Unmarshal(values[path], &capabilities) != nil || len(capabilities) == 0 || len(capabilities) > 32 {
				return AccessResult{}, invalid
			}
			for _, capability := range capabilities {
				if !knownCapability(capability) {
					return AccessResult{}, invalid
				}
			}
			result.Capabilities[redact(path)] = capabilities
		}
	}
	return result, nil
}

// Unknown capabilities require explicit compatibility work, not a fabricated
// preview. These are the documented ACL verbs plus root/deny result markers.
func knownCapability(value string) bool {
	switch value {
	case "create", "read", "update", "patch", "delete", "list", "sudo", "deny", "root", "subscribe", "recover":
		return true
	}
	return false
}
