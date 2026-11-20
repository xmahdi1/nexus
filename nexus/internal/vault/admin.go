package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
)

type AdminResult struct {
	DataJSON              string `json:"dataJson"`
	Revision              string `json:"revision,omitempty"`
	Redacted              bool   `json:"redacted,omitempty"`
	AutomaticRetryAllowed bool   `json:"automaticRetryAllowed"`
}

type adminPlan struct {
	method, path string
	body         map[string]any
	keys         string
	auth         bool
	resourceMap  bool
}

// adminRPC never returns upstream error text. No redirects or application retries
// are made, including for mutating GET endpoints and lost acknowledgement bodies.
func adminRPC(ctx context.Context, c *http.Client, p Profile, token, method, path string, body map[string]any, mutation bool, guard func() bool) (map[string]json.RawMessage, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, ErrInvalidAdmin
		}
		defer clear(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+p.TLSName+path, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("Vault management request failed")
	}
	req.Header.Set("X-Vault-Token", token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// A mutating GET must not be retried by net/http on an ambiguous transport
	// failure. NewClient also disables keep-alive; this blocks method-based replay
	// even if a caller supplies a reusable transport in tests.
	if mutation {
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.GetBody = nil
	}
	if mutation && (guard == nil || !guard() || ctx.Err() != nil) {
		return nil, ErrDenied
	}
	res, err := c.Do(req)
	if err != nil {
		if mutation {
			return nil, ErrRemoteUnknown
		}
		return nil, errors.New("Vault management transport unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return nil, ErrDenied
	}
	if res.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if res.StatusCode == 400 || res.StatusCode == 409 || res.StatusCode == 412 {
		return nil, ErrConflict
	}
	if res.StatusCode != 200 && res.StatusCode != 204 {
		if mutation {
			return nil, ErrRemoteUnknown
		}
		return nil, errors.New("Vault management unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 1048577))
	defer clear(data)
	invalid := errors.New("invalid or oversized Vault management response")
	if mutation {
		invalid = ErrRemoteUnknown
	}
	if err != nil || len(data) > 1048576 {
		return nil, invalid
	}
	if res.StatusCode == 204 {
		if len(bytes.TrimSpace(data)) != 0 {
			return nil, invalid
		}
		return map[string]json.RawMessage{}, nil
	}
	var value map[string]json.RawMessage
	if !boundedJSONDepth(data) || json.Unmarshal(data, &value) != nil || value == nil {
		return nil, invalid
	}
	return value, nil
}

func adminData(raw map[string]json.RawMessage, auth bool) (map[string]json.RawMessage, error) {
	key := "data"
	if auth {
		key = "auth"
	}
	if v, ok := raw[key]; ok {
		var data map[string]json.RawMessage
		if json.Unmarshal(v, &data) != nil || data == nil {
			return nil, errors.New("incomplete Vault management response")
		}
		return data, nil
	}
	// Vault's system endpoints also expose legacy root aliases.
	if !auth {
		return raw, nil
	}
	return nil, errors.New("incomplete Vault management response")
}

func selectAdmin(data map[string]json.RawMessage, keys string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, key := range strings.Fields(keys) {
		if value, ok := data[key]; ok {
			out[key] = value
		}
	}
	return out
}

func verifyAdminMount(ctx context.Context, c *http.Client, p Profile, token, mount, expected string, auth bool) error {
	path := "/v1/sys/mounts"
	if auth {
		path = "/v1/sys/auth"
	}
	raw, err := adminRPC(ctx, c, p, token, "GET", path, nil, false, nil)
	if err != nil {
		return err
	}
	data, err := adminData(raw, false)
	if err != nil {
		return err
	}
	var m struct {
		Type    string            `json:"type"`
		Options map[string]string `json:"options"`
	}
	if json.Unmarshal(data[mount+"/"], &m) != nil || m.Type == "" {
		return ErrNotFound
	}
	if m.Type != expected || (expected == "kv" && m.Options["version"] != "2") {
		return ErrConflict
	}
	return nil
}

// Admin executes only a registered operation. Every mutation checks the current
// Nexus session immediately before its dispatch. Upstream Vault ACLs remain the
// final authority. Caller tokens and values are never persisted here.
func Admin(ctx context.Context, c *http.Client, p Profile, id string, input AdminRequest, guard func() bool) (AdminResult, error) {
	result := AdminResult{}
	if p.Namespace != "" {
		return result, ErrInvalidAdmin
	}
	op, ok := AdminOperationByID(id)
	if !ok {
		return result, ErrInvalidAdmin
	}
	v, err := input.values(op)
	if err != nil {
		return result, err
	}
	allowed, err := checkToken(ctx, c, p, input.Token)
	if err != nil {
		return result, err
	}
	if !allowed {
		return result, ErrDenied
	}
	if op.mountType != "" || op.authType != "" {
		typ := op.mountType
		if op.authType != "" {
			typ = op.authType
		}
		if err = verifyAdminMount(ctx, c, p, input.Token, v["mount"].(string), typ, op.authType != ""); err != nil {
			return result, err
		}
	}
	if id == "policy-read" || id == "policy-save" || id == "policy-delete" {
		return adminPolicy(ctx, c, p, op, input, v, guard)
	}
	plan, err := buildAdminPlan(op, v)
	if err != nil {
		return result, err
	}
	if id == "identity-alias-save" {
		raw, e := adminRPC(ctx, c, p, input.Token, "GET", "/v1/sys/auth", nil, false, nil)
		if e != nil {
			return result, e
		}
		data, e := adminData(raw, false)
		if e != nil {
			return result, e
		}
		var method struct {
			Accessor string `json:"accessor"`
		}
		if json.Unmarshal(data[v["mount"].(string)+"/"], &method) != nil || method.Accessor == "" {
			return result, ErrNotFound
		}
		plan.body["mount_accessor"] = method.Accessor
	}
	if id == "engine-disable" || id == "auth-disable" {
		mount, typ := v["mount"].(string), v["expected_type"].(string)
		if mount == "sys" || mount == "identity" || mount == "cubbyhole" || (id == "auth-disable" && (mount == "token" || typ == "token")) {
			return result, ErrInvalidAdmin
		}
		if err = verifyAdminMount(ctx, c, p, input.Token, mount, typ, id == "auth-disable"); err != nil {
			return result, err
		}
	}
	if id == "audit-disable" {
		raw, e := adminRPC(ctx, c, p, input.Token, "GET", "/v1/sys/audit", nil, false, nil)
		if e != nil {
			return result, e
		}
		data, e := adminData(raw, false)
		if e != nil {
			return result, e
		}
		if len(data) < 2 || data[v["name"].(string)+"/"] == nil {
			return result, ErrConflict
		}
	}
	raw, err := adminRPC(ctx, c, p, input.Token, plan.method, plan.path, plan.body, op.Mutation, guard)
	if err != nil {
		return result, err
	}
	if len(raw) == 0 || (op.Mutation && !adminRequiresResult(id) && bytes.Equal(bytes.TrimSpace(raw["data"]), []byte("null"))) {
		if !op.Mutation || adminRequiresResult(id) {
			if op.Mutation {
				return result, ErrRemoteUnknown
			}
			return result, errors.New("incomplete Vault management response")
		}
		result.DataJSON = `{"acknowledged":true}`
		return result, nil
	}
	var data map[string]json.RawMessage
	if id == "lease-renew" {
		data = raw
	} else {
		data, err = adminData(raw, plan.auth)
	}
	if err != nil {
		if op.Mutation {
			err = ErrRemoteUnknown
		}
		return result, err
	}
	selected := selectAdmin(data, plan.keys)
	if plan.resourceMap {
		if len(data) > 1024 {
			return result, errors.New("Vault inventory is oversized")
		}
		selected = map[string]json.RawMessage{}
		for name, item := range data {
			if len(name) > 1024 {
				return result, errors.New("invalid Vault resource name")
			}
			var entry map[string]json.RawMessage
			if json.Unmarshal(item, &entry) != nil {
				return result, errors.New("invalid Vault resource metadata")
			}
			value, _ := json.Marshal(selectAdmin(entry, plan.keys))
			selected[name] = value
		}
	}
	// An empty/malformed success after a mutation is not proof that it failed.
	if op.Mutation && adminRequiresResult(id) && len(selected) == 0 {
		return result, ErrRemoteUnknown
	}
	if id == "token-create" {
		var issued string
		var policies []string
		var ttl int64
		if json.Unmarshal(selected["client_token"], &issued) != nil || issued == "" || len(issued) > 8192 || strings.ContainsAny(issued, "\r\n\x00") || json.Unmarshal(selected["policies"], &policies) != nil || policies == nil || json.Unmarshal(selected["lease_duration"], &ttl) != nil || ttl < 1 || ttl > 86400 {
			return result, ErrRemoteUnknown
		}
		for _, policy := range policies {
			if policy == "root" {
				return result, ErrRemoteUnknown
			}
		}
	}
	if id == "approle-secret-id" {
		var issued string
		if json.Unmarshal(selected["secret_id"], &issued) != nil || issued == "" {
			return result, ErrRemoteUnknown
		}
	}
	if id == "pki-issue" {
		var key, certificate string
		if json.Unmarshal(selected["private_key"], &key) != nil || key == "" || json.Unmarshal(selected["certificate"], &certificate) != nil || certificate == "" {
			return result, ErrRemoteUnknown
		}
	}
	if !op.Mutation && !plan.resourceMap && len(selected) == 0 {
		return result, errors.New("incomplete Vault management response")
	}
	encoded, _ := json.Marshal(selected)
	// Keep the browser out of the numeric round-trip. Recursive sanitation keeps
	// JSON valid even when the supplied credential contains JSON metacharacters.
	var clean any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&clean) != nil {
		return result, errors.New("invalid Vault management result")
	}
	clean, result.Redacted = redactAdmin(clean, input.Token)
	encoded, _ = json.MarshalIndent(clean, "", "  ")
	result.DataJSON = string(encoded)
	return result, nil
}

func adminRequiresResult(id string) bool {
	switch id {
	case "token-create", "token-renew", "token-self-renew", "approle-secret-id", "pki-root-generate", "pki-intermediate-generate", "pki-intermediate-sign", "pki-intermediate-import", "pki-issue", "pki-sign", "pki-revoke", "pki-crl-rotate", "lease-renew":
		return true
	}
	return false
}

func redactAdmin(value any, token string) (any, bool) {
	changed := false
	switch v := value.(type) {
	case string:
		clean := strings.ReplaceAll(v, token, "[redacted]")
		return clean, clean != v
	case []any:
		for i, x := range v {
			var b bool
			v[i], b = redactAdmin(x, token)
			changed = changed || b
		}
	case map[string]any:
		// Sorted traversal plus explicit collision rejection avoids allowing a
		// reflected credential in an object key to replace another field.
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := map[string]any{}
		for _, key := range keys {
			x, b := redactAdmin(v[key], token)
			clean := strings.ReplaceAll(key, token, "[redacted]")
			changed = changed || b || clean != key
			if _, ok := out[clean]; ok {
				return "[redacted object]", true
			}
			out[clean] = x
		}
		return out, changed
	}
	return value, changed
}

func adminPolicy(ctx context.Context, c *http.Client, p Profile, op AdminOperation, input AdminRequest, v map[string]any, guard func() bool) (AdminResult, error) {
	result := AdminResult{}
	name := v["name"].(string)
	raw, err := adminRPC(ctx, c, p, input.Token, "GET", "/v1/sys/policies/acl/"+name, nil, false, nil)
	revision, source := "missing", ""
	if err != nil && !errors.Is(err, ErrNotFound) {
		return result, err
	}
	if err == nil {
		data, e := adminData(raw, false)
		if e != nil {
			return result, e
		}
		if json.Unmarshal(data["policy"], &source) != nil || len(source) > 65536 {
			return result, errors.New("invalid Vault policy response")
		}
		digest := sha256.Sum256([]byte(source))
		revision = hex.EncodeToString(digest[:])
	}
	if op.ID == "policy-read" {
		clean := strings.ReplaceAll(source, input.Token, "[redacted]")
		result.Redacted = clean != source
		if !result.Redacted {
			result.Revision = revision
		}
		value, _ := json.MarshalIndent(map[string]any{"name": name, "exists": revision != "missing", "policy": clean}, "", "  ")
		result.DataJSON = string(value)
		return result, nil
	}
	if v["revision"] != revision || strings.Contains(source, input.Token) {
		return result, ErrConflict
	}
	method := "PUT"
	var body map[string]any
	if op.ID == "policy-save" {
		body = map[string]any{"policy": v["policy"]}
	} else {
		method = "DELETE"
		if revision == "missing" {
			return result, ErrNotFound
		}
	}
	_, err = adminRPC(ctx, c, p, input.Token, method, "/v1/sys/policies/acl/"+name, body, true, guard)
	if err != nil {
		return result, err
	}
	result.DataJSON = `{"acknowledged":true}`
	return result, nil
}
