package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrDenied        = errors.New("Vault denied access to this operation")
	ErrNotFound      = errors.New("Vault resource was not found")
	ErrConflict      = errors.New("Vault rejected the write; refresh metadata before trying again")
	ErrRemoteUnknown = errors.New("Vault write outcome is unknown; inspect remote metadata before retrying")
)

// KVRequest deliberately excludes arbitrary URLs, methods and upstream paths.
// Version is mandatory for writes: zero means create only, never overwrite.
type KVRequest struct {
	Token   string          `json:"token"`
	Mount   string          `json:"mount"`
	Path    string          `json:"path"`
	Version *int            `json:"version,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9_@.-]+$`)

func safeKVPath(value string, empty bool) bool {
	if value == "" {
		return empty
	}
	if len(value) > 1024 {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || !segmentPattern.MatchString(segment) {
			return false
		}
	}
	return true
}
func (r KVRequest) Validate(action string) error {
	if len(r.Token) == 0 || len(r.Token) > 8192 || strings.ContainsAny(r.Token, "\r\n\x00") || !safeKVPath(r.Mount, false) || !safeKVPath(r.Path, action == "list") {
		return errors.New("invalid Vault KV request")
	}
	switch action {
	case "list", "metadata", "read":
		if r.Version != nil || len(r.Data) != 0 {
			return errors.New("unexpected Vault KV fields")
		}
	case "write":
		if r.Version == nil || *r.Version < 0 || *r.Version > 2147483646 || len(r.Data) == 0 || len(r.Data) > 65536 {
			return errors.New("a bounded JSON object and expected version are required")
		}
		var value map[string]json.RawMessage
		if json.Unmarshal(r.Data, &value) != nil || value == nil || len(value) > 256 || !boundedJSONDepth(r.Data) {
			return errors.New("Vault data must be a bounded JSON object")
		}
		if !vaultSafeNumbers(r.Data) {
			return errors.New("JSON numbers would lose precision in Vault; use strings for exact values")
		}
	default:
		return errors.New("unsupported Vault KV operation")
	}
	return nil
}

// This slice reports the version only. Version history/deletion state require
// their own handling; do not invent those fields from default zero values.
type KVMetadata struct {
	Version int `json:"version"`
}

type KVResult struct {
	Keys                  []string        `json:"keys,omitempty"`
	Metadata              *KVMetadata     `json:"metadata,omitempty"`
	Data                  json.RawMessage `json:"data,omitempty"`
	AutomaticRetryAllowed bool            `json:"automaticRetryAllowed"`
}

// KV authenticates and verifies the requested mount on every operation. It does
// not assume a mount is still KV v2 because the browser previously displayed it.
func KV(ctx context.Context, client *http.Client, p Profile, action string, input KVRequest, beforeWrite func() bool) (KVResult, error) {
	result := KVResult{}
	if err := input.Validate(action); err != nil {
		return result, err
	}
	inventory, err := Inspect(ctx, client, p, input.Token)
	if err != nil {
		return result, err
	}
	if inventory.MountsStatus != "ok" {
		return result, ErrDenied
	}
	found := false
	for _, mount := range inventory.Mounts {
		if mount.Path == input.Mount+"/" && mount.Type == "kv" && mount.Version == "2" {
			found = true
		}
	}
	if !found {
		return result, errors.New("select an accessible KV-v2 mount")
	}
	path := "/v1/" + input.Mount + "/metadata/" + input.Path
	if action == "read" || action == "write" {
		path = "/v1/" + input.Mount + "/data/" + input.Path
	}
	if action == "list" {
		path += "?list=true"
	}
	method := "GET"
	var payload []byte
	if action == "write" {
		method = "POST"
		payload, err = json.Marshal(map[string]any{"options": map[string]int{"cas": *input.Version}, "data": input.Data})
		if err != nil {
			return result, errors.New("invalid Vault write data")
		}
		defer clear(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+p.TLSName+path, bytes.NewReader(payload))
	if err != nil {
		return result, errors.New("invalid Vault KV request")
	}
	req.Header.Set("X-Vault-Token", input.Token)
	if p.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.Namespace)
	}
	if action == "write" {
		req.Header.Set("Content-Type", "application/json")
		if beforeWrite == nil || !beforeWrite() {
			return result, ErrDenied
		}
	}
	response, err := client.Do(req)
	if err != nil {
		if action == "write" {
			return result, ErrRemoteUnknown
		}
		return result, errors.New("Vault KV transport failed")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case 200:
	case 401, 403:
		return result, ErrDenied
	case 404:
		return result, ErrNotFound
	case 400:
		if action == "write" {
			return result, ErrConflict
		}
		return result, errors.New("Vault rejected the KV request")
	default:
		if action == "write" {
			return result, ErrRemoteUnknown
		}
		return result, errors.New("Vault KV request failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 131073))
	defer clear(data)
	invalid := func() (KVResult, error) {
		if action == "write" {
			return result, ErrRemoteUnknown
		}
		return result, errors.New("invalid or oversized Vault KV response")
	}
	if err != nil || len(data) > 131072 {
		return invalid()
	}
	switch action {
	case "list":
		var value struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil || len(value.Data.Keys) > 1000 {
			return invalid()
		}
		for _, key := range value.Data.Keys {
			if !safeKVPath(strings.TrimSuffix(key, "/"), false) {
				return invalid()
			}
		}
		result.Keys = value.Data.Keys
	case "metadata":
		var value struct {
			Data struct {
				Version int `json:"current_version"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil || value.Data.Version < 1 {
			return invalid()
		}
		// Return only current version metadata, never custom metadata or values.
		result.Metadata = &KVMetadata{Version: value.Data.Version}
	case "read":
		var value struct {
			Data struct {
				Value    json.RawMessage `json:"data"`
				Metadata struct {
					Version int `json:"version"`
				} `json:"metadata"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil || len(value.Data.Value) > 65536 || value.Data.Metadata.Version < 1 {
			return invalid()
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(value.Data.Value, &object) != nil || object == nil || !boundedJSONDepth(value.Data.Value) {
			return invalid()
		}
		result.Data = value.Data.Value
		result.Metadata = &KVMetadata{Version: value.Data.Metadata.Version}
	case "write":
		var value struct {
			Data struct {
				Version int `json:"version"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &value) != nil || value.Data.Version != *input.Version+1 {
			return invalid()
		}
		result.Metadata = &KVMetadata{Version: value.Data.Version}
	}
	return result, nil
}

func boundedJSONDepth(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return depth == 0
		}
		if err != nil {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
				if depth > 32 {
					return false
				}
			case '}', ']':
				depth--
			}
		}
	}
}

// Vault's KV backend normalizes JSON numbers through float64. Compare decimal
// values with the shortest float64 round trip before sending a write. ParseFloat
// runs first and zero is handled separately to avoid allocating enormous powers
// of ten from an untrusted exponent in big.Rat.SetString.
func vaultSafeNumbers(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		number, ok := token.(json.Number)
		if !ok {
			continue
		}
		text := number.String()
		if len(text) > 128 {
			return false
		}
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return false
		}
		if value == 0 {
			mantissa := strings.SplitN(strings.ToLower(text), "e", 2)[0]
			if strings.ContainsAny(mantissa, "123456789") {
				return false
			}
			continue
		}
		original, ok := new(big.Rat).SetString(text)
		if !ok {
			return false
		}
		roundTrip, ok := new(big.Rat).SetString(strconv.FormatFloat(value, 'g', -1, 64))
		if !ok || original.Cmp(roundTrip) != 0 {
			return false
		}
	}
}
