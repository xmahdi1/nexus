package ansible

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/xmahdi1/nexus/internal/vault"
)

var ErrInput = errors.New("invalid Ansible project or target plan")
var ErrDenied = errors.New("Ansible access unavailable")
var ErrConflict = errors.New("Ansible revision or plan changed")
var ErrDisabled = errors.New("automation is disabled")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var variablePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var pinPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func safeText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r") && !strings.Contains(value, "{{") && !strings.Contains(value, "{%") && !strings.Contains(value, "{#")
}
func reservedVariable(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "ansible_") || strings.HasPrefix(lower, "nexus_") {
		return true
	}
	switch lower {
	case "inventory_hostname", "inventory_hostname_short", "inventory_dir", "inventory_file", "hostvars", "groups", "group_names", "playbook_dir", "role_path", "omit", "environment", "vars":
		return true
	}
	return false
}

var collectionPart = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var collectionVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$`)
var collectionHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ValidateBundle(bundle Bundle) error {
	if len(bundle.Collections) > 4 {
		return ErrInput
	}
	names := map[string]bool{}
	for _, c := range bundle.Collections {
		key := c.Namespace + "." + c.Name
		if !collectionPart.MatchString(c.Namespace) || !collectionPart.MatchString(c.Name) || !collectionVersion.MatchString(c.Version) || !collectionHash.MatchString(c.SHA256) || names[key] || key == "ansible.builtin" || key == "ansible.legacy" {
			return ErrInput
		}
		names[key] = true
	}

	if len(bundle.Files) < 1 || len(bundle.Files) > 32 || len(bundle.Variables) > 25 || bundle.Files[bundle.Main] == "" || (!strings.HasSuffix(bundle.Main, ".yml") && !strings.HasSuffix(bundle.Main, ".yaml")) {
		return ErrInput
	}
	size := 0
	for name, content := range bundle.Files {
		if len(bundle.Collections) > 0 && (name == "collections" || strings.HasPrefix(name, "collections/")) {
			return ErrInput
		}
		if len(name) > 200 || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, "\\\r\n\x00") || len(content) > 16384 || !utf8.ValidString(content) || strings.ContainsRune(content, 0) {
			return ErrInput
		}
		for _, part := range strings.Split(name, "/") {
			if part == "" || strings.HasPrefix(part, ".") || part == "ansible.cfg" {
				return ErrInput
			}
		}
		size += len(content) + len(name)
	}
	if size > 32768 {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, v := range bundle.Variables {
		if !variablePattern.MatchString(v.Name) || reservedVariable(v.Name) || seen[v.Name] {
			return ErrInput
		}
		seen[v.Name] = true
		switch v.Kind {
		case "string", "integer", "boolean", "vault":
			if len(v.Choices) != 0 {
				return ErrInput
			}
		case "choice":
			if len(v.Choices) < 1 || len(v.Choices) > 16 {
				return ErrInput
			}
			choices := map[string]bool{}
			for _, c := range v.Choices {
				if !safeText(c, 256) || choices[c] {
					return ErrInput
				}
				choices[c] = true
			}
		default:
			return ErrInput
		}
	}
	return nil
}
func validateReference(value any) (VaultReference, error) {
	var ref VaultReference
	data, err := json.Marshal(value)
	if err != nil {
		return ref, ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ref) != nil || !idPattern.MatchString(ref.ServerID) || !variablePattern.MatchString(ref.Field) || ref.Version < 1 || (vault.KVRequest{Token: "reference", Mount: ref.Mount, Path: ref.Path}).Validate("read") != nil {
		return VaultReference{}, ErrInput
	}
	return ref, nil
}
func Variables(bundle Bundle, values map[string]any) (map[string]any, error) {
	if len(values) > 25 {
		return nil, ErrInput
	}
	out := map[string]any{}
	for _, schema := range bundle.Variables {
		value, ok := values[schema.Name]
		if !ok {
			if schema.Required {
				return nil, ErrInput
			}
			continue
		}
		switch schema.Kind {
		case "string", "choice":
			text, ok := value.(string)
			if !ok || !safeText(text, 1024) {
				return nil, ErrInput
			}
			if schema.Kind == "choice" {
				found := false
				for _, c := range schema.Choices {
					found = found || c == text
				}
				if !found {
					return nil, ErrInput
				}
			}
			out[schema.Name] = text
		case "boolean":
			if _, ok := value.(bool); !ok {
				return nil, ErrInput
			}
			out[schema.Name] = value
		case "integer":
			var n float64
			switch v := value.(type) {
			case json.Number:
				var err error
				n, err = v.Float64()
				if err != nil {
					return nil, ErrInput
				}
			case float64:
				n = v
			default:
				return nil, ErrInput
			}
			if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < -1e9 || n > 1e9 {
				return nil, ErrInput
			}
			out[schema.Name] = int64(n)
		case "vault":
			ref, err := validateReference(value)
			if err != nil {
				return nil, err
			}
			out[schema.Name] = ref
		default:
			return nil, ErrInput
		}
	}
	if len(out) != len(values) {
		return nil, ErrInput
	}
	return out, nil
}
func validateOptions(options Options) error {
	if options.Mode != "check" && options.Mode != "apply" && options.Mode != "syntax" {
		return ErrInput
	}
	if options.TimeoutSeconds < 10 || options.TimeoutSeconds > 600 || options.Verbosity < 0 || options.Verbosity > 2 || len(options.Tags) > 16 || len(options.SkipTags) > 16 {
		return ErrInput
	}
	for _, tag := range append(append([]string{}, options.Tags...), options.SkipTags...) {
		if !tagPattern.MatchString(tag) {
			return ErrInput
		}
	}
	if options.VaultPassword != nil {
		if _, err := validateReference(options.VaultPassword); err != nil {
			return err
		}
	}
	return nil
}
