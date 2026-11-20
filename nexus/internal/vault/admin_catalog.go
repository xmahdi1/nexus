package vault

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// AdminField describes a fixed, typed form field. It never selects an HTTP
// method or an arbitrary upstream endpoint.
type AdminField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`
	Required bool     `json:"required"`
	Choices  []string `json:"choices,omitempty"`
}

type AdminOperation struct {
	ID          string       `json:"id"`
	Group       string       `json:"group"`
	Label       string       `json:"label"`
	Notice      string       `json:"notice"`
	Fields      []AdminField `json:"fields"`
	Permissions []string     `json:"permissions"`
	Mutation    bool         `json:"mutation"`
	Sensitive   bool         `json:"sensitive"`
	mountType   string
	authType    string
}

type AdminRequest struct {
	Token        string                     `json:"token"`
	Params       map[string]json.RawMessage `json:"params"`
	Confirmation string                     `json:"confirmation,omitempty"`
}

func field(key, label, kind string, required bool, choices ...string) AdminField {
	return AdminField{key, label, kind, required, choices}
}
func fields(values ...AdminField) []AdminField { return values }

var mountField = field("mount", "Mount path (without a trailing slash)", "path", true)
var nameField = field("name", "Name", "name", true)
var pathField = field("path", "Secret path", "path", true)
var versionFields = fields(mountField, pathField, field("versions", "Versions (one per line)", "versions", true))
var policyFields = fields(nameField, field("revision", "Revision from Read policy, or missing for a new policy", "revision", true))
var ttlField = field("ttl", "TTL in seconds (maximum 86400)", "seconds", true)
var certificateTTLField = field("ttl", "Certificate lifetime in seconds (maximum 10 years; also limited by the issuer and mount)", "duration", true)
var tokenPolicyField = field("policies", "Policies (one per line, never root)", "policies", true)
var roleFields = fields(mountField, nameField, tokenPolicyField, ttlField)

var ErrInvalidAdmin = errors.New("invalid Vault management fields; check the required fields, bounds and confirmation")
var adminUUIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

func (r AdminRequest) Validate(op AdminOperation) error {
	_, err := r.values(op)
	return err
}
func (r AdminRequest) values(op AdminOperation) (map[string]any, error) {
	if r.Token == "" || len(r.Token) > 8192 || strings.ContainsAny(r.Token, "\r\n\x00") || len(r.Params) > 32 || (op.Mutation && r.Confirmation != op.ID) || (!op.Mutation && r.Confirmation != "") {
		return nil, ErrInvalidAdmin
	}
	v := map[string]any{}
	for _, f := range op.Fields {
		raw, ok := r.Params[f.Key]
		if !ok {
			if f.Required {
				return nil, ErrInvalidAdmin
			}
			continue
		}
		if len(raw) > 90000 || string(raw) == "null" {
			return nil, ErrInvalidAdmin
		}
		switch f.Kind {
		case "seconds", "positive", "nonnegative", "duration", "inherited-duration", "retention":
			var n json.Number
			if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' || json.Unmarshal(raw, &n) != nil {
				return nil, ErrInvalidAdmin
			}
			i, e := strconv.ParseInt(string(n), 10, 32)
			min := int64(1)
			if f.Kind == "nonnegative" || f.Kind == "inherited-duration" {
				min = 0
			}
			max := int64(86400)
			if f.Kind == "positive" {
				max = 2147483647
			}
			if f.Kind == "duration" || f.Kind == "inherited-duration" {
				max = 315360000
			}
			if f.Kind == "retention" {
				max = 1000
			}
			if e != nil || i < min || i > max {
				return nil, ErrInvalidAdmin
			}
			v[f.Key] = i
		case "policies", "versions", "strings", "domains", "ids":
			if f.Kind == "versions" {
				var ns []int64
				if json.Unmarshal(raw, &ns) != nil || len(ns) == 0 || len(ns) > 64 {
					return nil, ErrInvalidAdmin
				}
				seen := map[int64]bool{}
				for _, n := range ns {
					if n < 1 || n > 2147483647 || seen[n] {
						return nil, ErrInvalidAdmin
					}
					seen[n] = true
				}
				v[f.Key] = ns
			} else {
				var ss []string
				if json.Unmarshal(raw, &ss) != nil || len(ss) > 64 || (f.Required && len(ss) == 0) {
					return nil, ErrInvalidAdmin
				}
				for _, s := range ss {
					if len(s) == 0 || len(s) > 1024 || strings.ContainsAny(s, "\x00\r\n") {
						return nil, ErrInvalidAdmin
					}
					if f.Kind == "policies" && (!policyPattern.MatchString(s) || s == "root" || s == "." || s == "..") {
						return nil, ErrInvalidAdmin
					}
					if f.Kind == "domains" && !validAdminDomain(s) {
						return nil, ErrInvalidAdmin
					}
					if f.Kind == "ids" && !adminUUIDPattern.MatchString(s) {
						return nil, ErrInvalidAdmin
					}
				}
				v[f.Key] = ss
			}
		case "bool":
			var b bool
			if json.Unmarshal(raw, &b) != nil {
				return nil, ErrInvalidAdmin
			}
			v[f.Key] = b
		default:
			var s string
			if json.Unmarshal(raw, &s) != nil || strings.ContainsRune(s, 0) || (f.Required && s == "") {
				return nil, ErrInvalidAdmin
			}
			valid := true
			switch f.Kind {
			case "path", "prefix":
				valid = safeKVPath(s, f.Kind == "prefix")
			case "name":
				valid = policyPattern.MatchString(s) && s != "." && s != ".."
			case "identifier":
				valid = len(s) <= 512 && !strings.ContainsAny(s, "\r\n\t /?%#\\")
			case "revision":
				valid = s == "missing" || (len(s) == 64 && strings.Trim(s, "abcdef0123456789") == "")
			case "uuid":
				valid = adminUUIDPattern.MatchString(s)
			case "domain":
				valid = validAdminDomain(s)
			case "serial":
				valid = len(s) <= 128 && len(s) > 0 && strings.Trim(s, "abcdefABCDEF0123456789:-") == ""
			case "csr":
				valid = validAdminPEM(s, true)
			case "certificates":
				valid = validAdminPEM(s, false)
			case "text", "pem":
				valid = len(s) <= 65536
			case "password":
				valid = len(s) <= 4096
			case "choice":
				valid = false
				for _, c := range f.Choices {
					if s == c {
						valid = true
					}
				}
			default:
				valid = len(s) <= 2048 && !strings.ContainsAny(s, "\r\n")
			}
			if !valid {
				return nil, ErrInvalidAdmin
			}
			v[f.Key] = s
		}
	}
	if len(v) != len(r.Params) {
		return nil, ErrInvalidAdmin
	}
	if op.ID == "policy-save" || op.ID == "policy-delete" {
		if v["name"] == "root" || v["name"] == "default" {
			return nil, ErrInvalidAdmin
		}
	}
	if v["default_lease_ttl"] != nil && v["max_lease_ttl"] != nil {
		a, b := v["default_lease_ttl"].(int64), v["max_lease_ttl"].(int64)
		if b != 0 && a > b {
			return nil, ErrInvalidAdmin
		}
	}
	return v, nil
}

func validAdminDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func validAdminPEM(s string, csr bool) bool {
	if len(s) == 0 || len(s) > 65536 {
		return false
	}
	remaining := []byte(strings.TrimSpace(s))
	count := 0
	for len(remaining) > 0 {
		typ := "CERTIFICATE"
		if csr {
			typ = "CERTIFICATE REQUEST"
		}
		if !bytesHasPEMPrefix(remaining, typ) {
			return false
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != typ || len(block.Headers) != 0 {
			return false
		}
		if csr {
			request, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || request.CheckSignature() != nil {
				return false
			}
		} else {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return false
			}
		}
		count++
		if count > 16 || (csr && count > 1) {
			return false
		}
		remaining = []byte(strings.TrimSpace(string(rest)))
	}
	return count > 0
}
func bytesHasPEMPrefix(value []byte, typ string) bool {
	return strings.HasPrefix(string(value), "-----BEGIN "+typ+"-----")
}
