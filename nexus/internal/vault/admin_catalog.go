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

// The same catalog registers the router, Nexus authorization and guided UI.
// Adding a capability requires an explicit operation, schema and implementation.
var adminOperations = func() []AdminOperation {
	var out []AdminOperation
	add := func(id, group, label, notice, permission string, mutation, sensitive bool, fs []AdminField) {
		p := strings.Fields("integrations.manage servers.connect secrets.use " + permission)
		if sensitive {
			p = append(p, "secrets.reveal")
		}
		out = append(out, AdminOperation{ID: id, Group: group, Label: label, Notice: notice, Fields: fs, Permissions: p, Mutation: mutation, Sensitive: sensitive})
	}
	add("policy-read", "Policies", "Read policy and revision", "Read before editing. The revision check detects earlier changes; Vault has no atomic policy compare-and-set.", "roles.manage", false, false, fields(nameField))
	add("policy-save", "Policies", "Save ACL policy", "Changes can grant or remove Vault access. Coordinate with other administrators: the revision check is not atomic. Built-in root/default policies are protected.", "roles.manage", true, false, append(append([]AdminField{}, policyFields...), field("policy", "ACL policy source (HCL or JSON)", "text", true)))
	add("policy-delete", "Policies", "Delete ACL policy", "Existing tokens using this policy lose its permissions. Coordinate concurrent edits. Built-in policies are protected.", "roles.manage", true, false, policyFields)
	add("kv-history", "Secret versions", "Inspect version history", "Metadata only; secret values are not returned.", "secrets.metadata.read", false, false, fields(mountField, pathField))
	add("kv-version", "Secret versions", "Reveal a secret version", "Values are displayed for this request only. Hide them when finished.", "secrets.metadata.read", false, true, fields(mountField, pathField, field("version", "Version", "positive", true)))
	for _, v := range []struct{ id, label, notice string }{{"kv-delete", "Soft-delete versions", "Soft-deleted versions can be undeleted until destroyed."}, {"kv-undelete", "Undelete versions", "Restores access to soft-deleted values; destroyed versions cannot be recovered."}, {"kv-destroy", "Permanently destroy versions", "IRREVERSIBLE: permanently removes the selected versions' secret values."}} {
		add(v.id, "Secret versions", v.label, v.notice, "secrets.rotate", true, false, versionFields)
	}
	add("kv-delete-metadata", "Secret versions", "Delete all versions and metadata", "IRREVERSIBLE: deletes every version and the metadata at this secret path.", "secrets.rotate", true, false, fields(mountField, pathField))
	add("kv-config-read", "Secret versions", "Read KV engine retention settings", "Engine-wide retention and compare-and-set defaults; no secret values.", "secrets.metadata.read", false, false, fields(mountField))
	add("kv-configure", "Secret versions", "Configure KV engine retention", "Reducing maximum versions can permanently remove old versions on future writes. This applies engine-wide. Nexus always sends compare-and-set on its own writes, even when the engine default is disabled.", "settings.manage secrets.rotate", true, false, fields(mountField, field("max_versions", "Maximum retained versions (1–1000)", "retention", true), field("cas_required", "Require compare-and-set for all clients", "bool", true), field("delete_version_after", "Automatically soft-delete after seconds (zero disables)", "inherited-duration", true)))
	add("engine-enable", "Engines", "Enable secrets engine", "Creates a built-in engine at a new path. KV engines are always version 2. Provider-specific engine configuration is separate.", "settings.manage", true, false, fields(mountField, field("type", "Engine type", "choice", true, "kv", "pki", "transit", "database", "ssh"), field("description", "Description", "string", false)))
	for _, group := range []string{"engine", "auth"} {
		label := "Engines"
		if group == "auth" {
			label = "Authentication"
		}
		add(group+"-tune-read", label, "Read "+group+" TTL settings", "Zero means inherit Vault's default TTL.", "settings.manage", false, false, fields(mountField))
		add(group+"-tune", label, "Change "+group+" TTL settings", "TTL changes apply according to Vault's lease rules; existing credentials may have their own limits.", "settings.manage", true, false, fields(mountField, field("default_lease_ttl", "Default TTL seconds (zero inherits)", "inherited-duration", true), field("max_lease_ttl", "Maximum TTL seconds (zero inherits)", "inherited-duration", true)))
		add(group+"-disable", label, "Disable "+group, "IRREVERSIBLE: revokes related leases and removes this mount's data or authentication configuration. Built-in mounts are protected.", "settings.manage roles.manage", true, false, fields(mountField, field("expected_type", "Currently observed mount type", "name", true)))
	}
	add("auth-enable", "Authentication", "Enable auth method", "Creates a local userpass or AppRole method. These methods are validated against the disposable Vault fixture.", "settings.manage roles.manage", true, false, fields(mountField, field("type", "Auth method type", "choice", true, "userpass", "approle"), field("description", "Description", "string", false)))
	for _, family := range []string{"userpass", "approle"} {
		group := "Authentication"
		add(family+"-list", group, "List "+family+" accounts/roles", "Names only; no passwords or secret IDs are returned.", "roles.manage", false, false, fields(mountField))
		add(family+"-read", group, "Read "+family+" account/role", "Selected role and token settings only.", "roles.manage", false, false, fields(mountField, nameField))
		fs := append([]AdminField{}, roleFields...)
		if family == "userpass" {
			fs = append(fs, field("password", "New password (leave empty to keep on an existing user)", "password", false))
		}
		add(family+"-save", group, "Save "+family+" account/role", "Saves explicit token policies and a bounded TTL. AppRole secret IDs require a separate generation action.", "roles.manage secrets.create", true, false, fs)
		add(family+"-delete", group, "Delete "+family+" account/role", "Removes this login configuration. Existing issued tokens follow Vault's revocation rules; inspect them separately.", "roles.manage", true, false, fields(mountField, nameField))
	}
	add("approle-role-id", "Authentication", "Read AppRole role ID", "Role ID is an identifier, not a secret ID.", "roles.manage", false, false, fields(mountField, nameField))
	add("approle-secret-id", "Authentication", "Generate one-use AppRole secret ID", "Generates a secret ID valid for at most one hour and one login. Displayed once; copy it to its intended consumer.", "roles.manage secrets.create", true, true, fields(mountField, nameField))
	add("approle-accessors", "Authentication", "List AppRole secret-ID accessors", "Accessors identify secret IDs without revealing their values.", "roles.manage", false, false, fields(mountField, nameField))
	add("approle-revoke-secret-id", "Authentication", "Revoke AppRole secret ID by accessor", "Prevents further logins using that secret ID. Existing issued tokens are separate.", "roles.manage secrets.rotate", true, false, fields(mountField, nameField, field("accessor", "Secret-ID accessor", "identifier", true)))
	add("token-self", "Tokens", "Inspect caller token", "Token value and arbitrary token metadata are excluded.", "secrets.metadata.read", false, false, nil)
	add("token-self-renew", "Tokens", "Renew caller token", "Requests a bounded renewal without returning the bearer token. Vault applies its original maximum lifetime.", "secrets.rotate", true, false, fields(field("increment", "Requested increment in seconds", "seconds", true)))
	add("token-self-revoke", "Tokens", "Revoke caller token", "Revokes this supplied Vault token, its children and its leases. It does not sign you out of Nexus.", "secrets.rotate", true, false, nil)
	add("token-accessors", "Tokens", "List token accessors", "Requires upstream sudo/list authority. Accessors are not bearer tokens.", "roles.manage", false, false, nil)
	add("token-lookup", "Tokens", "Inspect token by accessor", "Selected metadata only; the token value is never returned.", "roles.manage", false, false, fields(field("accessor", "Token accessor", "identifier", true)))
	add("token-create", "Tokens", "Create bounded child token", "Creates a renewable child token with explicit policies and a hard 24-hour maximum lifetime. Never creates root, orphan or periodic tokens.", "roles.manage secrets.create", true, true, fields(tokenPolicyField, ttlField, field("display_name", "Display name", "name", true)))
	add("token-renew", "Tokens", "Renew token by accessor", "Vault applies the token's original maximum TTL. No token value is returned.", "roles.manage secrets.rotate", true, false, fields(field("accessor", "Token accessor", "identifier", true), field("increment", "Requested increment in seconds", "seconds", true)))
	add("token-revoke", "Tokens", "Revoke token by accessor", "Revokes the token, its child tokens and associated leases. Revoking your own token may prevent receipt verification.", "roles.manage secrets.rotate", true, false, fields(field("accessor", "Token accessor", "identifier", true)))
	add("lease-list", "Leases", "List lease prefix", "Listing prefixes does not reveal credential values.", "secrets.metadata.read", false, false, fields(field("prefix", "Lease prefix (empty for root, without trailing slash)", "prefix", false)))
	add("lease-lookup", "Leases", "Inspect lease", "Selected lease metadata only.", "secrets.metadata.read", false, false, fields(field("lease_id", "Lease ID", "path", true)))
	add("lease-renew", "Leases", "Renew lease", "Vault may cap or reject the increment. This does not renew KV-v2 secret versions.", "secrets.rotate", true, false, fields(field("lease_id", "Lease ID", "path", true), field("increment", "Requested increment in seconds", "seconds", true)))
	add("lease-revoke", "Leases", "Revoke one lease", "Revokes the external credential through its backend. Force and bulk revocation are not used.", "secrets.rotate", true, false, fields(field("lease_id", "Lease ID", "path", true)))
	add("audit-list", "Audit", "Inspect audit devices", "Selected device configuration only. Nexus request auditing remains separate from Vault audit devices.", "audit.read", false, false, nil)
	add("audit-enable", "Audit", "Enable file audit device", "Writes HMAC-protected JSON audit records to /vault/logs/<name>.json (0600). Configure log rotation and capacity on the host.", "settings.manage audit.read", true, false, fields(nameField))
	add("audit-disable", "Audit", "Disable audit device", "Refuses to disable the last observed audit device. Coordinate with other operators; the device-count check is not atomic.", "settings.manage audit.read", true, false, fields(nameField))
	addPKIOperations(add)
	addIdentityTransitOperations(add)
	for i := range out {
		switch {
		case strings.HasPrefix(out[i].ID, "kv-"):
			out[i].mountType = "kv"
		case strings.HasPrefix(out[i].ID, "pki-"):
			out[i].mountType = "pki"
		case strings.HasPrefix(out[i].ID, "transit-"):
			out[i].mountType = "transit"
		case strings.HasPrefix(out[i].ID, "userpass-"):
			out[i].authType = "userpass"
		case strings.HasPrefix(out[i].ID, "approle-"):
			out[i].authType = "approle"
		}
	}
	return out
}()

func AdminOperations() []AdminOperation {
	// Callers receive copies, including mutable nested slices.
	out := append([]AdminOperation{}, adminOperations...)
	for i := range out {
		out[i].Fields = append([]AdminField{}, out[i].Fields...)
		out[i].Permissions = append([]string{}, out[i].Permissions...)
		for j := range out[i].Fields {
			out[i].Fields[j].Choices = append([]string{}, out[i].Fields[j].Choices...)
		}
	}
	return out
}
func AdminOperationByID(id string) (AdminOperation, bool) {
	for _, op := range adminOperations {
		if op.ID == id {
			return op, true
		}
	}
	return AdminOperation{}, false
}

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
