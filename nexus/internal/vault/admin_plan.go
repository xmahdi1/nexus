package vault

import (
	"strconv"
	"strings"
)

type adminPlan struct {
	method, path string
	body         map[string]any
	keys         string
	auth         bool
	resourceMap  bool
}

// Only this switch constructs upstream paths. Values used in path segments have
// already passed the catalog's ASCII segment/path validation.
func buildAdminPlan(op AdminOperation, v map[string]any) (adminPlan, error) {
	s := func(k string) string { x, _ := v[k].(string); return x }
	copyFields := func(names string) map[string]any {
		b := map[string]any{}
		for _, k := range strings.Fields(names) {
			if x, ok := v[k]; ok {
				b[k] = x
			}
		}
		return b
	}
	plan := adminPlan{method: "GET"}
	mount, name := s("mount"), s("name")
	switch op.ID {
	case "kv-config-read":
		plan.path = "/v1/" + mount + "/config"
		plan.keys = "max_versions cas_required delete_version_after"
	case "kv-configure":
		plan.method, plan.path = "POST", "/v1/"+mount+"/config"
		plan.body = copyFields("max_versions cas_required")
		plan.body["delete_version_after"] = strconv.FormatInt(v["delete_version_after"].(int64), 10) + "s"
	case "kv-history":
		plan.path = "/v1/" + mount + "/metadata/" + s("path")
		plan.keys = "current_version oldest_version created_time updated_time max_versions cas_required delete_version_after versions"
	case "kv-version":
		plan.path = "/v1/" + mount + "/data/" + s("path") + "?version=" + strconv.FormatInt(v["version"].(int64), 10)
		plan.keys = "data metadata"
	case "kv-delete", "kv-undelete", "kv-destroy":
		verb := strings.TrimPrefix(op.ID, "kv-")
		if verb == "delete" {
			verb = "delete"
		}
		plan.method, plan.path, plan.body = "POST", "/v1/"+mount+"/"+verb+"/"+s("path"), copyFields("versions")
	case "kv-delete-metadata":
		plan.method, plan.path = "DELETE", "/v1/"+mount+"/metadata/"+s("path")
	case "engine-enable", "auth-enable":
		prefix := "/v1/sys/mounts/"
		if op.ID == "auth-enable" {
			prefix = "/v1/sys/auth/"
		}
		plan.method, plan.path, plan.body = "POST", prefix+mount, copyFields("type description")
		if s("type") == "kv" {
			plan.body["options"] = map[string]string{"version": "2"}
		}
	case "engine-tune-read", "auth-tune-read", "engine-tune", "auth-tune", "engine-disable", "auth-disable":
		prefix := "/v1/sys/mounts/"
		if strings.HasPrefix(op.ID, "auth-") {
			prefix = "/v1/sys/auth/"
		}
		plan.path = prefix + mount
		if strings.HasSuffix(op.ID, "disable") {
			plan.method = "DELETE"
		} else {
			plan.path += "/tune"
			if strings.HasSuffix(op.ID, "read") {
				plan.keys = "default_lease_ttl max_lease_ttl description force_no_cache"
			} else {
				plan.method, plan.body = "POST", copyFields("default_lease_ttl max_lease_ttl")
			}
		}
	case "userpass-list", "userpass-read", "userpass-save", "userpass-delete", "approle-list", "approle-read", "approle-save", "approle-delete":
		family, action, _ := strings.Cut(op.ID, "-")
		base := "/v1/auth/" + mount + "/users"
		if family == "approle" {
			base = "/v1/auth/" + mount + "/role"
		}
		plan.path = base
		switch action {
		case "list":
			plan.path += "?list=true"
			plan.keys = "keys"
		case "read":
			plan.path += "/" + name
			plan.keys = "token_policies token_ttl token_max_ttl token_explicit_max_ttl token_no_default_policy token_num_uses token_type bind_secret_id secret_id_bound_cidrs secret_id_num_uses secret_id_ttl policies"
		case "save":
			plan.method, plan.path, plan.body = "POST", base+"/"+name, map[string]any{"token_policies": v["policies"], "token_ttl": v["ttl"], "token_max_ttl": v["ttl"], "token_explicit_max_ttl": v["ttl"], "token_no_default_policy": false}
			if family == "userpass" {
				if s("password") != "" {
					plan.body["password"] = s("password")
				}
			} else {
				plan.body["bind_secret_id"] = true
				plan.body["secret_id_num_uses"] = 1
				plan.body["secret_id_ttl"] = 3600
			}
		case "delete":
			plan.method, plan.path = "DELETE", base+"/"+name
		}
	case "approle-role-id":
		plan.path = "/v1/auth/" + mount + "/role/" + name + "/role-id"
		plan.keys = "role_id"
	case "approle-secret-id":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/"+mount+"/role/"+name+"/secret-id", map[string]any{"num_uses": 1, "ttl": 3600}
		plan.keys = "secret_id secret_id_accessor secret_id_num_uses secret_id_ttl"
	case "approle-accessors":
		plan.path = "/v1/auth/" + mount + "/role/" + name + "/secret-id?list=true"
		plan.keys = "keys"
	case "approle-revoke-secret-id":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/"+mount+"/role/"+name+"/secret-id-accessor/destroy", map[string]any{"secret_id_accessor": s("accessor")}
	case "token-self":
		plan.path = "/v1/auth/token/lookup-self"
		plan.keys = "accessor creation_time creation_ttl display_name expire_time explicit_max_ttl issue_time num_uses orphan path policies renewable ttl type"
	case "token-self-renew":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/token/renew-self", copyFields("increment")
		plan.auth = true
		plan.keys = "accessor policies lease_duration renewable token_type"
	case "token-self-revoke":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/token/revoke-self", map[string]any{}
	case "token-accessors":
		plan.path = "/v1/auth/token/accessors?list=true"
		plan.keys = "keys"
	case "token-lookup":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/token/lookup-accessor", copyFields("accessor")
		plan.keys = "accessor creation_time creation_ttl display_name expire_time explicit_max_ttl issue_time num_uses orphan path policies renewable ttl type"
	case "token-create":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/token/create", copyFields("policies ttl display_name")
		plan.body["explicit_max_ttl"] = v["ttl"]
		plan.body["renewable"] = true
		plan.body["no_default_policy"] = false
		plan.auth = true
		plan.keys = "client_token accessor policies lease_duration renewable token_type"
	case "token-renew":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/token/renew-accessor", copyFields("accessor increment")
		plan.auth = true
		plan.keys = "accessor policies lease_duration renewable token_type"
	case "token-revoke":
		plan.method, plan.path, plan.body = "POST", "/v1/auth/token/revoke-accessor", copyFields("accessor")
	case "lease-list":
		plan.path = "/v1/sys/leases/lookup"
		if s("prefix") != "" {
			plan.path += "/" + s("prefix")
		}
		plan.path += "?list=true"
		plan.keys = "keys"
	case "lease-lookup":
		plan.method, plan.path, plan.body = "POST", "/v1/sys/leases/lookup", copyFields("lease_id")
		plan.keys = "id issue_time expire_time last_renewal_time ttl renewable"
	case "lease-renew":
		plan.method, plan.path, plan.body = "POST", "/v1/sys/leases/renew", copyFields("lease_id increment")
		plan.keys = "lease_id lease_duration renewable"
	case "lease-revoke":
		plan.method, plan.path, plan.body = "POST", "/v1/sys/leases/revoke", copyFields("lease_id")
		plan.body["sync"] = true
	case "audit-list":
		plan.path = "/v1/sys/audit"
		plan.resourceMap = true
		plan.keys = "type description local"
	case "audit-enable":
		plan.method, plan.path, plan.body = "POST", "/v1/sys/audit/"+name, map[string]any{"type": "file", "description": "Nexus managed file audit", "options": map[string]string{"file_path": "/vault/logs/" + name + ".json", "mode": "0600", "format": "json", "log_raw": "false", "hmac_accessor": "true"}}
	case "audit-disable":
		plan.method, plan.path = "DELETE", "/v1/sys/audit/"+name
	default:
		if strings.HasPrefix(op.ID, "identity-") || strings.HasPrefix(op.ID, "transit-") {
			return buildIdentityTransitPlan(op, v)
		}
		return buildPKIPlan(op, v)
	}
	return plan, nil
}

func buildPKIPlan(op AdminOperation, v map[string]any) (adminPlan, error) {
	s := func(k string) string { x, _ := v[k].(string); return x }
	base := "/v1/" + s("mount") + "/"
	p := adminPlan{method: "GET"}
	certKeys := "certificate issuing_ca ca_chain expiration serial_number issuer_id key_id issuer_name"
	switch op.ID {
	case "pki-roles":
		p.path = base + "roles?list=true"
		p.keys = "keys"
	case "pki-role-read":
		p.path = base + "roles/" + s("name")
		p.keys = "allowed_domains allow_subdomains allow_bare_domains allow_glob_domains allow_any_name allow_ip_sans allow_wildcard_certificates server_flag client_flag ttl max_ttl key_type key_bits issuer_ref"
	case "pki-role-delete":
		p.method, p.path = "DELETE", base+"roles/"+s("name")
	case "pki-role-save":
		p.method, p.path = "POST", base+"roles/"+s("name")
		p.body = map[string]any{"allowed_domains": v["allowed_domains"], "allow_subdomains": v["allow_subdomains"], "allow_bare_domains": v["allow_bare_domains"], "server_flag": v["server_flag"], "client_flag": v["client_flag"], "ttl": v["ttl"], "max_ttl": v["ttl"], "allow_any_name": false, "allow_glob_domains": false, "allow_ip_sans": false, "allow_wildcard_certificates": false, "key_type": "rsa", "key_bits": 2048, "enforce_hostnames": true, "require_cn": true}
	case "pki-issuers":
		p.path = base + "issuers?list=true"
		p.keys = "keys key_info"
	case "pki-issuer-read":
		p.path = base + "issuer/" + s("issuer")
		p.keys = "issuer_id issuer_name key_id certificate ca_chain usage leaf_not_after_behavior issuing_certificates crl_distribution_points ocsp_servers"
	case "pki-certificates":
		p.path = base + "certs?list=true"
		p.keys = "keys"
	case "pki-certificate-read":
		p.path = base + "cert/" + s("serial_number")
		p.keys = "certificate revocation_time revocation_time_rfc3339"
	case "pki-root-generate":
		p.method, p.path = "POST", base+"root/generate/internal"
		p.body = map[string]any{"common_name": s("common_name"), "issuer_name": s("issuer_name"), "ttl": v["ttl"], "key_type": "rsa", "key_bits": 2048}
		p.keys = certKeys
	case "pki-intermediate-generate":
		p.method, p.path = "POST", base+"intermediate/generate/internal"
		p.body = map[string]any{"common_name": s("common_name"), "key_type": "rsa", "key_bits": 2048}
		p.keys = "csr key_id"
	case "pki-intermediate-sign":
		p.method, p.path = "POST", base+"root/sign-intermediate"
		p.body = map[string]any{"csr": s("csr"), "common_name": s("common_name"), "ttl": v["ttl"], "format": "pem_bundle", "max_path_length": 0}
		p.keys = certKeys
	case "pki-intermediate-import":
		p.method, p.path = "POST", base+"intermediate/set-signed"
		p.body = map[string]any{"certificate": s("certificate")}
		p.keys = "imported_issuers existing_issuers mapping"
	case "pki-issue", "pki-sign":
		verb := "issue"
		if op.ID == "pki-sign" {
			verb = "sign"
		}
		p.method, p.path = "POST", base+verb+"/"+s("name")
		p.body = map[string]any{"common_name": s("common_name"), "ttl": v["ttl"], "format": "pem"}
		if names, ok := v["alt_names"].([]string); ok {
			p.body["alt_names"] = strings.Join(names, ",")
		}
		if op.ID == "pki-sign" {
			p.body["csr"] = s("csr")
		}
		p.keys = certKeys
		if op.Sensitive {
			p.keys += " private_key private_key_type"
		}
	case "pki-revoke":
		p.method, p.path, p.body = "POST", base+"revoke", map[string]any{"serial_number": s("serial_number")}
		p.keys = "revocation_time revocation_time_rfc3339"
	case "pki-crl-rotate":
		p.path = base + "crl/rotate"
		p.keys = "success"
	default:
		return adminPlan{}, ErrInvalidAdmin
	}
	return p, nil
}
