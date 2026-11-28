package vault

import "strings"

func addIdentityTransitOperations(add func(string, string, string, string, string, bool, bool, []AdminField)) {
	for _, kind := range []string{"entity", "group"} {
		prefix := "identity-" + kind
		add(prefix+"-list", "Identity", "List identity "+kind+" names", "Names only; arbitrary identity metadata is excluded.", "roles.manage", false, false, nil)
		add(prefix+"-read", "Identity", "Read identity "+kind, "Selected access and membership settings only. Read the current state before replacing policies or membership.", "roles.manage", false, false, fields(nameField))
		fs := fields(nameField, field("policies", "Attached policies (one per line; empty removes attachments)", "policies", false))
		if kind == "entity" {
			fs = append(fs, field("disabled", "Disable this entity's authentication", "bool", true))
		} else {
			fs = append(fs, field("member_entity_ids", "Member entity IDs (one per line; replaces current members)", "ids", false), field("member_group_ids", "Member group IDs (one per line; replaces current members)", "ids", false))
		}
		add(prefix+"-save", "Identity", "Save identity "+kind, "Replaces the explicit policies and, for internal groups, membership shown in this form. This can change effective access. Coordinate concurrent edits; Vault provides no atomic revision check here.", "roles.manage", true, false, fs)
		add(prefix+"-delete", "Identity", "Delete identity "+kind, "Removes the identity and associated aliases. Review affected login identities and access before proceeding.", "roles.manage", true, false, fields(nameField))
	}
	add("identity-alias-list", "Identity", "List entity alias IDs", "Entity aliases bind an upstream login name and auth mount to a canonical entity.", "roles.manage", false, false, nil)
	add("identity-alias-read", "Identity", "Read entity alias", "Selected binding fields only.", "roles.manage", false, false, fields(field("id", "Alias ID", "uuid", true)))
	add("identity-alias-save", "Identity", "Save entity alias", "PRIVILEGED: binds a login name to an entity's permissions. Select the correct auth mount and entity. Omit Alias ID only when creating a new binding.", "roles.manage", true, false, fields(field("id", "Existing alias ID (empty creates a new alias)", "uuid", false), nameField, mountField, field("canonical_id", "Canonical entity ID", "uuid", true)))
	add("identity-alias-delete", "Identity", "Delete entity alias", "Removes this login-to-entity binding. Review any resulting identity recreation on the next login.", "roles.manage", true, false, fields(field("id", "Alias ID", "uuid", true)))
	add("transit-keys", "Transit keys", "List transit keys", "Key names only. Key material is never exported.", "secrets.metadata.read", false, false, fields(mountField))
	add("transit-key-read", "Transit keys", "Inspect transit key", "Version metadata and public key information only; no private key material.", "secrets.metadata.read", false, false, fields(mountField, nameField))
	add("transit-key-create", "Transit keys", "Create non-exportable transit key", "Creates an internal key with plaintext backup and export disabled. Those protections cannot be relaxed through Nexus.", "secrets.create", true, false, fields(mountField, nameField, field("type", "Key type", "choice", true, "aes256-gcm96", "ed25519", "rsa-2048")))
	add("transit-key-rotate", "Transit keys", "Rotate transit key", "Creates a new version for future cryptographic operations. Existing versions remain available under the key's version policy.", "secrets.rotate", true, false, fields(mountField, nameField))
	add("transit-key-configure", "Transit keys", "Configure transit version limits", "Raising minimum decryption version blocks older ciphertext. Enabling deletion allows a separate irreversible key deletion. Read current settings first; changes are not atomic with other operators.", "secrets.rotate", true, false, fields(mountField, nameField, field("min_decryption_version", "Minimum decryption version", "positive", true), field("min_encryption_version", "Minimum encryption version (zero uses latest)", "nonnegative", true), field("deletion_allowed", "Allow permanent deletion of this key", "bool", true)))
	add("transit-key-delete", "Transit keys", "Permanently delete transit key", "IRREVERSIBLE: removes every key version. Any data depending on this key becomes unrecoverable. Deletion must first be enabled explicitly.", "secrets.rotate", true, false, fields(mountField, nameField))
}

func buildIdentityTransitPlan(op AdminOperation, v map[string]any) (adminPlan, error) {
	s := func(k string) string { x, _ := v[k].(string); return x }
	copyValues := func(keys string) map[string]any {
		b := map[string]any{}
		for _, key := range strings.Fields(keys) {
			if value, ok := v[key]; ok {
				b[key] = value
			}
		}
		return b
	}
	p := adminPlan{method: "GET"}
	if strings.HasPrefix(op.ID, "identity-entity-") || strings.HasPrefix(op.ID, "identity-group-") {
		parts := strings.Split(op.ID, "-")
		kind, action := parts[1], parts[2]
		base := "/v1/identity/" + kind + "/name"
		switch action {
		case "list":
			p.path = base + "?list=true"
			p.keys = "keys"
		case "read":
			p.path = base + "/" + s("name")
			p.keys = "id name policies disabled direct_group_ids inherited_group_ids group_ids member_entity_ids member_group_ids parent_group_ids type creation_time last_update_time"
		case "save":
			p.method, p.path = "POST", base+"/"+s("name")
			p.body = copyValues("policies disabled member_entity_ids member_group_ids")
			if p.body["policies"] == nil {
				p.body["policies"] = []string{}
			}
			if kind == "group" {
				p.body["type"] = "internal"
				if p.body["member_entity_ids"] == nil {
					p.body["member_entity_ids"] = []string{}
				}
				if p.body["member_group_ids"] == nil {
					p.body["member_group_ids"] = []string{}
				}
			}
			p.keys = "id name"
		case "delete":
			p.method, p.path = "DELETE", base+"/"+s("name")
		default:
			return p, ErrInvalidAdmin
		}
		return p, nil
	}
	switch op.ID {
	case "identity-alias-list":
		p.path = "/v1/identity/entity-alias/id?list=true"
		p.keys = "keys"
	case "identity-alias-read":
		p.path = "/v1/identity/entity-alias/id/" + s("id")
		p.keys = "id name canonical_id mount_accessor mount_path mount_type creation_time last_update_time"
	case "identity-alias-save":
		p.method, p.path = "POST", "/v1/identity/entity-alias"
		p.body = copyValues("id name canonical_id")
		p.keys = "id canonical_id"
	case "identity-alias-delete":
		p.method, p.path = "DELETE", "/v1/identity/entity-alias/id/"+s("id")
	case "transit-keys":
		p.path = "/v1/" + s("mount") + "/keys?list=true"
		p.keys = "keys"
	case "transit-key-read":
		p.path = "/v1/" + s("mount") + "/keys/" + s("name")
		p.keys = "name type derived exportable allow_plaintext_backup deletion_allowed min_decryption_version min_encryption_version latest_version min_available_version supports_encryption supports_decryption supports_derivation supports_signing auto_rotate_period"
	case "transit-key-create":
		p.method, p.path = "POST", "/v1/"+s("mount")+"/keys/"+s("name")
		p.body = map[string]any{"type": s("type"), "exportable": false, "allow_plaintext_backup": false, "derived": false}
		p.keys = "name type latest_version"
	case "transit-key-rotate":
		p.method, p.path, p.body = "POST", "/v1/"+s("mount")+"/keys/"+s("name")+"/rotate", map[string]any{}
	case "transit-key-configure":
		p.method, p.path, p.body = "POST", "/v1/"+s("mount")+"/keys/"+s("name")+"/config", copyValues("min_decryption_version min_encryption_version deletion_allowed")
	case "transit-key-delete":
		p.method, p.path = "DELETE", "/v1/"+s("mount")+"/keys/"+s("name")
	default:
		return p, ErrInvalidAdmin
	}
	return p, nil
}
