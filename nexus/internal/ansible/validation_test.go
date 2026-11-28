package ansible

import "testing"

func TestBundleAndTypedVariablesRejectAuthorityOverrides(t *testing.T) {
	base := Bundle{Main: "main.yml", Files: map[string]string{"main.yml": "- hosts: all\n  tasks: []"}, Variables: []Variable{{Name: "message", Kind: "string", Required: true}}}
	for _, name := range []string{"../main.yml", "/main.yml", "roles/../../main.yml", ".ssh/id_rsa", "ansible.cfg"} {
		b := base
		b.Main = name
		b.Files = map[string]string{name: "- hosts: all"}
		if ValidateBundle(b) == nil {
			t.Fatal("unsafe bundle path", name)
		}
	}
	for _, name := range []string{"ansible_host", "ANSIBLE_connection", "hostvars", "inventory_hostname", "nexus_server_id"} {
		b := base
		b.Variables = []Variable{{Name: name, Kind: "string"}}
		if ValidateBundle(b) == nil {
			t.Fatal("reserved variable admitted", name)
		}
	}
	for _, values := range []map[string]any{{"message": "{{lookup('pipe','id')}}"}, {"message": "ok", "ansible_host": "192.0.2.99"}, {"message": true}, {}} {
		if _, err := Variables(base, values); err == nil {
			t.Fatal("invalid variable admitted")
		}
	}
	if _, err := validateReference(map[string]any{"serverId": "vault", "mount": "secret", "path": "app", "field": "password", "version": 1, "token": "must-not-persist"}); err == nil {
		t.Fatal("Vault credential persisted in a reference")
	}
}
