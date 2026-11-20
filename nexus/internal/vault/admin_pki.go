package vault

func addPKIOperations(add func(string, string, string, string, string, bool, bool, []AdminField)) {
	for _, entry := range []struct {
		id, label string
		fs        []AdminField
	}{
		{"pki-roles", "List certificate roles", fields(mountField)},
		{"pki-role-read", "Read certificate role", fields(mountField, nameField)},
		{"pki-issuers", "List issuers", fields(mountField)},
		{"pki-issuer-read", "Read issuer certificate", fields(mountField, field("issuer", "Issuer name or ID", "name", true))},
		{"pki-certificates", "List issued certificate serials", fields(mountField)},
		{"pki-certificate-read", "Read issued certificate", fields(mountField, field("serial_number", "Certificate serial number", "serial", true))},
	} {
		add(entry.id, "PKI", entry.label, "Public certificate and selected configuration metadata only.", "secrets.metadata.read", false, false, entry.fs)
	}
	add("pki-role-save", "PKI", "Save certificate role", "Sets explicit allowed DNS domains, subdomain/bare-domain rules, server/client usage, and a bounded TTL. Arbitrary names, IP SANs and wildcard certificates are disabled.", "roles.manage", true, false, fields(mountField, nameField, field("allowed_domains", "Allowed DNS domains (one per line)", "domains", true), field("allow_subdomains", "Allow subdomains", "bool", true), field("allow_bare_domains", "Allow the domains themselves", "bool", true), field("server_flag", "Server authentication", "bool", true), field("client_flag", "Client authentication", "bool", true), certificateTTLField))
	add("pki-role-delete", "PKI", "Delete certificate role", "Removes issuance rules. Certificates already issued remain valid until expiration or revocation.", "roles.manage", true, false, fields(mountField, nameField))
	add("pki-root-generate", "PKI", "Generate internal root CA", "Creates a new CA. Its private key stays inside Vault and cannot be exported through Nexus. Distribute trust separately; this does not modify host trust.", "roles.manage secrets.create", true, false, fields(mountField, field("common_name", "CA common name", "string", true), field("issuer_name", "New issuer name", "name", true), certificateTTLField))
	add("pki-intermediate-generate", "PKI", "Generate internal intermediate CSR", "Creates an internal private key and returns a CSR for signing. The private key remains in Vault.", "roles.manage secrets.create", true, false, fields(mountField, field("common_name", "CA common name", "string", true)))
	add("pki-intermediate-sign", "PKI", "Sign intermediate CA CSR", "PRIVILEGED: the resulting CA can issue certificates beyond leaf-role domain restrictions. Only sign a CSR from a trusted CA operator.", "roles.manage secrets.create", true, false, fields(mountField, field("csr", "Intermediate CSR (PEM)", "csr", true), field("common_name", "CA common name", "string", true), certificateTTLField))
	add("pki-intermediate-import", "PKI", "Import signed intermediate certificate", "Imports only public certificates; no private-key upload. The matching private key must already be held by Vault.", "roles.manage secrets.create", true, false, fields(mountField, field("certificate", "Signed certificate chain (PEM)", "certificates", true)))
	add("pki-issue", "PKI", "Issue certificate and one-time private key", "Generates a leaf private key and certificate under the selected role. The key is displayed only in this response; Nexus does not save it.", "secrets.create", true, true, fields(mountField, nameField, field("common_name", "Certificate DNS name", "domain", true), field("alt_names", "Additional DNS names (one per line)", "domains", false), certificateTTLField))
	add("pki-sign", "PKI", "Sign leaf CSR", "Signs under a configured role. The caller retains its private key.", "secrets.create", true, false, fields(mountField, nameField, field("csr", "Leaf CSR (PEM)", "csr", true), field("common_name", "Certificate DNS name", "domain", true), certificateTTLField))
	add("pki-revoke", "PKI", "Revoke issued certificate", "Revocation requires relying parties to fetch and enforce current CRL/OCSP information.", "secrets.rotate", true, false, fields(mountField, field("serial_number", "Certificate serial number", "serial", true)))
	add("pki-crl-rotate", "PKI", "Rotate certificate revocation lists", "Refreshes this cluster's CRLs. This is a mutation even though Vault exposes it as GET.", "secrets.rotate", true, false, fields(mountField))
}
