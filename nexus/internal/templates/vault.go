package templates

import (
	"errors"
	"strconv"
)

func vaultTemplate() AppTemplate {
	return AppTemplate{ID: "vault", Name: "HashiCorp Vault", Icon: "🔐", Category: "Security", BuiltIn: true,
		Description: "Persistent single-node Vault with verified TLS and a loopback-only listener. Prepare configuration and certificates before deployment; initialization and unseal remain manual.",
		DocURL:      "https://developer.hashicorp.com/vault/docs",
		Vars:        []TemplateVar{{Name: "PORT", Label: "Loopback HTTPS port", Default: "8200", Required: true, Type: VarNumber}},
		PostDeploy:  "Vault is available only on the managed host's 127.0.0.1:${PORT}. Configure the Nexus Vault tab with the certificate's DNS name and CA. Initialize and unseal manually; retain shares and recovery material separately, revoke the initial root token, and use short-lived non-root tokens. See the Vault deployment guide before storing secrets.",
		Compose: `services:
  vault:
    image: hashicorp/vault:2.2.2@sha256:dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6
    restart: unless-stopped
    user: "100:1000"
    entrypoint: ["/usr/bin/dumb-init", "--", "/bin/vault"]
    command: ["server", "-config=/vault/config/vault.hcl"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    ulimits:
      core: 0
    stop_grace_period: 30s
    ports:
      - "127.0.0.1:${PORT}:8200"
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=16m,uid=100,gid=1000
    volumes:
      - vault_data:/vault/file
      - vault_audit:/vault/logs
      - type: bind
        source: /etc/nexus-vault/vault.hcl
        target: /vault/config/vault.hcl
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: /etc/nexus-vault/tls
        target: /vault/tls
        read_only: true
        bind:
          create_host_path: false
volumes:
  vault_data:
  vault_audit:
`}
}

func validateVaultVariables(values map[string]string) error {
	port, err := strconv.Atoi(values["PORT"])
	if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != values["PORT"] {
		return errors.New("Vault requires a numeric port between 1024 and 65535")
	}
	return nil
}
