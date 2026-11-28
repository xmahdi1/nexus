#!/bin/sh
set -eu
: "${NEXUS_LAB_NONCE:?Disposable fixture nonce is required}"
printf '%s' "$NEXUS_LAB_NONCE" > /nexus-disposable-fixture
cp /fixture-authorized-key /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh-keygen -A > /dev/null 2>&1
printf '\nHostKey /etc/ssh/ssh_host_ed25519_key\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n' >> /etc/ssh/sshd_config
nginx
# Local private-CA proxy validation: no ACME/DNS contact and no published HTTP port.
printf '{\n local_certs\n skip_install_trust\n http_port 8085\n https_port 8443\n admin localhost:2019\n}\n' > /etc/caddy/Caddyfile
caddy start --config /etc/caddy/Caddyfile > /tmp/caddy-fixture.log 2>&1
if [ "${NEXUS_LAB_FIREWALL:-}" = 1 ]; then
  # All rules live in this container network namespace. Avoid read-only host
  # sysctls. IPv6 is an explicit opt-in fixture mode.
  if [ "${NEXUS_LAB_FIREWALL_IPV6:-}" = 1 ]; then
    sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
  else
    sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
  fi
  printf '\nIPT_SYSCTL=/tmp/nexus-empty-sysctl\n' >> /etc/default/ufw
  touch /tmp/nexus-empty-sysctl
fi
exec /usr/sbin/sshd -D -e
