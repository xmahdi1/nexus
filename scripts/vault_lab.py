#!/usr/bin/env python3
"""Non-dev persistent Vault fixture. Only generated data and loopback test ports."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

root = Path(__file__).resolve().parent.parent
docker = ['docker', '--host', 'unix:///var/run/docker.sock']
image = 'hashicorp/vault:2.2.2@sha256:dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6'
nonce = uuid.uuid4().hex
volume = 'nexus-vault-lab-' + nonce
audit_volume = volume + '-audit'
network = volume
container = None
with tempfile.TemporaryDirectory(prefix='nexus-vault-lab-') as directory:
    base = Path(directory)
    tls = base / 'tls'
    tls.mkdir(mode=0o755)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable Vault fixture CA')])
    ca = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'vault.fixture')])).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('vault.fixture')]), critical=False).sign(ca_key, hashes.SHA256())
    (tls/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tls/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # Disposable test key only, under a private host parent. Runtime UID 100
    # needs read access through the read-only bind; no real key is ever read.
    (tls/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    config = base / 'vault.hcl'
    config.write_text('''ui = true
disable_mlock = true
api_addr = "https://vault.fixture:8200"
cluster_addr = "https://127.0.0.1:8201"
storage "raft" {
  path = "/vault/file"
  node_id = "fixture"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/cert.pem"
  tls_key_file = "/vault/tls/key.pem"
}
''')
    for file in [config, *tls.iterdir()]:
        file.chmod(0o644)
    try:
        subprocess.run(docker + ['network', 'create', network], check=True, capture_output=True)
        subprocess.run(docker + ['volume', 'create', volume], check=True, capture_output=True)
        subprocess.run(docker + ['volume', 'create', audit_volume], check=True, capture_output=True)
        container = subprocess.check_output(docker + ['run', '-d', '--label', 'nexus.vault-lab='+nonce, '--network', network, '--user', '100:1000', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--ulimit', 'core=0:0', '--pids-limit', '128', '--memory', '512m', '-p', '127.0.0.1::8200', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m,uid=100,gid=1000', '--mount', f'type=volume,source={volume},target=/vault/file', '--mount', f'type=volume,source={audit_volume},target=/vault/logs', '--mount', f'type=bind,source={config},target=/vault/config/vault.hcl,readonly', '--mount', f'type=bind,source={tls},target=/vault/tls,readonly', '--entrypoint', '/usr/bin/dumb-init', image, '--', '/bin/vault', 'server', '-config=/vault/config/vault.hcl'], text=True).strip()
        published = subprocess.run(docker + ['port', container, '8200/tcp'], capture_output=True, text=True)
        if published.returncode:
            subprocess.run(docker + ['inspect', '--format', '{{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}} oom={{.State.OOMKilled}}', container], check=False)
            subprocess.run(docker + ['logs', '--tail', '30', container], check=False)  # Before any initialization.
            raise RuntimeError('Uninitialized Vault fixture exited during startup')
        address = published.stdout.strip()
        host, port = address.rsplit(':', 1)
        for _ in range(100):
            try:
                with socket.create_connection((host, int(port)), timeout=.2):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('Vault fixture listener did not start')
        env = {k:v for k,v in os.environ.items() if not k.startswith('NEXUS_')}
        env['NEXUS_VAULT_LAB_COMPOSE'] = '1'
        subprocess.run(['go', 'test', './internal/templates', '-run', '^TestVaultComposeConfiguration$', '-count=1'], cwd=root/'nexus', env=env, check=True, timeout=60)
        env.update(NEXUS_VAULT_LAB_CONTAINER=container, NEXUS_VAULT_LAB_NONCE=nonce, NEXUS_VAULT_LAB_ADDR=address, NEXUS_VAULT_LAB_CA=str(tls/'ca.pem'))
        subprocess.run(['go', 'test', '-race', './internal/vault', '-run', '^TestPersistentDisposableVault$', '-count=1', '-v'], cwd=root/'nexus', env=env, check=True, timeout=180)
    finally:
        if container:
            # Do not print Vault logs after initialization: they may contain
            # sensitive operational information. Tests report redacted failures.
            subprocess.run(docker + ['rm', '-f', container], check=False, capture_output=True)
        subprocess.run(docker + ['volume', 'rm', volume], check=False, capture_output=True)
        subprocess.run(docker + ['volume', 'rm', audit_volume], check=False, capture_output=True)
        subprocess.run(docker + ['network', 'rm', network], check=False, capture_output=True)
