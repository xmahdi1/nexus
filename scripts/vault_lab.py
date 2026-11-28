#!/usr/bin/env python3
"""Non-dev persistent Vault fixture. Only generated data and loopback test ports."""

import argparse
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
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
images = {
    "2.2.2": "hashicorp/vault:2.2.2@sha256:dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6",
    "2.1.2": "hashicorp/vault:2.1.2@sha256:c2f666266f383d2cf424d86b8bb8ce7d065562173ffec2b476d762943608bb55",
    "2.0.4": "hashicorp/vault:2.0.4@sha256:5be49781ecf78bfe775c5309c6a4d9f4e9e040b6c885c99eb2b12fb69855e1a2",
}
postgres_image = (
    "postgres:17-alpine@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32"
)
parser = argparse.ArgumentParser(description=__doc__)
selection = parser.add_mutually_exclusive_group()
selection.add_argument("--version", choices=images, default="2.2.2")
selection.add_argument("--matrix", action="store_true")
args = parser.parse_args()


def run_fixture(version):
    image = images[version]
    nonce = uuid.uuid4().hex
    volume = "nexus-vault-lab-" + nonce
    audit_volume = volume + "-audit"
    network = volume
    container = None
    postgres = None
    postgres_volume = volume + "-postgres"
    database_password = os.urandom(32).hex()
    with tempfile.TemporaryDirectory(prefix="nexus-vault-lab-") as directory:
        base = Path(directory)
        tls = base / "tls"
        tls.mkdir(mode=0o755)
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable Vault fixture CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vault.fixture")]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("vault.fixture")]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        pg_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pg_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "postgres.fixture")]))
            .issuer_name(name)
            .public_key(pg_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("postgres.fixture")]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        (tls / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (tls / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        # Disposable test key only, under a private host parent. Runtime UID 100
        # needs read access through the read-only bind; no real key is ever read.
        (tls / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        config = base / "vault.hcl"
        config.write_text("""ui = true
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
""")
        for file in [config, *tls.iterdir()]:
            file.chmod(0o644)
        try:
            subprocess.run(docker + ["network", "create", network], check=True, capture_output=True)
            subprocess.run(docker + ["volume", "create", volume], check=True, capture_output=True)
            subprocess.run(
                docker + ["volume", "create", audit_volume], check=True, capture_output=True
            )
            subprocess.run(
                docker + ["volume", "create", postgres_volume], check=True, capture_output=True
            )
            # The pinned Alpine image uses UID/GID 70. Private generated TLS and
            # bootstrap-password files are written through stdin as that user,
            # on its own tmpfs. No host file ownership or trust store is changed.
            postgres_command = docker + [
                "run",
                "-d",
                "--label",
                "nexus.vault-lab=" + nonce,
                "--network",
                network,
                "--network-alias",
                "postgres.fixture",
                "--user",
                "70:70",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--memory",
                "256m",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=32m,uid=70,gid=70",
                "--tmpfs",
                "/var/run/postgresql:rw,noexec,nosuid,size=8m,uid=70,gid=70",
                "--mount",
                f"type=volume,source={postgres_volume},target=/var/lib/postgresql/data",
                "-e",
                "POSTGRES_USER=fixture_admin",
                "-e",
                "POSTGRES_DB=fixture",
                "-e",
                "POSTGRES_PASSWORD_FILE=/tmp/tls/password",
                "--entrypoint",
                "/bin/sh",
                postgres_image,
                "-c",
                "while [ ! -f /tmp/tls/READY ]; do sleep 0.1; done; "
                "exec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on "
                "-c ssl_cert_file=/tmp/tls/cert.pem -c ssl_key_file=/tmp/tls/key.pem",
            ]
            postgres = subprocess.check_output(postgres_command, text=True).strip()
            private_files = {
                "cert.pem": pg_cert.public_bytes(serialization.Encoding.PEM),
                "ca.pem": ca.public_bytes(serialization.Encoding.PEM),
                "key.pem": pg_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                "password": database_password.encode(),
            }
            for name, contents in private_files.items():
                subprocess.run(
                    docker
                    + [
                        "exec",
                        "-i",
                        postgres,
                        "sh",
                        "-c",
                        "umask 077; mkdir -p /tmp/tls; cat > /tmp/tls/" + name,
                    ],
                    input=contents,
                    check=True,
                    capture_output=True,
                )
            subprocess.run(
                docker + ["exec", postgres, "touch", "/tmp/tls/READY"],
                check=True,
                capture_output=True,
            )
            for _ in range(150):
                ready = subprocess.run(
                    docker
                    + [
                        "exec",
                        postgres,
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-U",
                        "fixture_admin",
                        "-d",
                        "fixture",
                    ],
                    capture_output=True,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("Owned PostgreSQL fixture did not become ready")

            vault_command = docker + [
                "run",
                "-d",
                "--label",
                "nexus.vault-lab=" + nonce,
                "--network",
                network,
                "--user",
                "100:1000",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--ulimit",
                "core=0:0",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "-p",
                "127.0.0.1::8200",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m,uid=100,gid=1000",
                "--mount",
                f"type=volume,source={volume},target=/vault/file",
                "--mount",
                f"type=volume,source={audit_volume},target=/vault/logs",
                "--mount",
                f"type=bind,source={config},target=/vault/config/vault.hcl,readonly",
                "--mount",
                f"type=bind,source={tls},target=/vault/tls,readonly",
                "--entrypoint",
                "/usr/bin/dumb-init",
                image,
                "--",
                "/bin/vault",
                "server",
                "-config=/vault/config/vault.hcl",
            ]
            container = subprocess.check_output(vault_command, text=True).strip()
            published = subprocess.run(
                docker + ["port", container, "8200/tcp"], capture_output=True, text=True
            )
            if published.returncode:
                subprocess.run(
                    docker
                    + [
                        "inspect",
                        "--format",
                        "{{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}} oom={{.State.OOMKilled}}",
                        container,
                    ],
                    check=False,
                )
                subprocess.run(
                    docker + ["logs", "--tail", "30", container], check=False
                )  # Before any initialization.
                raise RuntimeError("Uninitialized Vault fixture exited during startup")
            address = published.stdout.strip()
            host, port = address.rsplit(":", 1)
            for _ in range(100):
                try:
                    with socket.create_connection((host, int(port)), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Vault fixture listener did not start")
            env = {k: v for k, v in os.environ.items() if not k.startswith("NEXUS_")}
            env["NEXUS_VAULT_LAB_COMPOSE"] = "1"
            subprocess.run(
                [
                    "go",
                    "test",
                    "./internal/templates",
                    "-run",
                    "^TestVaultComposeConfiguration$",
                    "-count=1",
                ],
                cwd=root / "nexus",
                env=env,
                check=True,
                timeout=60,
            )
            env.update(
                NEXUS_VAULT_LAB_CONTAINER=container,
                NEXUS_VAULT_LAB_NONCE=nonce,
                NEXUS_VAULT_LAB_ADDR=address,
                NEXUS_VAULT_LAB_CA=str(tls / "ca.pem"),
                NEXUS_VAULT_LAB_PG_CONTAINER=postgres,
                NEXUS_VAULT_LAB_PG_PASSWORD=database_password,
            )
            subprocess.run(
                [
                    "go",
                    "test",
                    "-race",
                    "./internal/vault",
                    "-run",
                    "^TestPersistentDisposableVault$",
                    "-count=1",
                    "-v",
                ],
                cwd=root / "nexus",
                env=env,
                check=True,
                timeout=180,
            )
        finally:
            if container:
                # Do not print Vault logs after initialization: they may contain
                # sensitive operational information. Tests report redacted failures.
                subprocess.run(docker + ["rm", "-f", container], check=False, capture_output=True)
            if postgres:
                subprocess.run(docker + ["rm", "-f", postgres], check=False, capture_output=True)
            subprocess.run(
                docker + ["volume", "rm", postgres_volume], check=False, capture_output=True
            )
            subprocess.run(docker + ["volume", "rm", volume], check=False, capture_output=True)
            subprocess.run(
                docker + ["volume", "rm", audit_volume], check=False, capture_output=True
            )
            subprocess.run(docker + ["network", "rm", network], check=False, capture_output=True)


for version in images if args.matrix else [args.version]:
    print("Validating Vault " + version + " with the real PostgreSQL lease backend", flush=True)
    run_fixture(version)
