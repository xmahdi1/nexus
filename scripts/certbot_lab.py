#!/usr/bin/env python3
"""Actual Nexus Certbot/Cloudflare adapter against private Pebble and fake API.

Runtime containers share an INTERNAL, randomly named network, no published ports,
no host mounts or Docker socket. Fake API credentials and CA
keys are generated for this run only. Public packages are fetched at image build.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

root = Path(__file__).resolve().parent.parent
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
pebble = "ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef"
subprocess.run(docker + ["image", "inspect", pebble], check=True, capture_output=True)
subprocess.run(
    docker + ["build", "-t", "nexus:disposable-certbot-lab", str(root / "scripts/certbot_lab")],
    check=True,
)
network = "nexus-certbot-" + uuid.uuid4().hex
containers = []
subprocess.run(
    docker + ["network", "create", "--internal", network], check=True, capture_output=True
)
try:
    with tempfile.TemporaryDirectory(prefix="nexus-certbot-lab-") as directory:
        fixture = Path(directory)
        nonce = uuid.uuid4().hex
        (fixture / "nonce").write_text(nonce)
        tokens = {os.urandom(24).hex(): scope for scope in ["edit", "read", "other-zone"]}
        (fixture / "tokens.json").write_text(json.dumps(tokens))
        ca_key = ec.generate_private_key(ec.SECP256R1())
        server_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nexus disposable ACME lab")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(ca_key, hashes.SHA256())
        )
        server = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pebble")]))
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("pebble"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (fixture / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (fixture / "server.pem").write_bytes(server.public_bytes(serialization.Encoding.PEM))
        (fixture / "server.key").write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (fixture / "pebble.json").write_text(
            json.dumps(
                {
                    "pebble": {
                        "listenAddress": "0.0.0.0:14000",
                        "managementListenAddress": "0.0.0.0:15000",
                        "certificate": "/fixture/server.pem",
                        "privateKey": "/fixture/server.key",
                        "httpPort": 80,
                        "tlsPort": 443,
                        "retryAfter": {"authz": 1, "order": 1},
                    }
                }
            )
        )
        for file in fixture.iterdir():
            file.chmod(0o600)

        def start(image, alias, options=(), arguments=()):
            command = docker + [
                "create",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "96",
                "--memory",
                "256m",
                "--network",
                network,
                "--network-alias",
                alias,
                *options,
                image,
                *arguments,
            ]
            container = subprocess.check_output(command, text=True).strip()
            containers.append(container)
            subprocess.run(
                docker + ["cp", directory, container + ":/fixture"], check=True, capture_output=True
            )
            subprocess.run(docker + ["start", container], check=True, capture_output=True)
            return container

        target = start(
            "nexus:disposable-certbot-lab",
            "target",
            ["--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "CHOWN"],
        )
        target_ip = json.loads(subprocess.check_output(docker + ["inspect", target], text=True))[0][
            "NetworkSettings"
        ]["Networks"][network]["IPAddress"]
        fixture_user = f"{os.getuid()}:{os.getgid()}"
        provider = start(
            "nexus:disposable-certbot-lab",
            "provider",
            ["--user", fixture_user, "--entrypoint", "python3", "-e", "TARGET_IP=" + target_ip],
            ["/lab/provider.py"],
        )
        provider_ip = json.loads(
            subprocess.check_output(docker + ["inspect", provider], text=True)
        )[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        start(
            pebble,
            "pebble",
            [
                "--user",
                fixture_user,
                "-e",
                "PEBBLE_VA_NOSLEEP=1",
                "-e",
                "PEBBLE_AUTHZREUSE=0",
                "-e",
                "PEBBLE_WFE_NONCEREJECT=0",
            ],
            ["-config", "/fixture/pebble.json", "-strict", "-dnsserver", provider_ip + ":8053"],
        )
        probe = "import ssl,urllib.request; urllib.request.urlopen('https://pebble:14000/dir',context=ssl.create_default_context(cafile='/fixture/ca.pem'),timeout=1).read(); urllib.request.urlopen('http://provider:8056/__fixture/state',timeout=1).read()"
        for _ in range(100):
            result = subprocess.run(
                docker + ["exec", target, "python3", "-c", probe], capture_output=True
            )
            if result.returncode == 0:
                break
            time.sleep(0.1)
        else:
            for container in containers:
                subprocess.run(docker + ["logs", "--tail", "12", container], check=False)
            raise RuntimeError("Disposable Certbot CA/provider did not become ready")
        subprocess.run(docker + ["exec", target, "certbot", "--version"], check=True)
        subprocess.run(
            docker
            + [
                "exec",
                target,
                "dpkg-query",
                "-W",
                "python3-certbot-dns-cloudflare",
                "python3-cloudflare",
            ],
            check=True,
        )
        env = {key: value for key, value in os.environ.items() if not key.startswith("NEXUS_")}
        env.update(
            NEXUS_CERTBOT_LAB_TARGET=target,
            NEXUS_CERTBOT_LAB_NONCE=nonce,
            NEXUS_CERTBOT_LAB_TOKENS=str(fixture / "tokens.json"),
        )
        subprocess.run(
            [
                "go",
                "test",
                "-race",
                "./internal/proxy",
                "-run",
                "^TestDisposableCertbotAdapter$",
                "-count=1",
                "-v",
            ],
            cwd=root / "nexus",
            env=env,
            check=True,
            timeout=360,
        )
finally:
    for container in reversed(containers):
        subprocess.run(docker + ["rm", "-f", container], check=False, stdout=subprocess.DEVNULL)
    subprocess.run(docker + ["network", "rm", network], check=False, stdout=subprocess.DEVNULL)
