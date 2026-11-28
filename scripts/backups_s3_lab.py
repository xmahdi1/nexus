#!/usr/bin/env python3
"""Real HTTPS S3 backup/retention/restore in an isolated, owned Docker network."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

GATEWAY = r"""
import socket, socketserver, ssl, threading
from pathlib import Path


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = socket.create_connection(("emulator", 4566), timeout=20)
        upstream.settimeout(180)
        self.request.settimeout(180)

        def relay(source, destination):
            try:
                while True:
                    data = source.recv(256 * 1024)
                    if not data:
                        break
                    destination.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        thread = threading.Thread(
            target=relay, args=(self.request, upstream), daemon=True
        )
        thread.start()
        try:
            relay(upstream, self.request)
        finally:
            upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        stream, address = super().get_request()
        try:
            return context.wrap_socket(stream, server_side=True), address
        except ssl.SSLError:
            with Path("/tmp/tls-rejections").open("ab") as output:
                output.write(b"x")
            stream.close()
            raise


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/fixture/ca.pem", "/fixture/key.pem")
with Server(("0.0.0.0", 8443), Tunnel) as server:
    server.serve_forever()
"""

DRIVER = r"""
import hashlib, json, secrets, shutil, subprocess, tempfile, time, urllib.request, uuid
from pathlib import Path

pins = json.loads(Path("/fixture/pins.json").read_text())
engine = "PINS=" + json.dumps(pins) + "\n" + Path("/fixture/engine.py").read_text()
for attempt in range(100):
    try:
        urllib.request.urlopen(
            urllib.request.Request("http://emulator:4566/nexus-fixture", method="PUT"),
            timeout=2,
        ).close()
        break
    except Exception:
        time.sleep(0.2)
else:
    raise RuntimeError("Owned emulator not ready")
with tempfile.TemporaryDirectory(prefix="s3-engine-") as directory:
    base = Path(directory)
    work = base / "work"
    work.mkdir(mode=0o700)
    (work / "tools").mkdir(mode=0o700)
    binary = Path("/fixture/restic")
    assert (
        hashlib.sha256(binary.read_bytes()).hexdigest()
        == pins["assets"]["amd64"]["binarySHA256"]
    )
    shutil.copyfile(binary, work / "tools/restic-0.20.0")
    (work / "tools/restic-0.20.0").chmod(0o500)
    data = base / "data"
    data.mkdir()
    secret = secrets.token_hex(24)
    (data / "fixture.txt").write_text(secret)
    repository = {
        "kind": "s3",
        "location": "s3:https://storage:8443/nexus-fixture/repository",
        "password": secrets.token_hex(24),
        "accessKey": "fixture-access",
        "secretKey": secrets.token_hex(24),
        "region": "us-east-1",
        "bucketLookup": "path",
    }
    definition = {
        "repository": repository,
        "sources": [{"kind": "files", "path": str(data), "label": "Owned files"}],
        "runtimeSeconds": 120,
        "exportLimitGiB": 1,
        "allowLiveFiles": True,
    }
    policy = uuid.uuid4().hex

    def action(
        name, *, owner=None, snapshot="", retention=None, expected=0, deadline=180
    ):
        print("S3 fixture: " + name, flush=True)
        identity = uuid.uuid4().hex
        request = {
            "action": name,
            "policyId": owner or policy,
            "runId": identity,
            "definition": definition,
            "workRoot": str(work),
            "runtimeSeconds": 120,
        }
        if snapshot:
            request["snapshotId"] = snapshot
        if retention is not None:
            request["retention"] = retention
        result = subprocess.run(
            ["python3", "-I", "-c", engine],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=deadline,
        )
        assert all(
            value not in result.stdout + result.stderr
            for value in [secret, repository["password"], repository["secretKey"]]
        ), "Fixture credentials leaked"
        assert result.returncode == expected, (
            name,
            result.stdout[-300:],
            result.stderr[-200:],
        )
        return json.loads(result.stdout)

    action("init")
    first = action("backup")
    second = action("backup")
    other = uuid.uuid4().hex
    foreign = action("backup", owner=other)
    eligible = [first["snapshotId"], second["snapshotId"]]
    preview = action(
        "retention-preview", retention={"keepLast": 1, "eligibleIds": eligible}
    )["retention"]
    assert len(preview["removeIds"]) == 1 and preview["keptCount"] == 1
    # A new policy snapshot invalidates the reviewed set before any deletion.
    third = action("backup")
    eligible.append(third["snapshotId"])
    assert (
        action("retention-apply", retention=preview, expected=1)["phase"] == "retention"
    )
    preview = action(
        "retention-preview", retention={"keepLast": 1, "eligibleIds": eligible}
    )["retention"]
    assert len(preview["removeIds"]) == 2
    assert action("retention-apply", retention=preview)["state"] == "retention_applied"
    remaining = action("snapshots")["snapshots"]
    assert len(remaining) == 1
    assert (
        action("snapshots", owner=other)["snapshots"][0]["id"] == foreign["snapshotId"]
    ), "Other policy was removed"
    restored = action("restore", snapshot=remaining[0]["id"])
    assert (
        restored["verified"]
        and (
            Path(restored["restorePath"]) / str(data).lstrip("/") / "fixture.txt"
        ).read_text()
        == secret
    )
    assert action("check")["state"] == "checked"
    # A certificate hostname mismatch must fail, without disabling TLS checks.
    repository["location"] = "s3:https://127.0.0.1:8443/nexus-fixture/repository"
    rejected = Path("/tmp/tls-rejections")
    before = rejected.stat().st_size if rejected.exists() else 0
    try:
        assert action("snapshots", expected=1, deadline=10)["state"] == "failed"
    except subprocess.TimeoutExpired:
        pass  # Bound Restic's retry loop after observing the actual TLS alert.
    assert (
        rejected.exists() and rejected.stat().st_size > before
    ), "Client did not reject the mismatched certificate"
    print(
        "HTTPS S3 init/backup/check, stale retention rejection, exact cleanup/prune, cross-policy preservation, verified restore and TLS hostname rejection passed.",
        flush=True,
    )
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restic", required=True)
    parser.add_argument("--emulator-image", required=True, help="Existing local Floci image ID")
    parser.add_argument(
        "--python-image", required=True, help="Existing local Python/glibc image ID"
    )
    args = parser.parse_args()
    for image in [args.emulator_image, args.python_image]:
        assert re.fullmatch(r"(sha256:)?[a-f0-9]{12,64}", image)
        subprocess.run(["docker", "image", "inspect", image], check=True, capture_output=True)
    root = Path(__file__).resolve().parent.parent
    nonce = uuid.uuid4().hex
    network = "nexus-backup-s3-" + nonce
    containers = []
    label = "nexus.backup.management.lab=" + nonce
    subprocess.run(
        ["docker", "network", "create", "--internal", "--label", label, network],
        check=True,
        capture_output=True,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-s3-fixture-") as directory:
            fixture = Path(directory)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "storage")])
            now = datetime.datetime.now(datetime.timezone.utc)
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("storage")]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            (fixture / "ca.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            (fixture / "key.pem").write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            (fixture / "key.pem").chmod(0o600)
            (fixture / "gateway.py").write_text(GATEWAY)
            (fixture / "driver.py").write_text(DRIVER)
            for name in ["engine.py", "pins.json"]:
                shutil.copyfile(root / "nexus/internal/backups" / name, fixture / name)
            shutil.copyfile(args.restic, fixture / "restic")

            def start(image, alias, options, command):
                container = subprocess.check_output(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--network",
                        network,
                        "--network-alias",
                        alias,
                        "--label",
                        label,
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges",
                        "--pids-limit",
                        "256",
                        "--memory",
                        "1g",
                        *options,
                        image,
                        *command,
                    ],
                    text=True,
                ).strip()
                containers.append(container)
                return container

            emulator = start(
                args.emulator_image,
                "emulator",
                ["--user", "1001:1001", "--entrypoint", "/app/application"],
                [
                    "-Dquarkus.http.host=0.0.0.0",
                    "-Dfloci.security.allow-unsafe-network-exposure=true",
                ],
            )
            time.sleep(1)
            details = json.loads(
                subprocess.check_output(["docker", "inspect", emulator], text=True)
            )[0]
            if not details["State"]["Running"]:
                log = subprocess.run(
                    ["docker", "logs", "--tail", "20", emulator],
                    capture_output=True,
                    text=True,
                )
                raise RuntimeError("Owned emulator stopped: " + (log.stdout + log.stderr)[-2000:])
            gateway = start(
                args.python_image,
                "storage",
                [
                    "--user",
                    str(os.getuid()) + ":" + str(os.getgid()),
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777",
                    "--mount",
                    "type=bind,source=" + str(fixture) + ",target=/fixture,readonly",
                    "--mount",
                    "type=bind,source="
                    + str(fixture / "ca.pem")
                    + ",target=/etc/ssl/certs/ca-certificates.crt,readonly",
                ],
                ["python3", "-I", "/fixture/gateway.py"],
            )
            subprocess.run(
                ["docker", "exec", gateway, "python3", "-I", "/fixture/driver.py"],
                check=True,
                timeout=360,
            )
    finally:
        for container in containers:
            details = json.loads(
                subprocess.check_output(["docker", "inspect", container], text=True)
            )[0]
            assert details["Config"]["Labels"].get(
                "nexus.backup.management.lab"
            ) == nonce and not details["HostConfig"].get("PortBindings")
            subprocess.run(["docker", "rm", "-f", "-v", container], check=True, capture_output=True)
        details = json.loads(
            subprocess.check_output(["docker", "network", "inspect", network], text=True)
        )[0]
        assert details["Labels"].get("nexus.backup.management.lab") == nonce and details["Internal"]
        subprocess.run(["docker", "network", "rm", network], check=True, capture_output=True)


if __name__ == "__main__":
    main()
