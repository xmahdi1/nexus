#!/usr/bin/env python3
"""Run existing disposable adapter fixtures with pinned, reproducible inputs.

Only use an isolated developer machine or a disposable hosted CI runner. No
deployment environment, credentials or remote infrastructure are consulted.
"""

import argparse
import bz2
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
IMAGES = {
    "python": "python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f",
    "postgres": "postgres:18-alpine@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015",
    "mysql": "mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b",
    "mongo": "mongo:6.0.26-jammy@sha256:4b3deaf7f44d61bc401fc698d452b54623a9bb81d09ff63bbc742e322cf1a947",
    "s3": "floci/floci@sha256:e97cd0c1dc2aa14e7697fb5ef5018404c4d6345169dbd276315f0bed2c7b0520",
    "pebble": "ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef",
    "challenges": "ghcr.io/letsencrypt/pebble-challtestsrv@sha256:0152c8cb506e2ecba2900ed47d23932e27e3e6575a7d2c8ef93c7719ee3dea4c",
}


def run(command, timeout=1200):
    subprocess.run(command, cwd=ROOT, check=True, timeout=timeout)


def image(name):
    ref = IMAGES[name]
    run(["docker", "pull", ref], timeout=600)
    return subprocess.check_output(
        ["docker", "image", "inspect", ref, "--format", "{{.Id}}"], text=True
    ).strip()


def lab(name, *args):
    run([sys.executable, str(ROOT / "scripts" / (name + "_lab.py")), *args])


def restic(directory):
    if platform.machine() not in {"x86_64", "AMD64"}:
        raise SystemExit("These existing backup fixtures currently validate amd64 only")
    pins = json.loads((ROOT / "nexus/internal/backups/pins.json").read_text())["assets"]["amd64"]
    request = urllib.request.Request(pins["url"], headers={"User-Agent": "Nexus-disposable-CI"})
    with urllib.request.urlopen(request, timeout=60) as response:
        archive = response.read(32 * 1024 * 1024 + 1)
    if (
        len(archive) > 32 * 1024 * 1024
        or hashlib.sha256(archive).hexdigest() != pins["archiveSHA256"]
    ):
        raise SystemExit("Restic archive failed size/checksum verification")
    binary = bz2.decompress(archive)
    if hashlib.sha256(binary).hexdigest() != pins["binarySHA256"]:
        raise SystemExit("Restic binary failed checksum verification")
    path = Path(directory) / "restic"
    path.write_bytes(binary)
    path.chmod(0o700)
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "profile", choices=["vault", "certificates", "ansible", "backups", "runner"]
    )
    args = parser.parse_args()
    # Fixture subprocesses generate their own random credentials. Never inherit
    # an operator's NEXUS_* deployment settings into an adapter test.
    for key in list(os.environ):
        if key.startswith("NEXUS_"):
            del os.environ[key]
    if args.profile == "vault":
        refs = [
            "hashicorp/vault:2.2.2@sha256:dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6",
            "hashicorp/vault:2.1.2@sha256:c2f666266f383d2cf424d86b8bb8ce7d065562173ffec2b476d762943608bb55",
            "hashicorp/vault:2.0.4@sha256:5be49781ecf78bfe775c5309c6a4d9f4e9e040b6c885c99eb2b12fb69855e1a2",
            "postgres:17-alpine@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32",
        ]
        for ref in refs:
            run(["docker", "pull", ref], timeout=600)
        lab("vault", "--matrix")
    elif args.profile == "certificates":
        image("pebble")
        image("challenges")
        lab("acme")
        lab("certbot")
    elif args.profile == "ansible":
        python_image = image("python")
        lab("ansible_environment", "--image", python_image)
        lab("ansible_execution", "--image", python_image, "--ssh")
    elif args.profile == "runner":
        lab("github_runner", "--image", image("python"))
        lab("github_runner_artifact")
    else:
        with tempfile.TemporaryDirectory(prefix="nexus-ci-restic-") as directory:
            binary = restic(directory)
            lab("backups_engine", "--restic", binary)
            lab("backups_docker", "--restic", binary, "--image", image("python"))
            lab(
                "backups_s3",
                "--restic",
                binary,
                "--emulator-image",
                image("s3"),
                "--python-image",
                image("python"),
            )
            lab(
                "backups_database",
                "--restic",
                binary,
                "--postgres-image",
                image("postgres"),
                "--mysql-image",
                image("mysql"),
                "--mongodb-image",
                image("mongo"),
            )


if __name__ == "__main__":
    main()
