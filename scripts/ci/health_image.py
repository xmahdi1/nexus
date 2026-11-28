#!/usr/bin/env python3
"""Start one owned image with no networking and probe health inside its namespace."""

import argparse
import base64
import json
import os
import subprocess
import time

import bcrypt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True)
args = parser.parse_args()
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
subprocess.run(docker + ["image", "inspect", args.image], check=True, capture_output=True)
env = {name: value for name, value in os.environ.items() if not name.startswith("NEXUS_")}
env.update(
    NEXUS_PASSWORD_HASH=bcrypt.hashpw(os.urandom(24), bcrypt.gensalt(rounds=4)).decode(),
    NEXUS_ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode(),
    NEXUS_TOTP_ENABLED="false",
)
container = subprocess.check_output(
    docker
    + [
        "run",
        "-d",
        "--rm",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "256m",
        "--cpus",
        "1",
        "--pids-limit",
        "128",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "-e",
        "NEXUS_PASSWORD_HASH",
        "-e",
        "NEXUS_ENCRYPTION_KEY",
        "-e",
        "NEXUS_TOTP_ENABLED",
        args.image,
    ],
    env=env,
    text=True,
).strip()
try:
    probe = "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8080/health/ready',timeout=2).status==200"
    for _ in range(60):
        result = subprocess.run(
            docker + ["exec", container, "python3", "-c", probe], capture_output=True
        )
        if result.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise SystemExit("fresh image failed readiness; inspect only this fixture privately")
    inspect = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[0]
    assert inspect["Config"]["User"] not in {"", "root", "0", "0:0"}, "image must run as non-root"
    assert inspect["HostConfig"]["NetworkMode"] == "none"
    assert not inspect["HostConfig"].get("Binds")
    print(
        "Fresh image readiness and non-root isolated startup passed. No ports or host files exposed."
    )
finally:
    subprocess.run(docker + ["rm", "-f", container], capture_output=True, check=False)
