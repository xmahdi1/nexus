#!/usr/bin/env python3
"""Verify Docker volume and bind snapshots using owned, labeled fixtures only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--restic", required=True)
parser.add_argument("--image", required=True, help="Existing Python/glibc image ID")
args = parser.parse_args()
assert re.fullmatch(r"(sha256:)?[a-f0-9]{12,64}", args.image)
subprocess.run(["docker", "image", "inspect", args.image], check=True, capture_output=True)
root = Path(__file__).resolve().parent.parent
pins = json.loads((root / "nexus/internal/backups/pins.json").read_text())
binary = Path(args.restic).resolve()
assert hashlib.sha256(binary.read_bytes()).hexdigest() == pins["assets"]["amd64"]["binarySHA256"]
engine = "PINS=" + json.dumps(pins) + "\n" + (root / "nexus/internal/backups/engine.py").read_text()
nonce = uuid.uuid4().hex
label = "nexus.backups.lab=" + nonce
volume = "nexus-backups-" + nonce
container = None
subprocess.run(
    ["docker", "volume", "create", "--label", label, volume], check=True, capture_output=True
)
try:
    with tempfile.TemporaryDirectory(prefix="nexus-backup-docker-") as directory:
        base = Path(directory)
        work = base / "work"
        work.mkdir(mode=0o700)
        (work / "tools").mkdir(mode=0o700)
        shutil.copyfile(binary, work / "tools/restic-0.20.0")
        (work / "tools/restic-0.20.0").chmod(0o500)
        source = base / "source"
        source.mkdir(mode=0o700)
        value, password = secrets.token_hex(24), secrets.token_hex(24)
        (source / "bind.txt").write_text(value)
        # Populate only our new volume; no existing containers or paths are used.
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--label",
                label,
                "--mount",
                "type=volume,source=" + volume + ",target=/fixture",
                args.image,
                "python3",
                "-c",
                'from pathlib import Path;p=Path("/fixture/volume.txt");p.write_text("'
                + value
                + '");p.chmod(0o644)',
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        details = json.loads(
            subprocess.check_output(["docker", "volume", "inspect", volume], text=True)
        )[0]
        mountpoint = details["Mountpoint"]
        group = os.stat("/var/run/docker.sock").st_gid
        command = [
            "docker",
            "run",
            "-d",
            "--network",
            "none",
            "--label",
            label,
            "--user",
            str(os.getuid()) + ":" + str(os.getgid()),
            "--group-add",
            str(group),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "1g",
            "--mount",
            "type=bind,source=" + str(base) + ",target=" + str(base),
            "--mount",
            "type=bind,source=" + str(source) + ",target=" + str(source) + ",readonly",
            "--mount",
            "type=volume,source=" + volume + ",target=" + mountpoint + ",readonly",
            "--mount",
            "type=bind,source=/usr/bin/docker,target=/usr/bin/docker,readonly",
            "--mount",
            "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
            args.image,
            "sleep",
            "600",
        ]
        container = subprocess.check_output(command, text=True).strip()
        policy = uuid.uuid4().hex
        definition = {
            "repository": {
                "kind": "local",
                "location": str(base / "repository"),
                "password": password,
            },
            "sources": [
                {"kind": "docker-volume", "label": "Owned volume", "volume": volume},
                {
                    "kind": "docker-bind",
                    "label": "Owned bind",
                    "path": str(source),
                    "containerId": container,
                },
            ],
            "runtimeSeconds": 120,
            "exportLimitGiB": 1,
            "allowLiveFiles": True,
        }

        def action(name, snapshot="", expected=0):
            run = uuid.uuid4().hex
            payload = {
                "action": name,
                "policyId": policy,
                "runId": run,
                "definition": definition,
                "workRoot": str(work),
                "runtimeSeconds": 120,
            }
            if snapshot:
                payload["snapshotId"] = snapshot
            result = subprocess.run(
                ["docker", "exec", "-i", container, "python3", "-I", "-c", engine],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=180,
            )
            assert (
                value not in result.stdout + result.stderr
                and password not in result.stdout + result.stderr
            )
            assert result.returncode == expected, (name, result.stdout[-300:], result.stderr[-300:])
            return json.loads(result.stdout)

        action("init")
        saved = action("backup")
        restored = action("restore", saved["snapshotId"])
        destination = Path(restored["restorePath"])
        assert restored["verified"]
        assert (destination / mountpoint.lstrip("/") / "volume.txt").read_text() == value
        assert (destination / str(source).lstrip("/") / "bind.txt").read_text() == value
        # An existing container is insufficient: the exact mount must still match.
        definition["sources"][1]["path"] = str(base / "missing-bind")
        assert action("backup", expected=1)["phase"] == "source_export"
        print(
            "Docker named volume and pinned bind backup, verified restore content and mount-identity rejection passed."
        )
finally:
    if container:
        details = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[
            0
        ]
        assert details["Config"]["Labels"].get("nexus.backups.lab") == nonce
        subprocess.run(["docker", "rm", "-f", container], check=True, capture_output=True)
    details = json.loads(
        subprocess.check_output(["docker", "volume", "inspect", volume], text=True)
    )[0]
    assert details["Labels"].get("nexus.backups.lab") == nonce
    subprocess.run(["docker", "volume", "rm", volume], check=True, capture_output=True)
