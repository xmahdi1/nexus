#!/usr/bin/env python3
"""Run real file/SQLite repository acceptance inside an already-built Nexus image."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True)
parser.add_argument("--restic", required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
subprocess.run(["docker", "image", "inspect", args.image], check=True, capture_output=True)
with tempfile.TemporaryDirectory(prefix="nexus-backup-image-") as directory:
    fixture = Path(directory)
    # Export only these source files and the pinned test binary. Runtime/private
    # files from the checkout are never mounted into the fixture container.
    for name in [
        "scripts/backups_engine_lab.py",
        "nexus/internal/backups/engine.py",
        "nexus/internal/backups/pins.json",
    ]:
        target = fixture / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
    shutil.copyfile(args.restic, fixture / "restic")
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "1g",
            "--user",
            str(os.getuid()) + ":" + str(os.getgid()),
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777",
            "--mount",
            "type=bind,source=" + str(fixture) + ",target=/fixture,readonly",
            "--entrypoint",
            "python3",
            args.image,
            "/fixture/scripts/backups_engine_lab.py",
            "--restic",
            "/fixture/restic",
        ],
        check=True,
        timeout=240,
    )
