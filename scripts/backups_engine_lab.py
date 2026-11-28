#!/usr/bin/env python3
"""Exercise real repository backup/restore against owned temporary source files."""

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--restic",
    required=True,
    help="Already downloaded pinned Restic0.20.0 amd64 fixture binary",
)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
pins = json.loads((root / "nexus/internal/backups/pins.json").read_text())
binary = Path(args.restic).resolve()
assert hashlib.sha256(binary.read_bytes()).hexdigest() == pins["assets"]["amd64"]["binarySHA256"]
source = "PINS=" + json.dumps(pins) + "\n" + (root / "nexus/internal/backups/engine.py").read_text()
with tempfile.TemporaryDirectory(prefix="nexus-backup-fixture-") as directory:
    base = Path(directory)
    work = base / "work"
    work.mkdir(mode=0o700)
    (work / "tools").mkdir(mode=0o700)
    managed = work / "tools/restic-0.20.0"
    shutil.copyfile(binary, managed)
    managed.chmod(0o500)
    data = base / "data"
    data.mkdir(mode=0o700)
    private = secrets.token_hex(30)
    password = secrets.token_hex(30)
    (data / "file with spaces.txt").write_text(private)
    live = base / "live.sqlite3"
    connection = sqlite3.connect(live)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE sample(value text)")
    connection.execute("INSERT INTO sample(value)VALUES(?)", (private,))
    connection.commit()
    policy = uuid.uuid4().hex
    config = {
        "name": "Owned fixture",
        "repository": {
            "kind": "local",
            "location": str(base / "repository"),
            "password": password,
        },
        "sources": [
            {"kind": "files", "label": "Files", "path": str(data)},
            {"kind": "sqlite", "label": "Live SQLite", "path": str(live)},
        ],
        "runtimeSeconds": 120,
        "exportLimitGiB": 1,
        "timing": {"mode": "manual"},
        "allowLiveFiles": True,
    }

    def execute(action, snapshot="", expected=0, policy_id=policy, retention=None):
        identity = uuid.uuid4().hex
        payload = {
            "action": action,
            "policyId": policy_id,
            "runId": identity,
            "definition": config,
            "runtimeSeconds": 120,
            "workRoot": str(work),
        }
        if snapshot:
            payload["snapshotId"] = snapshot
        if retention is not None:
            payload["retention"] = retention
        result = subprocess.run(
            ["python3", "-I", "-c", source],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert (
            private not in result.stdout + result.stderr
            and password not in result.stdout + result.stderr
        ), "Private data escaped"
        assert result.returncode == expected, (
            action,
            result.returncode,
            result.stdout[-1500:],
            result.stderr[-500:],
        )
        answer = json.loads(result.stdout)
        assert not (work / "jobs" / identity).exists(), "Private credentials retained"
        assert not list(Path(tempfile.gettempdir()).glob("nexus-export-" + identity + "-*")), (
            "Private exports retained"
        )
        return answer

    execute("install")
    execute("init")
    first = execute("backup")
    assert (
        first["state"] == "completed" and len(first["snapshotId"]) == 64 and not first["verified"]
    ), first
    snapshots = execute("snapshots")
    assert snapshots["snapshots"][0]["id"] == first["snapshotId"]
    assert execute("check")["state"] == "checked"
    restored = execute("restore", first["snapshotId"])
    destination = Path(restored["restorePath"])
    assert (
        restored["verified"]
        and (destination / str(data).lstrip("/") / "file with spaces.txt").read_text() == private
    )
    databases = list(destination.rglob("source-1.sqlite3"))
    assert len(databases) == 1, databases
    with sqlite3.connect(databases[0]) as restored_db:
        assert restored_db.execute("SELECT value FROM sample").fetchone()[0] == private
        assert restored_db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    manifests = list(destination.rglob("nexus-manifest.json"))
    assert len(manifests) == 1 and password not in manifests[0].read_text()
    assert execute("verify", first["snapshotId"])["verified"]
    assert (
        execute("restore", first["snapshotId"], expected=1, policy_id=uuid.uuid4().hex)["state"]
        == "failed"
    )
    second = execute("backup")
    unclassified = execute("backup")
    foreign_policy = uuid.uuid4().hex
    foreign = execute("backup", policy_id=foreign_policy)
    eligible = [first["snapshotId"], second["snapshotId"]]
    preview = execute("retention-preview", retention={"keepLast": 1, "eligibleIds": eligible})[
        "retention"
    ]
    assert len(preview["removeIds"]) == 1 and preview["unclassifiedCount"] == 1
    third = execute("backup")
    eligible.append(third["snapshotId"])
    assert execute("retention-apply", retention=preview, expected=1)["phase"] == "retention"
    preview = execute("retention-preview", retention={"keepLast": 1, "eligibleIds": eligible})[
        "retention"
    ]
    assert len(preview["removeIds"]) == 2 and preview["keptCount"] == 2
    assert execute("retention-apply", retention=preview)["state"] == "retention_applied"
    assert {row["id"] for row in execute("snapshots")["snapshots"]} == {
        third["snapshotId"],
        unclassified["snapshotId"],
    }
    assert (
        execute("snapshots", policy_id=foreign_policy)["snapshots"][0]["id"]
        == foreign["snapshotId"]
    )
    assert execute("verify", third["snapshotId"])["verified"]
    config["sources"][0]["path"] = str(work)
    assert execute("backup", expected=1)["phase"] == "source_export"
    config["sources"][0]["path"] = config["repository"]["location"]
    assert execute("backup", expected=1)["phase"] == "source_export"
    config["sources"][0]["path"] = str(base / "missing")
    assert execute("backup", expected=1)["phase"] == "source_export"
    connection.close()
    print(
        "Owned backup lab passed: real Restic, files, live SQLite/WAL, repository checks/restores, retention preview/stale rejection/exact prune, unknown/foreign snapshot preservation, failure redaction and private cleanup."
    )
