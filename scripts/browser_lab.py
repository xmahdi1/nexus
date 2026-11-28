#!/usr/bin/env python3
"""Owns a temporary DB/config and local listener; never reads a deployment .env.
Usage: python3 scripts/browser_lab.py /tmp/nexus-phase1-audit
Requires scripts/requirements-ci.txt and the pinned frontend Playwright install.
"""

import base64
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import bcrypt

root = Path(__file__).resolve().parent.parent
binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="nexus-browser-lab-") as directory:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    password = "Browser fixture password only"
    env = {k: v for k, v in os.environ.items() if not k.startswith("NEXUS_")}
    env.update(
        {
            name: os.environ[name]
            for name in ("NEXUS_BROWSER_EXECUTABLE", "NEXUS_BROWSER_SANDBOX")
            if name in os.environ
        }
    )
    env.update(
        NEXUS_DB_PATH=directory + "/fixture.db",
        NEXUS_PORT=str(port),
        NEXUS_BIND_ADDRESS="127.0.0.1",
        NEXUS_PASSWORD_HASH=bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode(),
        NEXUS_TOTP_ENABLED="false",
        NEXUS_TRUST_PROXY="false",
        NEXUS_LAB_PASSWORD=password,
        NEXUS_ENABLE_INVENTORY="true",
        NEXUS_ENABLE_JOB_SUPERVISION="true",
        NEXUS_ENABLE_VAULT="true",
        NEXUS_ENABLE_AUTOMATION="true",
        NEXUS_ENABLE_BACKUPS="true",
        NEXUS_LAB_BACKUP_REPOSITORY=directory + "/repository",
        NEXUS_LAB_URL=f"http://127.0.0.1:{port}",
    )
    # Generate encryption material at runtime rather than embedding a test key.
    env["NEXUS_ENCRYPTION_KEY"] = base64.b64encode(os.urandom(32)).decode()

    for args in [
        ("db-migrate", env["NEXUS_DB_PATH"]),
        ("owner-bootstrap", "--from-env", "owner"),
        ("owner-activate", "owner"),
    ]:
        subprocess.run(
            [str(binary), *args], env=env, cwd=directory, check=True, stdout=subprocess.DEVNULL
        )
    with sqlite3.connect(env["NEXUS_DB_PATH"]) as db:
        for target in ["dev", "prod"]:
            db.execute(
                "INSERT INTO servers(id,name,host,port,username) VALUES(?,?,?,1,'fixture')",
                (target, "Fixture " + target, "127.0.0.1"),
            )
        actor = db.execute("SELECT id FROM users WHERE username='owner'").fetchone()[0]
        db.execute(
            "INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES('browser-nexus-backups',?,'user','nexus-backup-administrator','global','',?,CURRENT_TIMESTAMP)",
            (actor, actor),
        )
        for role in ("ansible-inventory", "ansible-environment", "github-runners"):
            db.execute(
                "INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES(?,?,'user',?,'server','dev',?,CURRENT_TIMESTAMP)",
                ("browser-" + role, actor, role, actor),
            )
        db.execute(
            "INSERT INTO servers(id,name,host,port,username) VALUES('controller','Ansible controller','127.0.0.1',1,'root')"
        )
        for role in (
            "backup-administrator",
            "backup-retention-manager",
            "ansible-projects",
            "ansible-scheduler",
            "ansible-executor",
            "secret-reader",
            "ansible-environment",
            "github-connections",
            "github-actions-reader",
            "github-actions-dispatcher",
            "github-actions-controller",
            "github-actions-logs",
            "github-actions-artifacts",
            "github-provider-runners-reader",
            "github-provider-runners-manager",
            "github-workflow-reader",
            "github-workflow-editor",
            "github-webhooks",
            "github-org-connections",
            "github-org-runners-manager",
            "github-org-runners-enroller",
            "github-projects-reader",
        ):
            db.execute(
                "INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES(?,?,'user',?,'server','controller',?,CURRENT_TIMESTAMP)",
                ("browser-controller-" + role, actor, role, actor),
            )
        db.execute(
            "INSERT INTO github_connections(id,server_id,owner,name,repository_id,client_id,installation_id,config_enc,created_by,created_at)VALUES(?,'controller','fixture','repository',123,'Iv1.fixture',42,'',?,CURRENT_TIMESTAMP)",
            ("d" * 32, actor),
        )
        db.execute(
            "INSERT INTO github_organizations(id,server_id,login,organization_id,client_id,installation_id,config_enc,created_by,created_at)VALUES(?,'controller','fixture-org',777,'Iv1.fixture',42,'',?,CURRENT_TIMESTAMP)",
            ("e" * 32, actor),
        )
        db.execute(
            "INSERT INTO server_groups(id,name,created_at) VALUES('automation','Automation fixture',CURRENT_TIMESTAMP)"
        )
        db.execute(
            "INSERT INTO server_group_members(group_id,server_id) VALUES('automation','dev'),('automation','prod')"
        )
    with open(directory + "/server.log", "w") as log:
        process = subprocess.Popen([str(binary)], env=env, cwd=directory, stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(env["NEXUS_LAB_URL"] + "/health/ready", timeout=1)
                    break
                except Exception:
                    time.sleep(0.1)
            else:
                raise RuntimeError("fixture listener did not start")
            subprocess.run(
                ["node", str(root / "scripts/backups_browser_smoke.mjs")],
                env=env,
                cwd=directory,
                check=True,
            )
            # The general suite verifies that unrelated roles do not implicitly
            # reveal secrets. Remove this suite's explicit backup-only grants.
            with sqlite3.connect(env["NEXUS_DB_PATH"]) as db:
                db.execute(
                    "DELETE FROM role_grants WHERE id IN ('browser-nexus-backups','browser-controller-backup-administrator','browser-controller-backup-retention-manager')"
                )
            subprocess.run(
                ["node", str(root / "scripts/browser_smoke.mjs")],
                env=env,
                cwd=directory,
                check=True,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
