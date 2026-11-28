#!/usr/bin/env python3
"""Offline schema-8 → schema-36 image upgrade and matching-old-image rollback.
Requires local Docker, bcrypt, cryptography, and an already-local schema-8 image.
Never starts application workers, publishes ports, or reads a deployment .env.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

parser = argparse.ArgumentParser()
parser.add_argument("--old-image", required=True, help="Already-local trusted schema-8 image ID")
parser.add_argument("--new-image", default="nexus:phase1-security-check")
args = parser.parse_args()
if not re.fullmatch(r"(sha256:)?[a-f0-9]{12,64}", args.old_image):
    parser.error("old image must be a local image ID")
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
for tag in [args.old_image, args.new_image]:
    subprocess.run(docker + ["image", "inspect", tag], check=True, capture_output=True)
with tempfile.TemporaryDirectory(prefix="nexus-secret-image-lab-") as directory:
    key = os.urandom(32)
    env = {k: v for k, v in os.environ.items() if not k.startswith("NEXUS_")}
    env.update(
        NEXUS_PASSWORD_HASH=bcrypt.hashpw(
            b"Offline image fixture only", bcrypt.gensalt(rounds=4)
        ).decode(),
        NEXUS_ENCRYPTION_KEY=base64.b64encode(key).decode(),
        NEXUS_TOTP_ENABLED="false",
        NEXUS_DB_PATH="/data/fixture.db",
    )

    def cli(image, *arguments, check=True, extra_env=None):
        command = docker + [
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
            "64",
            "--memory",
            "128m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,source={directory},target=/data",
        ]
        for name in [
            "NEXUS_PASSWORD_HASH",
            "NEXUS_ENCRYPTION_KEY",
            "NEXUS_TOTP_ENABLED",
            "NEXUS_DB_PATH",
        ]:
            command += ["-e", name]
        return subprocess.run(
            command + [image, *arguments],
            env=extra_env or env,
            check=check,
            capture_output=True,
            text=True,
            timeout=60,
        )

    cli(args.old_image, "db-migrate", "/data/fixture.db")
    cli(args.old_image, "owner-bootstrap", "--from-env", "owner")
    cli(args.old_image, "owner-activate", "owner")
    path = Path(directory) / "fixture.db"
    values = json.dumps(
        {"PASSWORD": os.urandom(20).hex(), "PORT": "5432"}, separators=(",", ":"), sort_keys=True
    )
    nonce = os.urandom(12)
    ssh_cipher = base64.b64encode(
        nonce + AESGCM(key).encrypt(nonce, b"fixture private SSH material", None)
    ).decode()
    legacy_container_id = hashlib.sha256(("fixture\0container\0" + "a" * 64).encode()).hexdigest()
    with sqlite3.connect(path) as database:
        assert database.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 8, (
            "schema-8 image required"
        )
        database.execute(
            "INSERT INTO servers(id,name,host,port,username,private_key_enc)VALUES('fixture','Fixture','192.0.2.1',22,'fixture',?)",
            (ssh_cipher,),
        )
        notification_token = os.urandom(24).hex()
        database.execute(
            "UPDATE alert_configs SET telegram_token=?,telegram_enabled=1 WHERE id='default'",
            (notification_token,),
        )
        database.execute(
            "INSERT INTO deployed_apps(id,server_id,name,status,vars_json)VALUES('app','fixture','preserved','running',?)",
            (values,),
        )
        database.execute(
            "INSERT INTO inventory_resources(id,server_id,kind,natural_key,display_name,source,fingerprint,first_seen_at,last_seen_at,last_verified_at,data_state)VALUES(?,'fixture','container',?,'fixture-db','docker','original',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fresh')",
            (legacy_container_id, "a" * 64),
        )
        database.execute(
            "INSERT INTO inventory_containers(resource_id,engine_id,image,state)VALUES(?,?, 'fixture:1','running')",
            (legacy_container_id, "a" * 64),
        )
        owner = database.execute(
            "SELECT id,username,password_hash,status FROM users WHERE username='owner'"
        ).fetchone()
        admissions = database.execute(
            "SELECT * FROM account_admissions ORDER BY user_id"
        ).fetchall()
    # No key means no data conversion; ledger/variables must remain intact.
    assert cli(args.new_image, "db-migrate", "/data/fixture.db", check=False).returncode != 0, (
        "keyless conversion accepted"
    )
    cli(args.new_image, "db-migrate", "--from-env", "/data/fixture.db")
    with sqlite3.connect(path) as database:
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        notification_cipher = database.execute(
            "SELECT telegram_token_enc FROM alert_configs WHERE id='default'"
        ).fetchone()[0]
        notification_sealed = base64.b64decode(notification_cipher[3:])
        notification_aad = b"nexus:notification-token:v1\0default"
        assert (
            AESGCM(key)
            .decrypt(notification_sealed[:12], notification_sealed[12:], notification_aad)
            .decode()
            == notification_token
        )
        assert database.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 36
        assert database.execute(
            "SELECT engine_id,image,state,image_id,health,compose_project FROM inventory_containers WHERE resource_id=?",
            (legacy_container_id,),
        ).fetchone() == ("a" * 64, "fixture:1", "running", "", "", "")
        assert "vars_json" not in [
            row[1] for row in database.execute("PRAGMA table_info(deployed_apps)")
        ]
        app = database.execute(
            "SELECT id,server_id,name,status,vars_enc FROM deployed_apps WHERE id='app'"
        ).fetchone()
        assert app[2:4] == ("preserved", "running")
        assert app[4].startswith("v1:")
        sealed = base64.b64decode(app[4][3:])
        associated = b"nexus:deployment-variables:v1\0app\0fixture"
        assert AESGCM(key).decrypt(sealed[:12], sealed[12:], associated).decode() == values
        assert (
            database.execute(
                "SELECT id,username,password_hash,status FROM users WHERE username='owner'"
            ).fetchone()
            == owner
        )
        assert (
            database.execute("SELECT * FROM account_admissions ORDER BY user_id").fetchall()
            == admissions
        )
        assert (
            database.execute("SELECT private_key_enc FROM servers WHERE id='fixture'").fetchone()[0]
            == ssh_cipher
        )
        database.execute(
            "INSERT INTO vault_connections(server_id,port,tls_name,ca_pem,namespace)VALUES('fixture',8200,'vault.fixture','','')"
        )
        job_output = os.urandom(20).hex()
        job_aad = b"nexus:job-output:v1\0job\0fixture"
        job_nonce = os.urandom(12)
        job_cipher = (
            "v1:"
            + base64.b64encode(
                job_nonce + AESGCM(key).encrypt(job_nonce, job_output.encode(), job_aad)
            ).decode()
        )
        database.execute(
            "INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,output_enc,exit_code,created_at,finished_at)VALUES('job','fixture-task','fixture',? ,?,'exited',?,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
            (owner[0], "0" * 64, job_cipher),
        )
        operation_id = "a" * 32
        operation_output = os.urandom(20).hex()
        operation_aad = b"nexus:job-output:v1\0" + operation_id.encode() + b"\0fixture"
        operation_nonce = os.urandom(12)
        operation_cipher = (
            "v1:"
            + base64.b64encode(
                operation_nonce
                + AESGCM(key).encrypt(operation_nonce, operation_output.encode(), operation_aad)
            ).decode()
        )
        database.execute(
            "INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,output_enc,created_at,finished_at,kind,action,source_session_id,target_hash)VALUES(?,'','fixture',?,?,'exited',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'operation','compose-up','expired-fixture-session',?)",
            (operation_id, owner[0], "1" * 64, operation_cipher, "2" * 64),
        )
        ansible_id = "e" * 32
        ansible_output = os.urandom(20).hex()
        ansible_aad = b"nexus:job-output:v1\0" + ansible_id.encode() + b"\0fixture"
        ansible_nonce = os.urandom(12)
        ansible_cipher = (
            "v1:"
            + base64.b64encode(
                ansible_nonce
                + AESGCM(key).encrypt(ansible_nonce, ansible_output.encode(), ansible_aad)
            ).decode()
        )
        database.execute(
            "INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,output_enc,created_at,kind,action,source_session_id,operation_context)VALUES(?,'','fixture',?,?,'unknown',?,CURRENT_TIMESTAMP,'ansible','ansible-playbook','expired-fixture-session','fixture-plan')",
            (ansible_id, owner[0], "3" * 64, ansible_cipher),
        )
        database.execute(
            "INSERT INTO ansible_run_plans(run_id,plan_id)VALUES(?,'fixture-plan')", (ansible_id,)
        )
        database.execute(
            "INSERT INTO execution_host_locks(server_id,run_id)VALUES('fixture',?)", (ansible_id,)
        )
        automation_queries = {
            "plans": "SELECT * FROM ansible_run_plans ORDER BY run_id",
            "locks": "SELECT * FROM execution_host_locks ORDER BY server_id",
            "identity": "SELECT id,kind,action,source_session_id,operation_context,state,finished_at FROM supervised_runs WHERE kind='ansible' ORDER BY id",
        }
        app_key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        connection_id = "f" * 32
        github_config = json.dumps(
            {
                "Repository": {"owner": "fixture", "name": "repository", "repositoryId": 123},
                "ClientID": "Iv1.fixture",
                "InstallationID": 42,
                "PEM": app_key,
            },
            separators=(",", ":"),
        )
        connection_aad = b"nexus:github-connection:v1\0" + connection_id.encode() + b"\0fixture"
        connection_nonce = os.urandom(12)
        connection_cipher = (
            "v1:"
            + base64.b64encode(
                connection_nonce
                + AESGCM(key).encrypt(connection_nonce, github_config.encode(), connection_aad)
            ).decode()
        )
        database.execute(
            "INSERT INTO github_connections(id,server_id,owner,name,repository_id,client_id,installation_id,config_enc,created_by,created_at)VALUES(?,'fixture','fixture','repository',123,'Iv1.fixture',42,?,?,CURRENT_TIMESTAMP)",
            (connection_id, connection_cipher, owner[0]),
        )
        dispatch_id = "b" * 32
        github_input = json.dumps(
            {"workflowId": 7, "ref": "main", "inputs": {"value": os.urandom(20).hex()}},
            separators=(",", ":"),
        )
        dispatch_aad = b"nexus:github-dispatch:v1\0" + dispatch_id.encode() + b"\0fixture"
        dispatch_nonce = os.urandom(12)
        dispatch_cipher = (
            "v1:"
            + base64.b64encode(
                dispatch_nonce
                + AESGCM(key).encrypt(dispatch_nonce, github_input.encode(), dispatch_aad)
            ).decode()
        )
        database.execute(
            "INSERT INTO github_dispatches(id,server_id,connection_id,actor_id,source_session_id,input_enc,state,workflow_id,ref,created_at)VALUES(?,'fixture',?,?,'expired-fixture-session',?,'unknown',7,'main',CURRENT_TIMESTAMP)",
            (dispatch_id, connection_id, owner[0], dispatch_cipher),
        )
        automation_queries["github_connections"] = (
            "SELECT id,server_id,owner,name,repository_id,client_id,installation_id,created_by,created_at,disabled FROM github_connections ORDER BY id"
        )
        automation_queries["github_dispatches"] = (
            "SELECT id,server_id,connection_id,actor_id,source_session_id,state,workflow_id,ref,run_id,created_at,submitted_at FROM github_dispatches ORDER BY id"
        )
        database.execute(
            "INSERT INTO github_cancellations(id,server_id,connection_id,actor_id,source_session_id,run_id,run_attempt,state,created_at)VALUES(?,'fixture',?,?,'expired-fixture-session',99,1,'unknown',CURRENT_TIMESTAMP)",
            ("c" * 32, connection_id, owner[0]),
        )
        automation_queries["github_cancellations"] = (
            "SELECT * FROM github_cancellations ORDER BY id"
        )
        change_id = "d" * 32
        github_change = json.dumps(
            {
                "baseBranch": "main",
                "baseSha": "a" * 40,
                "blobSha": "b" * 40,
                "path": ".github/workflows/build.yml",
                "content": "name: " + os.urandom(12).hex(),
                "title": "Fixture workflow",
            },
            separators=(",", ":"),
        )
        change_aad = b"nexus:github-change:v1\0" + change_id.encode() + b"\0fixture"
        change_nonce = os.urandom(12)
        change_cipher = (
            "v1:"
            + base64.b64encode(
                change_nonce + AESGCM(key).encrypt(change_nonce, github_change.encode(), change_aad)
            ).decode()
        )
        database.execute(
            "INSERT INTO github_changes(id,server_id,connection_id,actor_id,source_session_id,kind,input_enc,state,phase,branch,created_at)VALUES(?,'fixture',?,?,'expired-fixture-session','workflow_edit',?,'unknown','file_write',?,CURRENT_TIMESTAMP)",
            (change_id, connection_id, owner[0], change_cipher, "nexus/workflows/" + change_id),
        )
        automation_queries["github_changes"] = (
            "SELECT id,server_id,connection_id,actor_id,source_session_id,kind,state,phase,resource_id,branch,commit_sha,pull_number,created_at,submitted_at FROM github_changes ORDER BY id"
        )

        new_automation_fields = []

        def sealed_automation(kind, identity, payload, server="fixture"):
            field_aad = ("nexus:" + kind + ":v1\0" + identity + "\0" + server).encode()
            nonce = os.urandom(12)
            value = (
                "v1:"
                + base64.b64encode(
                    nonce + AESGCM(key).encrypt(nonce, payload.encode(), field_aad)
                ).decode()
            )
            return value, field_aad

        hook_id = "1" * 32
        hook_config = json.dumps(
            {"ConnectionID": connection_id, "EndpointID": "2" * 32, "Secret": os.urandom(32).hex()},
            separators=(",", ":"),
        )
        value, field_aad = sealed_automation("github-webhook", hook_id, hook_config)
        database.execute(
            "INSERT INTO github_webhooks(id,server_id,connection_id,endpoint_id,secret_enc,created_by,created_at)VALUES(?,'fixture',?,?,?, ?,CURRENT_TIMESTAMP)",
            (hook_id, connection_id, "2" * 32, value, owner[0]),
        )
        new_automation_fields.append(
            ("github_webhooks", hook_id, "secret_enc", field_aad, hook_config)
        )
        org_id = "3" * 32
        org_config = json.dumps(
            {
                "Organization": {"login": "fixture-org", "organizationId": 777},
                "ClientID": "Iv1.fixture",
                "InstallationID": 42,
                "PEM": app_key,
            },
            separators=(",", ":"),
        )
        value, field_aad = sealed_automation("github-organization", org_id, org_config)
        database.execute(
            "INSERT INTO github_organizations(id,server_id,login,organization_id,client_id,installation_id,config_enc,created_by,created_at)VALUES(?,'fixture','fixture-org',777,'Iv1.fixture',42,?,?,CURRENT_TIMESTAMP)",
            (org_id, value, owner[0]),
        )
        new_automation_fields.append(
            ("github_organizations", org_id, "config_enc", field_aad, org_config)
        )
        org_change_id = "4" * 32
        org_input = json.dumps({"runnerId": 0, "name": ""}, separators=(",", ":"))
        value, field_aad = sealed_automation("github-organization-change", org_change_id, org_input)
        database.execute(
            "INSERT INTO github_organization_changes(id,server_id,connection_id,actor_id,source_session_id,kind,input_enc,state,created_at)VALUES(?,'fixture',?,?,'expired-fixture-session','registration',?,'unknown',CURRENT_TIMESTAMP)",
            (org_change_id, org_id, owner[0], value),
        )
        new_automation_fields.append(
            ("github_organization_changes", org_change_id, "input_enc", field_aad, org_input)
        )
        template_id = "5" * 32
        bundle = {
            "main": "main.yml",
            "files": {"main.yml": "- hosts: all\n  tasks: []\n"},
            "variables": [],
            "collections": [
                {
                    "namespace": "fixture",
                    "name": "example",
                    "version": "1.0.0",
                    "sha256": hashlib.sha256(b"fixture-archive").hexdigest(),
                }
            ],
        }

        def envelope(payload):
            compact = json.dumps(payload, separators=(",", ":"))
            salt = os.urandom(32)
            return json.dumps(
                {"salt": base64.b64encode(salt).decode(), "payload": payload}, separators=(",", ":")
            ), hashlib.sha256(salt + compact.encode()).hexdigest()

        template_config, template_digest = envelope({"name": "Fixture template", "bundle": bundle})
        value, field_aad = sealed_automation("ansible-template", template_id, template_config)
        database.execute(
            "INSERT INTO ansible_templates(id,server_id,name,bundle_enc,digest,created_by,created_at)VALUES(?,'fixture','Fixture template',?,?,?,CURRENT_TIMESTAMP)",
            (template_id, value, template_digest, owner[0]),
        )
        new_automation_fields.append(
            ("ansible_templates", template_id, "bundle_enc", field_aad, template_config)
        )
        project_id = "6" * 32
        revision_id = "7" * 32
        database.execute(
            "INSERT INTO ansible_projects(id,server_id,name,created_by,created_at)VALUES(?,'fixture','Fixture source project',?,CURRENT_TIMESTAMP)",
            (project_id, owner[0]),
        )
        revision_config, revision_digest = envelope(
            {
                "projectId": project_id,
                "bundle": bundle,
                "source": {
                    "connectionId": connection_id,
                    "repositoryId": 123,
                    "commitSha": "a" * 40,
                },
            }
        )
        value, field_aad = sealed_automation("ansible-revision", revision_id, revision_config)
        database.execute(
            "INSERT INTO ansible_revisions(id,project_id,server_id,digest,bundle_enc,created_by,created_at,source_connection_id,source_repository_id,source_commit_sha)VALUES(?,?,'fixture',?,?,?,CURRENT_TIMESTAMP,?,123,?)",
            (revision_id, project_id, revision_digest, value, owner[0], connection_id, "a" * 40),
        )
        new_automation_fields.append(
            ("ansible_revisions", revision_id, "bundle_enc", field_aad, revision_config)
        )
        preset_id = "8" * 32
        preset_config, preset_digest = envelope(
            {
                "name": "Fixture selection",
                "projectId": project_id,
                "revisionId": revision_id,
                "revisionDigest": revision_digest,
                "groupId": "fixture-group",
                "serverIds": ["fixture-target"],
                "options": {
                    "mode": "check",
                    "tags": [],
                    "skipTags": [],
                    "verbosity": 0,
                    "timeoutSeconds": 60,
                },
            }
        )
        value, field_aad = sealed_automation("ansible-preset", preset_id, preset_config)
        database.execute(
            "INSERT INTO ansible_presets(id,server_id,name,config_enc,digest,created_by,created_at)VALUES(?,'fixture','Fixture selection',?,?,?,CURRENT_TIMESTAMP)",
            (preset_id, value, preset_digest, owner[0]),
        )
        new_automation_fields.append(
            ("ansible_presets", preset_id, "config_enc", field_aad, preset_config)
        )
        automation_queries["execution_presets"] = (
            "SELECT id,server_id,name,digest,archived FROM ansible_presets ORDER BY id"
        )
        schedule_id = "9" * 32
        schedule_config, schedule_digest = envelope(
            {
                "name": "Fixture schedule",
                "presetId": preset_id,
                "intervalMinutes": 60,
                "variables": {"fixture_value": os.urandom(12).hex()},
            }
        )
        value, field_aad = sealed_automation("ansible-schedule", schedule_id, schedule_config)
        database.execute(
            "INSERT INTO ansible_schedules(id,server_id,name,preset_id,actor_id,source_session_id,config_enc,digest,interval_minutes,next_at,enabled,last_state,created_at)VALUES(?,'fixture','Fixture schedule',?,?,'expired-fixture-session',?,?,60,CURRENT_TIMESTAMP,1,'scheduled',CURRENT_TIMESTAMP)",
            (schedule_id, preset_id, owner[0], value, schedule_digest),
        )
        new_automation_fields.append(
            ("ansible_schedules", schedule_id, "config_enc", field_aad, schedule_config)
        )
        backup_ids = []
        for index, server in enumerate(["fixture", ""]):
            backup_id = ("a" if index == 0 else "b") * 32
            backup_config, backup_digest = envelope(
                {
                    "name": "Fixture backup",
                    "serverId": server,
                    "ownerId": owner[0],
                    "hostBinding": "nexus-local" if not server else "c" * 64,
                    "repository": {
                        "kind": "local",
                        "location": "/fixture-repository",
                        "password": os.urandom(24).hex(),
                    },
                    "sources": [{"kind": "files", "label": "Fixture files", "path": "/srv/fixture"}]
                    if server
                    else [{"kind": "nexus", "label": "Nexus"}],
                    "timing": {"mode": "interval", "intervalMinutes": 60},
                    "runtimeSeconds": 60,
                    "exportLimitGiB": 1,
                    "allowLiveFiles": True,
                }
            )
            value, field_aad = sealed_automation("backup-policy", backup_id, backup_config, server)
            database.execute(
                "INSERT INTO backup_policies(id,server_id,name,actor_id,config_enc,digest,mode,interval_minutes,next_at,enabled,last_state,created_at)VALUES(?,?,'Fixture backup',?,?,?,'interval',60,CURRENT_TIMESTAMP,1,'scheduled',CURRENT_TIMESTAMP)",
                (backup_id, server, owner[0], value, backup_digest),
            )
            new_automation_fields.append(
                ("backup_policies", backup_id, "config_enc", field_aad, backup_config)
            )
            backup_ids.append(backup_id)
        automation_queries["backup_policies"] = (
            "SELECT id,server_id,name,actor_id,digest,mode,interval_minutes,next_at,archived,last_run_id,last_success_at,last_check_at,last_restore_at,created_at FROM backup_policies ORDER BY id"
        )
        retention_id = "c" * 32
        retention_binding = json.dumps(
            [
                "fixture",
                backup_ids[0],
                owner[0],
                "expired-fixture-session",
                "d" * 64,
                "e" * 64,
                "backup:retention-apply",
            ],
            separators=(",", ":"),
        )
        retention_payload = json.dumps(
            {
                "keepLast": 3,
                "inventoryDigest": "f" * 64,
                "removeIds": ["a" * 64],
                "keptCount": 3,
                "unclassifiedCount": 0,
                "previewRunId": "b" * 32,
            },
            separators=(",", ":"),
        )
        value, field_aad = sealed_automation(
            "backup-retention", retention_id, retention_payload, retention_binding
        )
        database.execute(
            "INSERT INTO backup_retention_jobs(run_id,binding,request_enc)VALUES(?,?,?)",
            (retention_id, retention_binding, value),
        )
        new_automation_fields.append(
            ("backup_retention_jobs", retention_id, "request_enc", field_aad, retention_payload)
        )
        database.execute(
            "INSERT INTO backup_policy_settings(policy_id,keep_last,max_age_minutes,verify_after_days,updated_by,updated_at)VALUES(?,3,60,14,?,CURRENT_TIMESTAMP)",
            (backup_ids[0], owner[0]),
        )
        automation_queries["backup_settings"] = (
            "SELECT * FROM backup_policy_settings ORDER BY policy_id"
        )
        database.execute(
            "INSERT INTO scheduled_tasks(id,server_id,name,command,enabled,interval_minutes,last_status,created_at)VALUES('backup-recovery-task','fixture','Fixture task','true',1,60,'pending',CURRENT_TIMESTAMP)"
        )
        queue_id = "0" * 32
        database.execute(
            "INSERT INTO ansible_queue(id,server_id,plan_id,actor_id,source_session_id,state,not_before,expires_at,created_at)VALUES(?,'fixture','fixture-queued-plan',?,'expired-fixture-session','waiting',CURRENT_TIMESTAMP,datetime('now','+20 minutes'),CURRENT_TIMESTAMP)",
            (queue_id, owner[0]),
        )
        automation_queries["organizations"] = (
            "SELECT id,server_id,login,organization_id,client_id,installation_id,disabled,created_by,created_at FROM github_organizations ORDER BY id"
        )
        automation_queries["organization_changes"] = (
            "SELECT id,server_id,connection_id,actor_id,source_session_id,kind,state,resource_id,expires_at FROM github_organization_changes ORDER BY id"
        )
        automation_queries["project_templates"] = (
            "SELECT id,server_id,name,digest,archived FROM ansible_templates ORDER BY id"
        )
        automation_queries["source_revisions"] = (
            "SELECT id,project_id,server_id,digest,source_connection_id,source_repository_id,source_commit_sha FROM ansible_revisions ORDER BY id"
        )

        automation_rows = {
            name: database.execute(query).fetchall() for name, query in automation_queries.items()
        }
        host_id = hashlib.sha256(b"fixture\0host\0registered-host").hexdigest()
        service_id = hashlib.sha256(b"fixture\0service\0ssh.service").hexdigest()
        interface_id = hashlib.sha256(b"fixture\0interface\0eth0").hexdigest()
        device_id = hashlib.sha256(b"fixture\0block_device\0vda1").hexdigest()
        network_id = hashlib.sha256(("fixture\0docker_network\0" + "b" * 64).encode()).hexdigest()
        link_id = hashlib.sha256(
            ("fixture\0" + host_id + "\0manages\0" + service_id).encode()
        ).hexdigest()
        for resource_id, kind, natural_key, name, source in [
            (host_id, "host", "registered-host", "fixture-host", "ssh"),
            (service_id, "service", "ssh.service", "ssh.service", "systemd"),
            (interface_id, "interface", "eth0", "eth0", "ip-address"),
            (device_id, "block_device", "vda1", "vda1", "lsblk"),
            (network_id, "docker_network", "b" * 64, "fixture-network", "docker-network"),
        ]:
            database.execute(
                "INSERT INTO inventory_resources(id,server_id,kind,natural_key,display_name,source,fingerprint,first_seen_at,last_seen_at,last_verified_at,data_state)VALUES(?,'fixture',?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fresh')",
                (resource_id, kind, natural_key, name, source, "3" * 64),
            )
        database.execute(
            "INSERT INTO inventory_hosts(resource_id,hostname,os,kernel)VALUES(?,'fixture-host','Fixture Linux','fixture-kernel')",
            (host_id,),
        )
        database.execute(
            "INSERT INTO inventory_services(resource_id,unit,load,active,sub)VALUES(?,'ssh.service','loaded','active','running')",
            (service_id,),
        )
        database.execute(
            "INSERT INTO inventory_interfaces(resource_id,name,mtu,state)VALUES(?,'eth0',1500,'UP')",
            (interface_id,),
        )
        database.execute(
            "INSERT INTO inventory_block_devices(resource_id,name,type,device_number,size_bytes,read_only)VALUES(?,'vda1','part','254:1',10737418240,0)",
            (device_id,),
        )
        database.execute(
            "INSERT INTO inventory_docker_networks(resource_id,engine_id,name,driver,scope)VALUES(?,?,'fixture-network','bridge','local')",
            (network_id, "b" * 64),
        )
        database.execute(
            "INSERT INTO inventory_documents(server_id,notes,revision,updated_at)VALUES('fixture','Fixture maintenance notes',1,CURRENT_TIMESTAMP)"
        )
        database.execute(
            "INSERT INTO inventory_relationships(id,server_id,source_id,target_id,kind,source,first_seen_at,last_verified_at,data_state)VALUES(?,'fixture',?,?,'manages','systemd',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'fresh')",
            (link_id, host_id, service_id),
        )
        database.execute(
            "INSERT INTO discovery_runs(id,server_id,actor_id,status,started_at,finished_at,warning)VALUES('scan','fixture',?,'succeeded',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'')",
            (owner[0],),
        )
        after = json.dumps(
            {"name": "ssh.service", "details": {"active": "active"}}, separators=(",", ":")
        )
        before = json.dumps(
            {"name": "ssh.service", "details": {"active": "inactive"}}, separators=(",", ":")
        )
        database.execute(
            "INSERT INTO inventory_changes(server_id,run_id,resource_id,kind,at,before_json,after_json)VALUES('fixture','scan',?,'updated',CURRENT_TIMESTAMP,?,?)",
            (service_id, before, after),
        )
        database.execute(
            "UPDATE inventory_resources SET last_run_id='scan' WHERE server_id='fixture'"
        )
        database.execute(
            "UPDATE inventory_relationships SET last_run_id='scan' WHERE server_id='fixture'"
        )
        database.execute(
            "INSERT INTO inventory_collection_sources(run_id,source,server_id,status,collected_at)VALUES('scan','ssh','fixture','ok',CURRENT_TIMESTAMP)"
        )
        database.execute(
            "INSERT INTO inventory_policies(server_id,actor_id,enabled,interval_minutes,freshness_minutes,retention_days,revision,next_run_at,updated_at)VALUES('fixture',?,1,60,15,0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
            (owner[0],),
        )
        inventory_queries = {
            "policies": "SELECT server_id,actor_id,interval_minutes,freshness_minutes,retention_days,revision,next_run_at,updated_at FROM inventory_policies ORDER BY server_id",
            "sources": "SELECT * FROM inventory_collection_sources ORDER BY run_id,source",
            "resources": "SELECT * FROM inventory_resources ORDER BY id",
            "hosts": "SELECT * FROM inventory_hosts ORDER BY resource_id",
            "services": "SELECT * FROM inventory_services ORDER BY resource_id",
            "interfaces": "SELECT * FROM inventory_interfaces ORDER BY resource_id",
            "block_devices": "SELECT * FROM inventory_block_devices ORDER BY resource_id",
            "containers": "SELECT * FROM inventory_containers ORDER BY resource_id",
            "docker_networks": "SELECT * FROM inventory_docker_networks ORDER BY resource_id",
            "documents": "SELECT * FROM inventory_documents ORDER BY server_id",
            "relationships": "SELECT * FROM inventory_relationships ORDER BY id",
            "changes": "SELECT * FROM inventory_changes ORDER BY id",
            "runs": "SELECT * FROM discovery_runs ORDER BY id",
        }
        inventory_rows = {
            name: database.execute(query).fetchall() for name, query in inventory_queries.items()
        }
    wrong = dict(env, NEXUS_ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode())
    assert (
        cli(
            args.new_image,
            "db-migrate",
            "--from-env",
            "/data/fixture.db",
            extra_env=wrong,
            check=False,
        ).returncode
        != 0
    ), "wrong-key reopen accepted"
    assert cli(args.old_image, "db-migrate", "/data/fixture.db", check=False).returncode != 0, (
        "old binary accepted new schema"
    )
    snapshots = list(Path(directory).glob("fixture.db.pre-migration-*.db"))
    assert snapshots, "missing pre-migration recovery set"
    for snapshot in snapshots:
        assert snapshot.stat().st_mode & 0o777 == 0o600, "snapshot must remain private"
        cli(args.old_image, "db-migrate", "/data/" + snapshot.name)
        with sqlite3.connect(snapshot) as database:
            assert database.execute("SELECT max(version) FROM schema_migrations").fetchone()[0] == 8
            assert (
                database.execute("SELECT vars_json FROM deployed_apps WHERE id='app'").fetchone()[0]
                == values
            )
    current_key = Path(directory) / "current-key.base64"
    current_key.write_bytes(base64.b64encode(key) + b"\n")
    current_key.chmod(0o600)
    cli(
        args.new_image,
        "key-rotate",
        "--offline",
        "--key-file",
        "/data/current-key.base64",
        "/data/fixture.db",
        "/data/rotated",
    )
    rotated = Path(directory) / "rotated"
    assert (rotated / "READY").is_file(), "rotation not completed"
    new_key = base64.b64decode((rotated / "encryption-key.base64").read_bytes().strip())
    assert new_key != key
    for item in rotated.iterdir():
        assert item.stat().st_mode & 0o777 == 0o600, "rotation files must remain private"
    rotated_env = dict(env, NEXUS_ENCRYPTION_KEY=base64.b64encode(new_key).decode())
    cli(args.new_image, "db-migrate", "--from-env", "/data/rotated/nexus.db", extra_env=rotated_env)
    assert (
        cli(
            args.new_image, "db-migrate", "--from-env", "/data/rotated/nexus.db", check=False
        ).returncode
        != 0
    ), "rotated DB accepted old key"
    with sqlite3.connect(rotated / "nexus.db") as database:
        sealed = base64.b64decode(
            database.execute("SELECT vars_enc FROM deployed_apps WHERE id='app'").fetchone()[0][3:]
        )
        assert AESGCM(new_key).decrypt(sealed[:12], sealed[12:], associated).decode() == values
        sealed = base64.b64decode(
            database.execute("SELECT private_key_enc FROM servers WHERE id='fixture'").fetchone()[0]
        )
        assert (
            AESGCM(new_key).decrypt(sealed[:12], sealed[12:], None)
            == b"fixture private SSH material"
        )
        assert (
            database.execute(
                "SELECT id,username,password_hash,status FROM users WHERE username='owner'"
            ).fetchone()
            == owner
        )
        assert database.execute(
            "SELECT port,tls_name,ca_pem,namespace FROM vault_connections WHERE server_id='fixture'"
        ).fetchone() == (8200, "vault.fixture", "", "")
        notification_sealed = base64.b64decode(
            database.execute(
                "SELECT telegram_token_enc FROM alert_configs WHERE id='default'"
            ).fetchone()[0][3:]
        )
        assert (
            AESGCM(new_key)
            .decrypt(notification_sealed[:12], notification_sealed[12:], notification_aad)
            .decode()
            == notification_token
        )
        assert (
            database.execute(
                "SELECT telegram_enabled FROM alert_configs WHERE id='default'"
            ).fetchone()[0]
            == 0
        )
        job_sealed = base64.b64decode(
            database.execute("SELECT output_enc FROM supervised_runs WHERE id='job'").fetchone()[0][
                3:
            ]
        )
        assert (
            AESGCM(new_key).decrypt(job_sealed[:12], job_sealed[12:], job_aad).decode()
            == job_output
        )
        operation = database.execute(
            "SELECT kind,action,source_session_id,target_hash,output_enc FROM supervised_runs WHERE id=?",
            (operation_id,),
        ).fetchone()
        assert operation[:4] == ("operation", "compose-up", "expired-fixture-session", "2" * 64)
        sealed = base64.b64decode(operation[4][3:])
        assert (
            AESGCM(new_key).decrypt(sealed[:12], sealed[12:], operation_aad).decode()
            == operation_output
        )
        sealed = base64.b64decode(
            database.execute(
                "SELECT output_enc FROM supervised_runs WHERE id=?", (ansible_id,)
            ).fetchone()[0][3:]
        )
        assert (
            AESGCM(new_key).decrypt(sealed[:12], sealed[12:], ansible_aad).decode()
            == ansible_output
        )
        for table, identity, field, associated, expected in [
            ("github_connections", connection_id, "config_enc", connection_aad, github_config),
            ("github_dispatches", dispatch_id, "input_enc", dispatch_aad, github_input),
            ("github_changes", change_id, "input_enc", change_aad, github_change),
        ] + new_automation_fields:
            identity_column = "run_id" if table == "backup_retention_jobs" else "id"
            sealed = base64.b64decode(
                database.execute(
                    f"SELECT {field} FROM {table} WHERE {identity_column}=?", (identity,)
                ).fetchone()[0][3:]
            )
            assert (
                AESGCM(new_key).decrypt(sealed[:12], sealed[12:], associated).decode() == expected
            )
        assert database.execute(
            "SELECT enabled,claim_id,lease_until,last_status FROM inventory_policies WHERE server_id='fixture'"
        ).fetchone() == (0, "", None, "recovery_copy")
        assert (
            database.execute(
                "SELECT disabled FROM github_webhooks WHERE id=?", (hook_id,)
            ).fetchone()[0]
            == 1
        )
        assert database.execute(
            "SELECT enabled,last_state FROM ansible_schedules WHERE id=?", (schedule_id,)
        ).fetchone() == (0, "recovery_copy")
        for backup_id in backup_ids:
            assert database.execute(
                "SELECT enabled,last_state FROM backup_policies WHERE id=?", (backup_id,)
            ).fetchone() == (0, "recovery_copy")
        assert (
            database.execute(
                "SELECT enabled FROM scheduled_tasks WHERE id='backup-recovery-task'"
            ).fetchone()[0]
            == 0
        )
        assert database.execute(
            "SELECT state,detail FROM ansible_queue WHERE id=?", (queue_id,)
        ).fetchone() == ("cancelled", "recovery_copy")
        for name, query in automation_queries.items():
            assert database.execute(query).fetchall() == automation_rows[name], (
                f"rotation changed automation {name}"
            )
        for name, query in inventory_queries.items():
            assert database.execute(query).fetchall() == inventory_rows[name], (
                f"rotation changed inventory {name}"
            )
    cli(args.new_image, "db-migrate", "--from-env", "/data/fixture.db")
    with sqlite3.connect(path) as database:
        assert (
            database.execute(
                "SELECT enabled FROM inventory_policies WHERE server_id='fixture'"
            ).fetchone()[0]
            == 1
        )
        assert (
            database.execute(
                "SELECT telegram_enabled FROM alert_configs WHERE id='default'"
            ).fetchone()[0]
            == 1
        )
        assert (
            database.execute(
                "SELECT disabled FROM github_webhooks WHERE id=?", (hook_id,)
            ).fetchone()[0]
            == 0
        )
        assert (
            database.execute(
                "SELECT enabled FROM ansible_schedules WHERE id=?", (schedule_id,)
            ).fetchone()[0]
            == 1
        )
        for backup_id in backup_ids:
            assert (
                database.execute(
                    "SELECT enabled FROM backup_policies WHERE id=?", (backup_id,)
                ).fetchone()[0]
                == 1
            )
        assert (
            database.execute(
                "SELECT enabled FROM scheduled_tasks WHERE id='backup-recovery-task'"
            ).fetchone()[0]
            == 1
        )
        assert (
            database.execute("SELECT state FROM ansible_queue WHERE id=?", (queue_id,)).fetchone()[
                0
            ]
            == "waiting"
        )
        for name, query in automation_queries.items():
            assert database.execute(query).fetchall() == automation_rows[name], (
                f"rotation changed source automation {name}"
            )
        for name, query in inventory_queries.items():
            assert database.execute(query).fetchall() == inventory_rows[name], (
                f"rotation changed source inventory {name}"
            )
    print("Offline image upgrade, rotation and recovery checks passed.")
