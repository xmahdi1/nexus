#!/usr/bin/env python3
"""Back up and restore native database exports in labeled, disposable containers."""

import argparse
import gzip
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--restic", required=True)
parser.add_argument("--postgres-image", required=True)
parser.add_argument("--mysql-image")
parser.add_argument("--mariadb-image")
parser.add_argument("--mongodb-image")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
pins = json.loads((root / "nexus/internal/backups/pins.json").read_text())
engine = "PINS=" + json.dumps(pins) + "\n" + (root / "nexus/internal/backups/engine.py").read_text()
images = [
    ("postgres", args.postgres_image),
    ("mysql", args.mysql_image),
    ("mariadb", args.mariadb_image),
    ("mongodb", args.mongodb_image),
]
for _, image in images:
    if image:
        assert re.fullmatch(r"(sha256:)?[a-f0-9]{12,64}", image), "Use an existing local image ID"
        subprocess.run(["docker", "image", "inspect", image], check=True, capture_output=True)
containers = []
nonce = uuid.uuid4().hex
try:
    with tempfile.TemporaryDirectory(prefix="nexus-backup-databases-") as directory:
        base = Path(directory)
        work = base / "work"
        work.mkdir(mode=0o700)
        (work / "tools").mkdir(mode=0o700)
        shutil.copyfile(args.restic, work / "tools/restic-0.20.0")
        (work / "tools/restic-0.20.0").chmod(0o500)
        value = secrets.token_hex(24)
        password = secrets.token_hex(24)
        sources = []
        kinds = []
        for kind, image in images:
            if not image:
                continue
            environment = dict(__import__("os").environ)
            variable = {
                "postgres": "POSTGRES_PASSWORD",
                "mysql": "MYSQL_ROOT_PASSWORD",
                "mariadb": "MARIADB_ROOT_PASSWORD",
                "mongodb": "MONGO_INITDB_ROOT_PASSWORD",
            }[kind]
            environment[variable] = password
            command = [
                "docker",
                "run",
                "-d",
                "--label",
                "nexus.backups.lab=" + nonce,
                "--pids-limit",
                "256",
                "--memory",
                "1g",
                "--cpus",
                "2",
                "-e",
                variable,
            ]
            if kind == "postgres":
                command += ["-e", "POSTGRES_USER=fixture", "-e", "POSTGRES_DB=fixture"]
            if kind == "mongodb":
                command += ["-e", "MONGO_INITDB_ROOT_USERNAME=root"]
            container = subprocess.check_output(
                command + [image], env=environment, text=True
            ).strip()
            containers.append(container)
            if kind == "postgres":
                # The image starts a socket-only server while initializing. Wait for the
                # final TCP listener so preparation cannot race that server's shutdown.
                ready = ["pg_isready", "-h", "127.0.0.1", "-U", "fixture", "-d", "fixture"]
                sql = (
                    "CREATE TABLE sample(value text);INSERT INTO sample(value)VALUES('"
                    + value
                    + "');"
                )
                prepare = ["psql", "-U", "fixture", "-d", "fixture", "-v", "ON_ERROR_STOP=1"]
            elif kind in ("mysql", "mariadb"):
                client = "mariadb" if kind == "mariadb" else "mysql"
                admin = "mariadb-admin" if kind == "mariadb" else "mysqladmin"
                shell = 'export MYSQL_PWD="${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}";exec '
                ready = [
                    "/bin/sh",
                    "-c",
                    shell + admin + " --protocol=tcp --host=127.0.0.1 --user=root ping --silent",
                ]
                prepare = ["/bin/sh", "-c", shell + client + " --user=root"]
                sql = (
                    "CREATE DATABASE fixture;USE fixture;CREATE TABLE sample(value text);INSERT INTO sample(value)VALUES('"
                    + value
                    + "');"
                )
            else:
                ready = [
                    "mongosh",
                    "--quiet",
                    "--eval",
                    "const a=db.getSiblingDB('admin');if(!a.auth(process.env.MONGO_INITDB_ROOT_USERNAME,process.env.MONGO_INITDB_ROOT_PASSWORD)){quit(1)};if(a.runCommand({ping:1}).ok!==1){quit(1)}",
                ]
                prepare = [
                    "mongosh",
                    "--quiet",
                    "--eval",
                    "db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME,process.env.MONGO_INITDB_ROOT_PASSWORD);db.getSiblingDB('fixture').sample.insertOne({value:'"
                    + value
                    + "'})",
                ]
                sql = ""
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                test = subprocess.run(
                    ["docker", "exec", container, *ready], capture_output=True, timeout=10
                )
                if test.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(kind + " fixture did not become ready")
            subprocess.run(
                ["docker", "exec", "-i", container, *prepare],
                input=sql.encode(),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            database = {"containerEnvironment": True}
            if kind == "mongodb":
                database = {"user": "root", "password": password}
            sources.append(
                {
                    "kind": kind,
                    "label": "Owned " + kind,
                    "containerId": container,
                    "database": database,
                }
            )
            kinds.append((kind, container, prepare))
        policy = uuid.uuid4().hex
        definition = {
            "repository": {
                "kind": "local",
                "location": str(base / "repository"),
                "password": secrets.token_hex(24),
            },
            "sources": sources,
            "runtimeSeconds": 180,
            "exportLimitGiB": 1,
        }

        def action(name, snapshot=""):
            run = uuid.uuid4().hex
            request = {
                "action": name,
                "runId": run,
                "policyId": policy,
                "definition": definition,
                "workRoot": str(work),
                "runtimeSeconds": 180,
            }
            if snapshot:
                request["snapshotId"] = snapshot
            process = subprocess.run(
                ["python3", "-I", "-c", engine],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                timeout=240,
            )
            assert (
                value not in process.stdout + process.stderr
                and password not in process.stdout + process.stderr
            ), "Fixture secret appeared in output"
            if process.returncode:
                raise RuntimeError("Database " + name + " failed: " + process.stdout[-300:])
            return json.loads(process.stdout)

        action("init")
        backup = action("backup")
        restored = action("restore", backup["snapshotId"])
        destination = Path(restored["restorePath"])
        assert restored["verified"]
        for index, (kind, container, prepare) in enumerate(kinds):
            files = list(
                destination.rglob(
                    "source-" + str(index) + (".archive.gz" if kind == "mongodb" else ".sql")
                )
            )
            assert len(files) == 1, (kind, "missing export")
            if kind == "postgres":
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container,
                        "psql",
                        "-U",
                        "fixture",
                        "-d",
                        "postgres",
                        "-c",
                        "DROP DATABASE fixture;",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["docker", "exec", "-i", container, "psql", "-U", "fixture", "-d", "postgres"],
                    input=files[0].read_bytes(),
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60,
                )
                result = subprocess.check_output(
                    [
                        "docker",
                        "exec",
                        container,
                        "psql",
                        "-U",
                        "fixture",
                        "-d",
                        "fixture",
                        "-Atc",
                        "SELECT value FROM sample;",
                    ],
                    text=True,
                )
                assert result.strip() == value, "PostgreSQL restore content mismatch"
            elif kind in ("mysql", "mariadb"):
                subprocess.run(
                    ["docker", "exec", "-i", container, *prepare],
                    input=b"DROP DATABASE fixture;CREATE DATABASE fixture;",
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                restore = prepare[:-1] + [prepare[-1] + " --one-database fixture"]
                subprocess.run(
                    ["docker", "exec", "-i", container, *restore],
                    input=files[0].read_bytes(),
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60,
                )
                result = subprocess.check_output(
                    ["docker", "exec", "-i", container, *prepare],
                    input=b"SELECT value FROM fixture.sample;",
                )
                assert value.encode() in result, "SQL restore content mismatch"
            else:
                assert value.encode() in gzip.decompress(files[0].read_bytes()), (
                    "MongoDB archive did not contain fixture data"
                )
                archive = "/tmp/nexus-fixture-" + nonce + ".archive.gz"
                subprocess.run(
                    ["docker", "cp", str(files[0]), container + ":" + archive],
                    check=True,
                    capture_output=True,
                )
                auth_script = "db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME,process.env.MONGO_INITDB_ROOT_PASSWORD);"
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        container,
                        "mongosh",
                        "--quiet",
                        "--eval",
                        auth_script + "db.getSiblingDB('fixture').dropDatabase()",
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        container,
                        "mongorestore",
                        "--config=/dev/stdin",
                        "--username=root",
                        "--authenticationDatabase=admin",
                        "--gzip",
                        "--archive=" + archive,
                    ],
                    input=json.dumps({"password": password}).encode(),
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60,
                )
                result = subprocess.check_output(
                    [
                        "docker",
                        "exec",
                        container,
                        "mongosh",
                        "--quiet",
                        "--eval",
                        auth_script + "print(db.getSiblingDB('fixture').sample.findOne().value)",
                    ],
                    text=True,
                )
                assert value in result, "MongoDB restored document mismatch"
            print(
                kind
                + ": native authenticated export, repository backup, verified restore copy and database import passed.",
                flush=True,
            )
finally:
    for container in containers:
        details = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[
            0
        ]
        if details["Config"]["Labels"].get("nexus.backups.lab") != nonce or details[
            "HostConfig"
        ].get("PortBindings"):
            raise RuntimeError("Fixture ownership mismatch; refusing cleanup")
        subprocess.run(["docker", "rm", "-f", "-v", container], check=True, capture_output=True)
