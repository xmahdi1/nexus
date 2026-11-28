"""Fixed backup adapter. Structured settings arrive on private stdin only."""

import bz2
import ctypes
import signal
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

PHASE = "validation"
HEX = re.compile(r"^[a-f0-9]{32}$")
SNAPSHOT = re.compile(r"^[a-f0-9]{64}$")
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]


def parent_death():
    # The native Nexus worker also binds this adapter to its parent. Each direct
    # export/repository child stops if the adapter disappears before cleanup.
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise ValueError("parent-death guard")
    if os.getppid() == 1:
        os.kill(os.getpid(), signal.SIGKILL)


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("private directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("directory ownership")
    return path


def binary_for(root):
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or arch not in PINS["assets"]:
        raise ValueError("unsupported platform")
    return root / "tools" / ("restic-" + PINS["version"]), PINS["assets"][arch]


def check_binary(binary, pin):
    info = binary.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
        or info.st_nlink != 1
    ):
        raise ValueError("tool ownership")
    with binary.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != pin["binarySHA256"]:
            raise ValueError("tool identity")


def install(root, binary, pin):
    tools = private_directory(root / "tools")
    if binary.exists():
        check_binary(binary, pin)
        return
    with urllib.request.urlopen(pin["url"], timeout=30) as response:
        data = response.read((64 << 20) + 1)
    if len(data) > 64 << 20 or hashlib.sha256(data).hexdigest() != pin["archiveSHA256"]:
        raise ValueError("download identity")
    unpacked = bz2.decompress(data)
    if (
        len(unpacked) > 128 << 20
        or hashlib.sha256(unpacked).hexdigest() != pin["binarySHA256"]
    ):
        raise ValueError("binary identity")
    fd, temporary = tempfile.mkstemp(prefix="install-", dir=tools)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(unpacked)
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o500)
        # Exclusive publication; a competing install never replaces a file.
        os.link(temporary, binary)
    finally:
        os.unlink(temporary)
    check_binary(binary, pin)


def safe_process(
    command, output, environment, limit, input_data=None, accepted_codes=(0,)
):
    options = (
        {"stdin": subprocess.DEVNULL}
        if input_data is None
        else {"stdin": subprocess.PIPE}
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        preexec_fn=parent_death,
        **options
    )
    try:
        if input_data is not None:
            process.stdin.write(input_data)
            process.stdin.close()
        count = 0
        while True:
            data = process.stdout.read(256 << 10)
            if not data:
                break
            count += len(data)
            if (
                count > limit
                or shutil.disk_usage(Path(output.name).parent).free < 64 << 20
            ):
                raise ValueError("export capacity")
            output.write(data)
        code = process.wait(timeout=30)
        if code not in accepted_codes:
            raise ValueError("export failed")
        return code
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


def export_source(source, stage, index, environment, private_stage, limit):
    kind = source["kind"]
    if kind == "files":
        path = Path(source["path"])
        if not (path.is_file() or path.is_dir()):
            raise ValueError("source missing")
        return str(path)
    if kind == "docker-volume":
        output = subprocess.check_output(
            DOCKER + ["volume", "inspect", "--", source["volume"]],
            env=environment,
            timeout=15,
            stderr=subprocess.DEVNULL,
            preexec_fn=parent_death,
        )
        record = json.loads(output)
        if (
            len(record) != 1
            or record[0]["Name"] != source["volume"]
            or record[0].get("Driver") != "local"
        ):
            raise ValueError("volume unavailable")
        path = Path(record[0]["Mountpoint"])
        if not path.is_absolute() or not path.is_dir():
            raise ValueError("volume path")
        return str(path)
    if kind == "docker-bind":
        record = json.loads(
            subprocess.check_output(
                DOCKER + ["inspect", "--", source["containerId"]],
                env=environment,
                timeout=15,
                stderr=subprocess.DEVNULL,
                preexec_fn=parent_death,
            )
        )
        if (
            len(record) != 1
            or record[0]["Id"] != source["containerId"]
            or not any(
                m.get("Type") == "bind" and m.get("Source") == source["path"]
                for m in record[0].get("Mounts", [])
            )
        ):
            raise ValueError("bind identity changed")
        if not Path(source["path"]).exists():
            raise ValueError("bind path unavailable")
        return source["path"]
    destination = stage / (
        "source-"
        + str(index)
        + (
            ".sqlite3"
            if kind == "sqlite"
            else ".archive.gz" if kind == "mongodb" else ".sql"
        )
    )
    if kind == "sqlite":
        uri = Path(source["path"]).as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=10) as database, sqlite3.connect(
            destination
        ) as target:
            page_size = database.execute("PRAGMA page_size").fetchone()[0]

            def progress(status, remaining, total):
                if (
                    total * page_size > limit
                    or shutil.disk_usage(stage).free < 64 << 20
                ):
                    raise ValueError("SQLite export capacity")

            database.backup(target, pages=1024, progress=progress)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("SQLite integrity")
        os.chmod(destination, 0o600)
        return str(destination)
    db = source.get("database", {})
    child_env = dict(environment)
    input_data = None
    if source.get("containerId") and kind == "mongodb":
        command = DOCKER + [
            "exec",
            "-i",
            source["containerId"],
            "mongodump",
            "--archive",
            "--gzip",
        ]
        if db.get("user"):
            command += [
                "--config=/dev/stdin",
                "--username=" + db["user"],
                "--authenticationDatabase=admin",
            ]
            input_data = json.dumps({"password": db.get("password", "")}).encode()
        if db.get("name"):
            command += ["--db=" + db["name"]]
    elif source.get("containerId"):
        # These scripts are fixed. Credentials stay inside the selected container;
        # neither inspect output nor stdout returns its environment to Nexus.
        scripts = {
            "postgres": 'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dumpall --no-password --username="${POSTGRES_USER:-postgres}"',
            "mysql": 'if [ -n "$MYSQL_ROOT_PASSWORD" ]; then export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; user=root; else export MYSQL_PWD="$MYSQL_PASSWORD"; user="${MYSQL_USER:-root}"; fi; exec mysqldump --single-transaction --quick --all-databases --user="$user"',
            "mariadb": 'if [ -n "${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}" ]; then export MYSQL_PWD="${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}"; user=root; else export MYSQL_PWD="$MARIADB_PASSWORD"; user="${MARIADB_USER:-root}"; fi; exec mariadb-dump --single-transaction --quick --all-databases --user="$user"',
        }
        command = DOCKER + [
            "exec",
            source["containerId"],
            "/bin/sh",
            "-c",
            scripts[kind],
        ]
    elif kind == "postgres":
        child_env["PGPASSWORD"] = db.get("password", "")
        command = [
            "pg_dumpall",
            "--no-password",
            "--host=" + db["host"],
            "--port=" + str(db["port"]),
            "--username=" + db["user"],
        ]
        if db.get("name"):
            command = [
                "pg_dump",
                "--no-password",
                "--host=" + db["host"],
                "--port=" + str(db["port"]),
                "--username=" + db["user"],
                "--dbname=" + db["name"],
            ]
    elif kind in ("mysql", "mariadb"):
        # Per-process defaults file keeps passwords out of argv and shell text.
        defaults = private_stage / ("mysql-" + str(index) + ".cnf")
        password = (
            db.get("password", "")
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        defaults.write_text('[client]\npassword="' + password + '"\n')
        defaults.chmod(0o600)
        command = [
            "mariadb-dump" if kind == "mariadb" else "mysqldump",
            "--defaults-extra-file=" + str(defaults),
            "--single-transaction",
            "--quick",
            "--host=" + db["host"],
            "--port=" + str(db["port"]),
            "--user=" + db["user"],
        ]
        command += (
            ["--databases", db["name"]] if db.get("name") else ["--all-databases"]
        )
    elif kind == "mongodb":
        command = [
            "mongodump",
            "--config=/dev/stdin",
            "--archive",
            "--gzip",
            "--host=" + db["host"],
            "--port=" + str(db["port"]),
            "--username=" + db["user"],
            "--authenticationDatabase=admin",
        ]
        input_data = json.dumps({"password": db.get("password", "")}).encode()
        if db.get("name"):
            command += ["--db=" + db["name"]]
    else:
        raise ValueError("unsupported export")
    with destination.open("xb") as output:
        safe_process(command, output, child_env, limit, input_data=input_data)
        output.flush()
        os.fsync(output.fileno())
    return str(destination)


def main():
    global PHASE
    os.umask(0o077)
    request = json.loads(sys.stdin.buffer.read(96 * 1024 + 1))
    identity, policy = request["runId"], request["policyId"]
    if not HEX.fullmatch(identity) or not HEX.fullmatch(policy):
        raise ValueError("identity")
    action = request["action"]
    if action not in (
        "install",
        "init",
        "backup",
        "snapshots",
        "check",
        "restore",
        "verify",
        "cleanup",
        "retention-preview",
        "retention-apply",
    ):
        raise ValueError("action")
    root = private_directory(request["workRoot"])
    if action == "cleanup":
        candidates = [root / "jobs" / identity]
        candidates += list(
            Path(tempfile.gettempdir()).glob("nexus-export-" + identity + "-*")
        )
        candidates += list(
            Path(tempfile.gettempdir()).glob("nexus-recovery-" + identity + "-*")
        )
        for candidate in candidates:
            if candidate.exists() or candidate.is_symlink():
                info = candidate.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("cleanup ownership")
                shutil.rmtree(candidate)
        print(json.dumps({"state": "cleaned", "verified": True}))
        return 0
    binary, pin = binary_for(root)
    PHASE = "tool"
    if action == "install":
        PHASE = "install"
        install(root, binary, pin)
        print(json.dumps({"state": "ready", "verified": True}))
        return 0
    check_binary(binary, pin)
    config = request["definition"]
    repository = config["repository"]
    if repository["kind"] == "local" and (
        Path(repository["location"]) == root
        or root in Path(repository["location"]).parents
    ):
        raise ValueError("repository uses managed storage")
    tag = "nexus-policy-" + policy
    jobs = private_directory(root / "jobs")
    stage = jobs / identity
    stage.mkdir(mode=0o700)  # A reused run cannot replace staging files.
    exports = Path(tempfile.mkdtemp(prefix="nexus-export-" + identity + "-"))
    try:
        password = stage / "repository-password"
        password.write_text(repository["password"] + "\n")
        password.chmod(0o600)
        repo_file = stage / "repository"
        repo_file.write_text(repository["location"] + "\n")
        repo_file.chmod(0o600)
        cache = private_directory(root / "cache")
        environment = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "HOME": str(stage),
            "RESTIC_REPOSITORY_FILE": str(repo_file),
            "RESTIC_PASSWORD_FILE": str(password),
            "RESTIC_CACHE_DIR": str(cache),
        }
        if repository["kind"] == "s3":
            environment.update(
                AWS_ACCESS_KEY_ID=repository["accessKey"],
                AWS_SECRET_ACCESS_KEY=repository["secretKey"],
            )
            if repository.get("region"):
                environment["AWS_DEFAULT_REGION"] = repository["region"]
            if repository.get("sessionToken"):
                environment["AWS_SESSION_TOKEN"] = repository["sessionToken"]
        else:
            path = Path(repository["location"])
            if path.is_symlink() or path.resolve() != path:
                raise ValueError("repository link")
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        def restic(arguments):
            options = (
                [
                    "-o",
                    "s3.bucket-lookup=" + (repository.get("bucketLookup") or "auto"),
                    "-o",
                    "s3.retries=2",
                ]
                if repository["kind"] == "s3"
                else []
            )
            # Bound output while it is produced; upstream diagnostics can include
            # private paths and are discarded instead of filling staging storage.
            with (stage / "result").open("w+b") as output:
                code = safe_process(
                    [str(binary), "--json", "--quiet"] + options + arguments,
                    output,
                    environment,
                    32 << 20,
                    accepted_codes=(0, 3),
                )
                output.seek(0)
                data = output.read(32 << 20)
            return code, data

        PHASE = "repository"
        if action == "init":
            code, _ = restic(["init"])
            if code:
                raise ValueError("repository init")
            print(json.dumps({"state": "initialized", "verified": True}))
            return 0
        snapshot = request.get("snapshotId", "")
        if snapshot and not SNAPSHOT.fullmatch(snapshot):
            raise ValueError("snapshot")
        retention = request.get("retention")
        query = (
            ["snapshots", snapshot]
            if snapshot
            else ["snapshots", "--tag=" + tag, "--group-by="]
        )
        if not snapshot and not action.startswith("retention-"):
            query += ["--latest=50"]
        code, data = restic(query)
        if code:
            raise ValueError("repository access")
        found = json.loads(data or "[]")
        if not isinstance(found, list) or len(found) > (
            500 if action.startswith("retention-") else 50
        ):
            raise ValueError("snapshot count")
        if action.startswith("retention-"):
            PHASE = "retention"
            if (
                not isinstance(retention, dict)
                or not 1 <= retention.get("keepLast", 0) <= 500
            ):
                raise ValueError("retention settings")
            # Bind the preview to the full policy snapshot set, including tags.
            # Unknown/imported/incomplete snapshots are always preserved.
            inventory = sorted(
                [
                    {
                        "id": row["id"],
                        "time": row["time"],
                        "tags": sorted(row.get("tags", [])),
                    }
                    for row in found
                    if SNAPSHOT.fullmatch(row.get("id", ""))
                    and tag in row.get("tags", [])
                ],
                key=lambda row: row["id"],
            )
            digest = hashlib.sha256(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if action == "retention-preview":
                eligible = retention.get("eligibleIds", [])
                if (
                    not isinstance(eligible, list)
                    or len(eligible) > 500
                    or any(not SNAPSHOT.fullmatch(i) for i in eligible)
                ):
                    raise ValueError("retention evidence")
                eligible = set(eligible)
                ordered = sorted(
                    [
                        row
                        for row in inventory
                        if row["id"] in eligible
                        and [
                            value
                            for value in row["tags"]
                            if value.startswith("nexus-policy-")
                        ]
                        == [tag]
                        and "nexus-keep" not in row["tags"]
                    ],
                    key=lambda row: (
                        datetime.datetime.fromisoformat(
                            row["time"].replace("Z", "+00:00")
                        ),
                        row["id"],
                    ),
                    reverse=True,
                )
                remove = sorted(row["id"] for row in ordered[retention["keepLast"] :])
                result = {
                    "keepLast": retention["keepLast"],
                    "inventoryDigest": digest,
                    "removeIds": remove,
                    "keptCount": len(inventory) - len(remove),
                    "unclassifiedCount": len(inventory) - len(ordered),
                }
                print(
                    json.dumps(
                        {
                            "state": "retention_preview",
                            "verified": True,
                            "retention": result,
                        }
                    )
                )
                return 0
            remove = retention.get("removeIds", [])
            if (
                retention.get("inventoryDigest") != digest
                or not isinstance(remove, list)
                or len(remove) != len(set(remove))
                or any(not SNAPSHOT.fullmatch(i) for i in remove)
            ):
                raise ValueError("retention preview changed")
            identities = {row["id"] for row in inventory}
            if (
                not set(remove).issubset(identities)
                or len(identities) - len(remove) < retention["keepLast"]
            ):
                raise ValueError("retention would remove retained snapshots")
            if remove:
                code, _ = restic(["forget", "--"] + remove)
                if code:
                    raise ValueError("retention forget")
                code, _ = restic(["prune"])
                if code:
                    raise ValueError("retention prune")
            print(
                json.dumps(
                    {
                        "state": "retention_applied",
                        "verified": True,
                        "retention": {
                            "keepLast": retention["keepLast"],
                            "inventoryDigest": digest,
                            "removeIds": remove,
                            "keptCount": len(identities) - len(remove),
                            "unclassifiedCount": retention.get("unclassifiedCount", 0),
                        },
                    }
                )
            )
            return 0
        snapshots = [
            {"id": row["id"], "time": row["time"]}
            for row in found
            if SNAPSHOT.fullmatch(row.get("id", "")) and tag in row.get("tags", [])
        ]
        if action == "snapshots":
            print(
                json.dumps(
                    {"state": "snapshots", "snapshots": snapshots, "verified": False}
                )
            )
            return 0
        if action == "check":
            PHASE = "check"
            code, _ = restic(["check", "--read-data"])
            if code:
                raise ValueError("repository check")
            print(json.dumps({"state": "checked", "verified": True}))
            return 0
        if action in ("restore", "verify"):
            PHASE = "restore"
            if not snapshot or not any(s["id"] == snapshot for s in snapshots):
                raise ValueError("snapshot not in policy")
            restores = private_directory(private_directory(root / "restores") / policy)
            destination = restores / identity
            destination.mkdir(mode=0o700)
            code, _ = restic(
                ["restore", snapshot, "--target=" + str(destination), "--verify"]
            )
            if code:
                raise ValueError("restore failed")
            if action == "verify":
                shutil.rmtree(destination)
                result = {"state": "restored", "verified": True}
            else:
                result = {
                    "state": "restored",
                    "verified": True,
                    "restorePath": str(destination),
                }
            print(json.dumps(result))
            return 0
        PHASE = "source_export"
        sources = []
        export_environment = {
            key: value
            for key, value in environment.items()
            if not key.startswith("AWS_") and not key.startswith("RESTIC_")
        }
        export_limit = (config.get("exportLimitGiB") or 10) << 30
        manifest = {
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "engineVersion": PINS["version"],
            "sources": [],
        }
        for index, source in enumerate(config["sources"]):
            if source["kind"] == "nexus":
                nexus_path = Path(request["nexusDirectory"])
                if not nexus_path.is_dir() or nexus_path.is_symlink():
                    raise ValueError("Nexus snapshot directory")
                sources.append(str(nexus_path))
            else:
                exported = export_source(
                    source, exports, index, export_environment, stage, export_limit
                )
                selected = Path(exported).resolve()
                excluded_paths = [
                    root,
                    Path("/proc"),
                    Path("/sys"),
                    Path("/dev"),
                    Path("/run"),
                ]
                if repository["kind"] == "local":
                    excluded_paths.append(Path(repository["location"]))
                if any(
                    selected == excluded or excluded in selected.parents
                    for excluded in excluded_paths
                ):
                    raise ValueError("selected source is excluded storage")
                sources.append(exported)
                if Path(exported).parent == exports:
                    export_limit -= Path(exported).stat().st_size
            details = {
                key: source[key]
                for key in ("kind", "label", "path", "containerId", "volume")
                if source.get(key)
            }
            if source.get("database"):
                details["database"] = {
                    key: source["database"][key]
                    for key in ("host", "port", "name", "user")
                    if source["database"].get(key)
                }
            details["exportFile"] = (
                Path(sources[-1]).name if Path(sources[-1]).parent == exports else ""
            )
            manifest["sources"].append(details)
        manifest_file = exports / "nexus-manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        sources.append(str(manifest_file))
        # Secret defaults/password files are outside exports and never backed up.
        PHASE = "backup"
        arguments = [
            "backup",
            "--tag=" + tag,
            "--tag=nexus-run-" + identity,
            "--host=nexus-" + policy,
            "--exclude=" + str(root),
        ]
        if repository["kind"] == "local":
            arguments += ["--exclude=" + repository["location"]]
        for excluded in ("/proc", "/sys", "/dev", "/run"):
            arguments += ["--exclude=" + excluded]
        arguments += ["--"] + sources
        code, data = restic(arguments)
        summaries = []
        for line in data.splitlines():
            value = json.loads(line)
            if isinstance(value, dict) and value.get("message_type") == "summary":
                summaries.append(value)
        if code not in (0, 3) or not summaries:
            raise ValueError("backup failed")
        summary = summaries[-1]
        snapshot_id = summary.get("snapshot_id", "")
        if not SNAPSHOT.fullmatch(snapshot_id):
            raise ValueError("missing snapshot identity")
        print(
            json.dumps(
                {
                    "state": "completed" if code == 0 else "incomplete",
                    "snapshotId": snapshot_id,
                    "files": int(summary.get("total_files_processed", 0)),
                    "bytes": int(summary.get("total_bytes_processed", 0)),
                    "verified": False,
                }
            )
        )
        return 0 if code == 0 else 1
    finally:
        shutil.rmtree(exports)
        shutil.rmtree(stage)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Upstream messages can include secrets. Only fixed phases cross this boundary.
        print(json.dumps({"state": "failed", "phase": PHASE, "verified": False}))
        sys.exit(1)
