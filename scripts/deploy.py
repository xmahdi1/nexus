#!/usr/bin/env python3
"""Interactive local Docker setup. Run from a source checkout; no extra Python packages."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def private_write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def snapshot(source, target):
    if not source.is_file() or source.is_symlink():
        raise RuntimeError("Database source must be an existing regular file.")
    private_write(target, b"")
    deadline = time.monotonic() + 30

    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise RuntimeError("Database copy timed out. Check that the old service is stopped.")

    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as original:
        original.execute("PRAGMA busy_timeout=5000")
        with sqlite3.connect(target) as backup:
            original.backup(backup, pages=256, sleep=0.1, progress=progress)
            if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Database integrity check failed.")


def ask(label, default=""):
    value = input(label + (f" [{default}]" if default else "") + ": ").strip()
    return value or default


def yes(label, default=False):
    while True:
        value = ask(label + (" (Y/n)" if default else " (y/N)")).lower()
        if not value:
            return default
        if value in ("y", "yes", "n", "no"):
            return value in ("y", "yes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, help="new installation directory (must be empty)")
    parser.add_argument("--image", help="use an already-local Nexus image instead of building")
    options = parser.parse_args()
    if os.name != "posix" or not sys.stdin.isatty():
        raise RuntimeError("Run in an interactive Linux/macOS terminal with local Docker.")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("NEXUS_", "COMPOSE_"))}

    def command(args, capture=False, check=True):
        return subprocess.run(args, env=env, check=check, capture_output=capture, text=True)

    command(["docker", "compose", "version"], capture=True)
    context = command(["docker", "context", "show"], capture=True).stdout.strip()
    endpoint = (
        os.environ.get("DOCKER_HOST")
        or json.loads(command(["docker", "context", "inspect", context], capture=True).stdout)[0][
            "Endpoints"
        ]["docker"]["Host"]
    )
    if not endpoint.startswith("unix://"):
        raise RuntimeError("This script requires a local Docker socket for its bind mounts.")
    mode = ask("Fresh installation or migrate an existing Nexus? (new/migrate)", "new")
    if mode not in ("new", "migrate"):
        raise RuntimeError("Choose new or migrate.")
    destination = (
        (options.directory or Path(ask("New installation directory", str(ROOT / "deployment"))))
        .expanduser()
        .absolute()
    )
    if destination.is_symlink() or any(parent.is_symlink() for parent in destination.parents):
        raise RuntimeError("Installation directory must not use symlinks.")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise RuntimeError(
            "Choose a new empty directory. Existing installations are never overwritten."
        )
    port = int(ask("Local host port", "8090"))
    if not 1024 <= port <= 65535:
        raise RuntimeError("Choose a port between 1024 and 65535.")
    proxy = yes("Will a trusted HTTPS proxy forward requests to Nexus?", True)
    automation = yes("Enable Ansible and GitHub tools?")
    backups = yes("Enable guided backups?")
    vault = yes("Enable Vault tools?")
    inventory = yes("Enable server inventory?")
    supervised = yes("Enable tracked jobs and operations?", automation or backups)
    source_env = source_db = old_binary = None
    old_container = old_image = ""
    if mode == "migrate":
        source_env = Path(ask("Existing matching .env file")).expanduser().resolve(strict=True)
        if not source_env.is_file():
            raise RuntimeError("The existing configuration must be a regular file.")
        raw = source_env.read_bytes()
        for key in (b"NEXUS_ENCRYPTION_KEY", b"NEXUS_PASSWORD_HASH"):
            if not re.search(rb"^\s*" + key + rb"\s*=\s*\S+", raw, re.M):
                raise RuntimeError(
                    "Existing configuration must include its original key and password hash."
                )
        old_container = ask("Old Nexus container name (leave blank for a native installation)")
        if old_container:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", old_container):
                raise RuntimeError("Invalid container name.")
            old_image = command(
                ["docker", "inspect", "--format", "{{.Image}}", old_container], capture=True
            ).stdout.strip()
            source_db = ask("Database path INSIDE that container", "/data/nexus.db")
            if not source_db.startswith("/") or "\x00" in source_db:
                raise RuntimeError(
                    "Use the existing absolute database path inside the old container."
                )
        else:
            source_db = Path(ask("Existing database file")).expanduser().resolve(strict=True)
            old_binary = (
                Path(ask("Old Nexus executable (saved for rollback)"))
                .expanduser()
                .resolve(strict=True)
            )
            if not old_binary.is_file():
                raise RuntimeError("Old executable must be a file.")
    print(f"\nInstall directory: {destination}\nLocal listener: 127.0.0.1:{port}\nMode: {mode}")
    print("A migration copies the old database/configuration. The old copy stays unchanged.")
    if old_container:
        print(f"The old container {old_container} will be stopped and left stopped.")
    if not yes("Build/prepare this installation and start it?", True):
        return
    if (
        mode == "migrate"
        and not old_container
        and ask("Stop the old Nexus process, then type STOPPED") != "STOPPED"
    ):
        raise RuntimeError("The old process must remain stopped during migration and cutover.")
    os.umask(0o077)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    (destination / "data").mkdir(mode=0o700)
    if options.image:
        image = command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", options.image], capture=True
        ).stdout.strip()
    else:
        tag = "nexus:setup-" + str(time.time_ns())
        with tempfile.TemporaryDirectory(prefix="nexus-build-") as workspace:
            source = Path(workspace) / "source"
            command([sys.executable, str(ROOT / "scripts/ci/export_source.py"), str(source)])
            command(["docker", "build", "-t", tag, str(source)])
        image = command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag], capture=True
        ).stdout.strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise RuntimeError("Could not identify the built image.")
    if mode == "new":
        command(
            [
                "docker",
                "run",
                "--rm",
                "-it",
                "--network",
                "none",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--mount",
                f"type=bind,source={destination},target=/setup",
                image,
                "setup",
                "--env-file",
                "/setup/.env",
            ]
        )
    else:
        recovery = destination / "recovery"
        recovery.mkdir(mode=0o700)
        if old_container:
            command(["docker", "stop", old_container], capture=True)
        saved_config = source_env.read_bytes()
        private_write(recovery / ".env", saved_config)
        private_write(destination / ".env", saved_config)
        if old_container:
            with tempfile.TemporaryDirectory(prefix="nexus-import-", dir=destination) as temp:
                copied = Path(temp) / "source.db"
                command(["docker", "cp", f"{old_container}:{source_db}", str(copied)], capture=True)
                for suffix in ("-wal", "-shm"):
                    command(
                        [
                            "docker",
                            "cp",
                            f"{old_container}:{source_db}{suffix}",
                            str(copied) + suffix,
                        ],
                        capture=True,
                        check=False,
                    )
                snapshot(copied, recovery / "nexus.db")
        else:
            private_write(recovery / "nexus", old_binary.read_bytes(), 0o700)
            snapshot(source_db, recovery / "nexus.db")
        snapshot(recovery / "nexus.db", destination / "data" / "nexus.db")
        private_write(
            recovery / "source.json",
            (
                json.dumps(
                    {"container": old_container, "image": old_image, "database": str(source_db)},
                    indent=2,
                )
                + "\n"
            ).encode(),
        )
    additions = {
        "NEXUS_DB_PATH": "/data/nexus.db",
        "NEXUS_PORT": "8080",
        "NEXUS_TRUST_PROXY": str(proxy).lower(),
        "NEXUS_ENABLE_AUTOMATION": str(automation).lower(),
        "NEXUS_ENABLE_BACKUPS": str(backups).lower(),
        "NEXUS_ENABLE_VAULT": str(vault).lower(),
        "NEXUS_ENABLE_INVENTORY": str(inventory).lower(),
        "NEXUS_ENABLE_JOB_SUPERVISION": str(supervised).lower(),
        "NEXUS_ENABLE_OPERATION_SUPERVISION": str(supervised).lower(),
    }
    with (destination / ".env").open("ab") as output:
        output.write(("\n" + "\n".join(f"{k}={v}" for k, v in additions.items()) + "\n").encode())
    runtime_uid = os.getuid() or 1000
    runtime_gid = os.getgid() if os.getuid() else 1000
    if os.getuid() == 0:
        for owned in (destination, destination / ".env", destination / "data"):
            os.chown(owned, runtime_uid, runtime_gid)
        if (destination / "data" / "nexus.db").exists():
            os.chown(destination / "data" / "nexus.db", runtime_uid, runtime_gid)
    project = "nexus-" + str(time.time_ns())
    compose = f'''name: {project}
services:
  nexus:
    image: {image}
    user: "{runtime_uid}:{runtime_gid}"
    restart: unless-stopped
    ports:
      - "127.0.0.1:{port}:8080"
    env_file:
      - .env
    volumes:
      - ./data:/data
      - ./.env:/app/.env
'''
    private_write(destination / "compose.yaml", compose.encode())
    base = [
        "docker",
        "compose",
        "--project-directory",
        str(destination),
        "-f",
        str(destination / "compose.yaml"),
    ]
    # CLI migration loads the old key and checks protected data before workers start.
    command(
        base + ["run", "--rm", "--no-deps", "nexus", "db-migrate", "--from-env", "/data/nexus.db"],
        capture=True,
    )
    command(base + ["up", "-d"], capture=True)
    for _ in range(120):
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                f"http://127.0.0.1:{port}/health/ready", timeout=2
            ) as response:
                if response.status == 200:
                    break
        except (OSError, TimeoutError):
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError(
            "Nexus did not become ready. Inspect this installation before retrying; the old database was not modified."
        )
    print(f"\nNexus is ready. Files: {destination}")
    print("Point your private HTTPS proxy at the loopback port before signing in.")
    print(
        "Manage this installation with docker compose -f "
        + str(destination / "compose.yaml")
        + " ..."
    )
    if mode == "migrate":
        print(
            "Keep recovery/ and the old image/executable. Never run both installations against the same managed hosts."
        )


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        # Subprocess output/configuration can contain credentials. Do not echo it.
        print("\nSetup stopped. Existing source data was not upgraded in place.", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(
                "A Docker command failed. Inspect local setup files before retrying.",
                file=sys.stderr,
            )
        elif isinstance(error, KeyboardInterrupt):
            print("Interrupted. Any stopped old container remains stopped.", file=sys.stderr)
        else:
            print(str(error), file=sys.stderr)
        sys.exit(1)
