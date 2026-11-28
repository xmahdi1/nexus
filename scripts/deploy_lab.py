#!/usr/bin/env python3
"""Test guided fresh setup and container migration using owned temporary installs.
Requires an already-built current local image. No user configuration is read.
"""

import argparse
import os
from pathlib import Path
import pty
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def guided(image, installation, env, dialogue):
    primary, child = pty.openpty()
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts/deploy.py"),
            "--image",
            image,
            "--directory",
            str(installation),
        ],
        env=env,
        stdin=child,
        stdout=child,
        stderr=child,
        start_new_session=True,
    )
    os.close(child)
    output = b""
    pending = b""
    deadline = time.monotonic() + 120
    try:
        while time.monotonic() < deadline:
            if select.select([primary], [], [], 0.2)[0]:
                try:
                    chunk = os.read(primary, 16384)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
                pending += chunk
                if dialogue and dialogue[0][0] in pending:
                    _, answer = dialogue.pop(0)
                    # Wait for the complete prompt, including password echo setup.
                    while not pending.rstrip().endswith(b":"):
                        if not select.select([primary], [], [], 5)[0]:
                            raise RuntimeError("Fixture prompt did not complete.")
                        chunk = os.read(primary, 16384)
                        pending += chunk
                        output += chunk
                    os.write(primary, answer + b"\n")
                    pending = b""
            if process.poll() is not None:
                break
        if process.poll() is None:
            process.wait(timeout=5)
        if process.returncode or dialogue or b"Nexus is ready." not in output:
            raise RuntimeError(
                f"Guided setup did not complete (exit={process.returncode}, prompts_left={len(dialogue)}). No credential transcript is printed."
            )
        if b"Disposable fixture password" in output or b"NEXUS_ENCRYPTION_KEY=" in output:
            raise RuntimeError("Guided setup printed fixture credentials.")
        if (installation / ".env").stat().st_mode & 0o777 != 0o600:
            raise RuntimeError("Configuration is not private.")
        if not (installation / "data" / "nexus.db").is_file():
            raise RuntimeError("Guided setup did not create the database.")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
        os.close(primary)


def common(mode, backups=False):
    return [
        (b"(new/migrate)", mode),
        (b"Local host port", str(free_port()).encode()),
        (b"HTTPS proxy", b"y"),
        (b"Ansible and GitHub tools", b"n"),
        (b"guided backups", b"y" if backups else b"n"),
        (b"Vault tools", b"n"),
        (b"server inventory", b"n"),
        (b"tracked jobs", b"" if backups else b"n"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    image = parser.parse_args().image
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("NEXUS_", "COMPOSE_"))
    }
    with tempfile.TemporaryDirectory(prefix="nexus-deploy-lab-") as directory:
        original, migrated = [Path(directory) / name for name in ("original", "migrated")]
        try:
            guided(
                image,
                original,
                env,
                common(b"new", backups=True)
                + [
                    (b"start it?", b"y"),
                    (b"Enter password", b"Disposable fixture password"),
                    (b"Confirm password", b"Disposable fixture password"),
                ],
            )
            with sqlite3.connect(original / "data" / "nexus.db") as db:
                db.execute("CREATE TABLE deployment_fixture(value text)")
                db.execute("INSERT INTO deployment_fixture VALUES('preserved fixture')")
            config = (original / ".env").read_bytes()
            if (
                b"NEXUS_ENABLE_BACKUPS=true" not in config
                or b"NEXUS_ENABLE_OPERATION_SUPERVISION=true" not in config
            ):
                raise RuntimeError("Guided backup choice did not enable its prerequisites.")
            container = subprocess.check_output(
                ["docker", "compose", "-f", str(original / "compose.yaml"), "ps", "-q", "nexus"],
                env=env,
            ).strip()
            if not container:
                raise RuntimeError("Missing owned source container.")
            guided(
                image,
                migrated,
                env,
                common(b"migrate")
                + [
                    (b"Existing matching .env", str(original / ".env").encode()),
                    (b"Old Nexus container", container),
                    (b"Database path INSIDE", b"/data/nexus.db"),
                    (b"start it?", b"y"),
                ],
            )
            if (migrated / "recovery" / ".env").read_bytes() != config or not (
                migrated / ".env"
            ).read_bytes().startswith(config):
                raise RuntimeError("Migration replaced the original configuration/key.")
            for path in (
                original / "data" / "nexus.db",
                migrated / "data" / "nexus.db",
                migrated / "recovery" / "nexus.db",
            ):
                with sqlite3.connect(path) as db:
                    if (
                        db.execute("SELECT value FROM deployment_fixture").fetchone()[0]
                        != "preserved fixture"
                    ):
                        raise RuntimeError("Migration lost fixture data.")
            running = subprocess.check_output(
                ["docker", "inspect", "--format", "{{.State.Running}}", container.decode()], env=env
            ).strip()
            if running != b"false":
                raise RuntimeError("Old container was restarted.")
            print(
                "Guided deployment passed: fresh private setup, Compose readiness, stopped-container migration, matching key/configuration, copied data and rollback files."
            )
        finally:
            for installation in (migrated, original):
                if (installation / "compose.yaml").exists():
                    subprocess.run(
                        [
                            "docker",
                            "compose",
                            "-f",
                            str(installation / "compose.yaml"),
                            "down",
                            "--remove-orphans",
                        ],
                        env=env,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=60,
                    )


if __name__ == "__main__":
    main()
