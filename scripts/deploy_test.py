#!/usr/bin/env python3
"""Deployment preparation tests. Docker and service starts are replaced by fixtures."""

import argparse
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location("deploy", Path(__file__).with_name("deploy.py"))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentTests(unittest.TestCase):
    def test_snapshot_includes_wal_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = sqlite3.connect(root / "source.db")
            original.execute("PRAGMA journal_mode=WAL")
            original.execute("CREATE TABLE sample(value text)")
            original.execute("INSERT INTO sample VALUES('preserved')")
            original.commit()
            deploy.snapshot(root / "source.db", root / "copy.db")
            with sqlite3.connect(root / "copy.db") as copied:
                self.assertEqual(
                    copied.execute("SELECT value FROM sample").fetchone()[0], "preserved"
                )
            self.assertEqual((root / "copy.db").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                deploy.snapshot(root / "source.db", root / "copy.db")
            original.close()

    def test_release_tag_is_verified_and_pinned_before_use(self):
        key = "sha256:" + "a" * 64
        pinned = deploy.RELEASE_IMAGE + "@" + key
        reference = deploy.release_reference("1.2.3-rc.4")
        execute = MagicMock(
            side_effect=[MagicMock(stdout=f"Digest: {key}\n"), MagicMock(), MagicMock()]
        )
        self.assertEqual(deploy.pull_release(execute, reference), pinned)
        commands = [call.args[0] for call in execute.call_args_list]
        self.assertEqual(commands[0], ["docker", "pull", reference])
        self.assertEqual(commands[1][:2], ["cosign", "verify"])
        self.assertIn(deploy.RELEASE_IDENTITY, commands[1])
        self.assertEqual(commands[1][-1], pinned)
        self.assertEqual(commands[2], ["docker", "pull", pinned])

    def test_release_digest_failure_stops_before_pull(self):
        key = "sha256:" + "f" * 64
        execute = MagicMock(side_effect=subprocess.CalledProcessError(1, ["cosign", "verify"]))
        with self.assertRaises(subprocess.CalledProcessError):
            deploy.pull_release(execute, deploy.release_reference(key))
        execute.assert_called_once()
        with self.assertRaises(argparse.ArgumentTypeError):
            deploy.release_reference("other.example/nexus:latest")

    def migration(self, fails=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old.db"
            with sqlite3.connect(old) as database:
                database.execute("CREATE TABLE sample(value text)")
                database.execute("INSERT INTO sample VALUES('old database')")
            config = root / "old.env"
            config.write_text(
                "NEXUS_PASSWORD_HASH='fixture-hash'\nNEXUS_ENCRYPTION_KEY=fixture-key\n"
            )
            binary = root / "old-nexus"
            binary.write_bytes(b"fixture executable")
            destination = root / "new"
            commands = []

            def run(args, **kwargs):
                commands.append(args)
                if args[:3] == ["docker", "context", "show"]:
                    text = "fixture"
                elif args[:3] == ["docker", "image", "inspect"]:
                    text = "sha256:" + "a" * 64
                else:
                    text = ""
                if "db-migrate" in args and fails:
                    raise subprocess.CalledProcessError(1, args, stderr="must not be printed")
                return subprocess.CompletedProcess(args, 0, stdout=text, stderr="")

            def ask(label, default=""):
                if label.startswith("Fresh"):
                    return "migrate"
                if label.startswith("Existing matching"):
                    return str(config)
                if label.startswith("Existing database"):
                    return str(old)
                if label.startswith("Old Nexus executable"):
                    return str(binary)
                if label.startswith("Stop the old"):
                    return "STOPPED"
                return default

            opener = MagicMock()
            opener.open.return_value.__enter__.return_value.status = 200
            with (
                patch.object(
                    deploy.sys,
                    "argv",
                    ["deploy.py", "--directory", str(destination), "--image", "fixture"],
                ),
                patch.object(deploy.sys.stdin, "isatty", return_value=True),
                patch.object(deploy, "ask", side_effect=ask),
                patch.object(deploy, "yes", side_effect=lambda _label, default=False: default),
                patch.object(deploy.subprocess, "run", side_effect=run),
                patch.object(deploy.urllib.request, "build_opener", return_value=opener),
                patch.dict(os.environ, {"DOCKER_HOST": "unix:///fixture"}),
            ):
                old_umask = os.umask(0o077)
                try:
                    if fails:
                        with self.assertRaises(subprocess.CalledProcessError):
                            deploy.main()
                    else:
                        deploy.main()
                finally:
                    os.umask(old_umask)
            self.assertEqual(config.read_text(), (destination / "recovery" / ".env").read_text())
            self.assertIn("NEXUS_ENCRYPTION_KEY=fixture-key", (destination / ".env").read_text())
            self.assertNotIn("setup", [part for command in commands for part in command])
            self.assertEqual(any("up" in command for command in commands), not fails)
            for path in [
                old,
                destination / "recovery" / "nexus.db",
                destination / "data" / "nexus.db",
            ]:
                with sqlite3.connect(path) as database:
                    self.assertEqual(
                        database.execute("SELECT value FROM sample").fetchone()[0], "old database"
                    )
            self.assertTrue((destination / "recovery" / "nexus").exists())
            self.assertEqual((destination / ".env").stat().st_mode & 0o777, 0o600)

    def test_migration_keeps_original_key_and_source(self):
        self.migration()

    def test_failed_migration_never_starts_service(self):
        self.migration(fails=True)


if __name__ == "__main__":
    unittest.main()
