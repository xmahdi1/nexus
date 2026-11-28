#!/usr/bin/env python3
"""Check the build-context privacy boundary in an isolated Git repository."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).with_name("export_source.py")


class SourceExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="nexus-export-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "repo"
        self.root.mkdir()
        script = self.root / "scripts/ci/export_source.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(SOURCE, script)
        self.script = script
        self.git("init", "-q")
        (self.root / "source.go").write_text("committed source\n")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        )

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def export(self, *args):
        destination = Path(self.directory.name) / "export"
        result = subprocess.run(
            [sys.executable, str(self.script), str(destination), *args], capture_output=True
        )
        return destination, result

    def test_untracked_files_never_enter_build_context(self):
        (self.root / "docs.zip").write_bytes(b"private fixture archive")
        (self.root / ".env").write_text("fixture private config")
        (self.root / "source.go").write_text("working source\n")
        destination, result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / "source.go").read_text(), "working source\n")
        self.assertFalse((destination / "docs.zip").exists())
        self.assertFalse((destination / ".env").exists())

    def test_immutable_ref_ignores_worktree_edits(self):
        (self.root / "source.go").write_text("unreviewed source\n")
        destination, result = self.export("--ref", "HEAD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / "source.go").read_text(), "committed source\n")

    def test_tracked_private_paths_are_rejected(self):
        (self.root / "docs.zip").write_bytes(b"private fixture archive")
        self.git("add", "docs.zip")
        _, result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"private path is tracked", result.stderr)

    def test_tracked_symlinks_are_rejected(self):
        (self.root / "alias").symlink_to("source.go")
        self.git("add", "alias")
        _, result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
