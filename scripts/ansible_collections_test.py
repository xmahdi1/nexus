#!/usr/bin/env python3
"""Exercise the offline collection installer against owned temporary archives."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "nexus_collections", ROOT / "nexus/internal/ansible/collections.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def artifact(directory, *, link=False, traversal=False, dependencies=None, wrong_identity=False):
    files_manifest = b'{"files": []}'
    manifest = {
        "collection_info": {
            "namespace": "fixture",
            "name": "example",
            "version": "2.0.0" if wrong_identity else "1.0.0",
            "dependencies": dependencies or {},
        },
        "file_manifest_file": {
            "name": "FILES.json",
            "chksum_type": "sha256",
            "chksum_sha256": hashlib.sha256(files_manifest).hexdigest(),
        },
    }
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, content in {
            "MANIFEST.json": json.dumps(manifest).encode(),
            "FILES.json": files_manifest,
            "plugins/modules/example.py": b"approved-fixture-code",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        if link or traversal:
            info = tarfile.TarInfo("escape" if link else "../escape")
            if link:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
            else:
                info.size = 1
            archive.addfile(info, io.BytesIO(b"x") if traversal else None)
    content = data.getvalue()
    digest = hashlib.sha256(content).hexdigest()
    (directory / (digest + ".tar.gz")).write_bytes(content)
    return {"namespace": "fixture", "name": "example", "version": "1.0.0", "sha256": digest}


class CollectionInstaller(unittest.TestCase):
    def run_case(self, mutate=None, **options):
        with tempfile.TemporaryDirectory(prefix="nexus-collection-test-") as temp:
            root = Path(temp)
            archives = root / "artifacts"
            archives.mkdir()
            project = root / "project"
            project.mkdir()
            lock = artifact(archives, **options)
            if mutate:
                mutate(lock, archives)
            path = root / "locks.json"
            path.write_text(json.dumps([lock]))
            module.install(path, archives, project)
            target = (
                project
                / "collections/ansible_collections/fixture/example/plugins/modules/example.py"
            )
            self.assertEqual(target.read_bytes(), b"approved-fixture-code")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse((root / "escape").exists())

    def test_exact_artifact(self):
        self.run_case()

    def test_links_and_traversal_rejected(self):
        for options in (
            {"link": True},
            {"traversal": True},
            {"wrong_identity": True},
            {"dependencies": {"missing.dependency": "*"}},
        ):
            with self.subTest(options=options), self.assertRaises((ValueError, KeyError)):
                self.run_case(**options)

    def test_changed_archive_rejected(self):
        def corrupt(lock, archives):
            path = archives / (lock["sha256"] + ".tar.gz")
            path.write_bytes(path.read_bytes() + b"changed")

        with self.assertRaises(ValueError):
            self.run_case(corrupt)


if __name__ == "__main__":
    unittest.main()
