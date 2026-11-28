#!/usr/bin/env python3
"""Check release identity and tag safety without credentials or network access."""

from io import BytesIO
import json
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import release

COMMIT = "a" * 40


def make_oci_archive(path, arch, version="0.1.0"):
    def add(name, data):
        item = tarfile.TarInfo(name)
        item.size = len(data)
        tar.addfile(item, BytesIO(data))

    def blob(media_type, value):
        data = json.dumps(value).encode()
        digest = release.digest(data)
        add("blobs/sha256/" + digest.split(":")[1], data)
        return {"mediaType": media_type, "size": len(data), "digest": digest}

    with tarfile.open(path, "w") as tar:
        config = blob(
            "application/vnd.oci.image.config.v1+json",
            {
                "os": "linux",
                "architecture": arch,
                "rootfs": {"type": "layers", "diff_ids": []},
                "config": {
                    "Labels": {
                        release.PREFIX + "version": version,
                        release.PREFIX + "revision": COMMIT,
                    },
                },
            },
        )
        descriptor = blob(
            release.MANIFEST,
            {"schemaVersion": 2, "mediaType": release.MANIFEST, "config": config, "layers": []},
        )
        add("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add(
            "index.json",
            json.dumps({"schemaVersion": 2, "manifests": [descriptor]}).encode(),
        )


class ReleaseTests(unittest.TestCase):
    def test_architecture_and_version_are_checked(self):
        with TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            make_oci_archive(archive, "amd64")
            descriptor = release.native_descriptor(archive, "amd64", "0.1.0", COMMIT)
            self.assertEqual(descriptor["platform"], {"os": "linux", "architecture": "amd64"})
            with self.assertRaises(ValueError):
                release.native_descriptor(archive, "arm64", "0.1.0", COMMIT)
            with self.assertRaises(ValueError):
                release.native_descriptor(archive, "amd64", "0.2.0", COMMIT)

    def test_same_release_requires_identical_digest(self):
        with patch.object(release, "remote_manifest", return_value=b"published bytes"):
            self.assertTrue(
                release.check_immutable_tag("local/test:1.0.0", release.digest(b"published bytes"))
            )
            with self.assertRaises(ValueError):
                release.check_immutable_tag("local/test:1.0.0", release.digest(b"new bytes"))

    def test_prereleases_leave_stable_aliases_alone(self):
        self.assertEqual(release.channel_tags("0.1.0-rc.1"), ())
        self.assertEqual(release.channel_tags("0.0.0-edge.2"), ("edge",))
        self.assertEqual(release.channel_tags("1.4.0"), ("latest", "1.4"))
        with self.assertRaises(ValueError):
            release.channel_tags("01.4.0")

    def test_older_build_does_not_move_a_channel(self):
        current = json.dumps({"annotations": {release.PREFIX + "version": "1.4.2"}}).encode()
        with (
            patch.object(release, "remote_manifest", return_value=current),
            patch.object(release, "put_index") as write,
        ):
            release.advance_channel("local/test:latest", b"older", "1.3.0")
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
