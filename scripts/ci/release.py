#!/usr/bin/env python3
"""Validate native OCI images, build the release index and promote its verified bytes."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import tarfile

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
PREFIX = "org.opencontainers.image."
ARCHITECTURES = ("amd64", "arm64")
VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(rc|edge)\.(0|[1-9]\d*))?")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def version_parts(version):
    match = VERSION.fullmatch(version)
    if not match or len(version) > 100:
        raise ValueError("expected a stable version, an rc.N prerelease, or an edge.N build")
    major, minor, patch, qualifier, number = match.groups()
    return (int(major), int(minor), int(patch)), qualifier, int(number or "0")


def archive_json(tar, name, limit=256 * 1024):
    item = tar.getmember(name)
    if not item.isfile() or item.size > limit:
        raise ValueError(f"invalid OCI archive member {name}")
    with tar.extractfile(item) as member:
        return member.read()


def archive_blob(tar, descriptor):
    reference = descriptor["digest"]
    if not DIGEST.fullmatch(reference):
        raise ValueError("invalid OCI blob digest")
    data = archive_json(tar, "blobs/sha256/" + reference.removeprefix("sha256:"))
    if len(data) != descriptor["size"] or digest(data) != reference:
        raise ValueError("OCI blob did not match its digest")
    return data


def native_descriptor(archive, architecture, version, commit):
    version_parts(version)
    with tarfile.open(archive, "r:") as tar:
        index = json.loads(archive_json(tar, "index.json"))
        if len(index["manifests"]) != 1:
            raise ValueError("expected one native image manifest without attached artifacts")
        descriptor = index["manifests"][0]
        if descriptor["mediaType"] != MANIFEST:
            raise ValueError("expected a native OCI image manifest")
        manifest = json.loads(archive_blob(tar, descriptor))
        config = json.loads(archive_blob(tar, manifest["config"]))
        if (config["os"], config["architecture"]) != ("linux", architecture):
            raise ValueError("image platform does not match the native job")
        labels = config["config"]["Labels"]
        if labels[PREFIX + "version"] != version or labels[PREFIX + "revision"] != commit:
            raise ValueError("unexpected image version or source revision")
    return {
        "mediaType": MANIFEST,
        "digest": descriptor["digest"],
        "size": descriptor["size"],
        "platform": {"architecture": architecture, "os": "linux"},
    }


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")


def release_index(evidence, version, commit):
    version_parts(version)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid source revision")
    manifests = []
    for arch in ARCHITECTURES:
        record = json.loads((evidence / f"evidence-{arch}" / "platform.json").read_bytes())
        if (record["version"], record["commit"]) != (version, commit):
            raise ValueError("native validation belongs to a different release")
        descriptor = record["image"]
        if (
            descriptor["platform"] != {"architecture": arch, "os": "linux"}
            or descriptor["mediaType"] != MANIFEST
            or not DIGEST.fullmatch(descriptor["digest"])
            or not 0 < descriptor["size"] <= 256 * 1024
        ):
            raise ValueError("invalid native image descriptor")
        manifests.append(descriptor)
    return {
        "schemaVersion": 2,
        "mediaType": INDEX,
        "manifests": manifests,
        "annotations": {PREFIX + "version": version, PREFIX + "revision": commit},
    }


def registry(*args, data=None, missing=False):
    result = subprocess.run(["regctl", *args], input=data, capture_output=True, check=False)
    if result.returncode == 0:
        return result.stdout
    error = result.stderr.decode(errors="replace").lower()
    if missing and ("not found" in error or "manifest unknown" in error):
        return None
    raise RuntimeError(f"registry command failed: {result.stderr.decode(errors='replace').strip()}")


def remote_manifest(reference, missing=False):
    return registry("manifest", "get", reference, "--format", "raw-body", missing=missing)


def check_immutable_tag(reference, expected):
    current = remote_manifest(reference, missing=True)
    if current is not None and digest(current) != expected:
        raise ValueError(f"{reference} already identifies a different image")
    return current is not None


def put_index(reference, data):
    registry("manifest", "put", "--content-type", INDEX, reference, data=data)
    if digest(remote_manifest(reference)) != digest(data):
        raise ValueError(f"registry changed the release index at {reference}")


def stage(image, version, commit, archives, evidence, index_file, run):
    index = index_file.read_bytes()
    expected = release_index(evidence, version, commit)
    if json.loads(index) != expected:
        raise ValueError("index differs from the tested platform evidence")
    if not re.fullmatch(r"\d+-\d+", run):
        raise ValueError("invalid build run")
    check_immutable_tag(f"{image}:{version}", digest(index))
    for arch, descriptor in zip(ARCHITECTURES, expected["manifests"], strict=True):
        archive = archives / arch / "image.tar"
        if native_descriptor(archive, arch, version, commit) != descriptor:
            raise ValueError("release archive does not match the tested image")
        reference = f"{image}:candidate-{run}-{arch}"
        registry("image", "import", reference, str(archive))
        if digest(remote_manifest(f"{image}@{descriptor['digest']}")) != descriptor["digest"]:
            raise ValueError("published native manifest differed from the tested image")
    put_index(f"{image}:candidate-{run}", index)


def channel_tags(version):
    (major, minor, _), qualifier, _ = version_parts(version)
    if qualifier == "edge":
        return ("edge",)
    if qualifier == "rc":
        return ()
    return "latest", f"{major}.{minor}"


def advance_channel(reference, index, version):
    existing = remote_manifest(reference, missing=True)
    if existing is not None:
        annotation = json.loads(existing).get("annotations", {}).get(PREFIX + "version", "")
        old, old_kind, old_serial = version_parts(annotation)
        new, new_kind, new_serial = version_parts(version)
        if old_kind != new_kind:
            raise ValueError(f"channel {reference} contains an unexpected version")
        if (old, old_serial) >= (new, new_serial):
            return
    put_index(reference, index)


def promote(image, version, commit, index_file, aliases):
    index = index_file.read_bytes()
    target = digest(index)
    if digest(remote_manifest(f"{image}@{target}")) != target:
        raise ValueError("approved index is missing or has changed")
    if aliases:
        if not check_immutable_tag(f"{image}:{version}", target):
            raise ValueError("publish the exact version before moving channels")
        for channel in channel_tags(version):
            advance_channel(f"{image}:{channel}", index, version)
        return
    if not check_immutable_tag(f"{image}:{version}", target):
        put_index(f"{image}:{version}", index)
    source = f"{image}:sha-{commit}"
    if remote_manifest(source, missing=True) is None:
        put_index(source, index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("version")
    validate.add_argument("version")

    native = commands.add_parser("native")
    native.add_argument("archive", type=Path)
    native.add_argument("architecture", choices=ARCHITECTURES)
    native.add_argument("version")
    native.add_argument("commit")
    native.add_argument("output", type=Path)

    assemble = commands.add_parser("assemble")
    assemble.add_argument("evidence", type=Path)
    assemble.add_argument("version")
    assemble.add_argument("commit")
    assemble.add_argument("output", type=Path)

    upload = commands.add_parser("stage")
    upload.add_argument("image")
    upload.add_argument("version")
    upload.add_argument("commit")
    upload.add_argument("archives", type=Path)
    upload.add_argument("evidence", type=Path)
    upload.add_argument("index", type=Path)
    upload.add_argument("run")

    tags = commands.add_parser("promote")
    tags.add_argument("image")
    tags.add_argument("version")
    tags.add_argument("commit")
    tags.add_argument("index", type=Path)
    tags.add_argument("--aliases", action="store_true")

    args = parser.parse_args()
    if args.command == "version":
        _, qualifier, _ = version_parts(args.version)
        print(qualifier or "stable")
    elif args.command == "native":
        descriptor = native_descriptor(args.archive, args.architecture, args.version, args.commit)
        write_json(
            args.output, {"version": args.version, "commit": args.commit, "image": descriptor}
        )
        print(descriptor["digest"])
    elif args.command == "assemble":
        write_json(args.output, release_index(args.evidence, args.version, args.commit))
        print(digest(args.output.read_bytes()))
    elif args.command == "stage":
        stage(
            args.image,
            args.version,
            args.commit,
            args.archives,
            args.evidence,
            args.index,
            args.run,
        )
    elif args.command == "promote":
        promote(args.image, args.version, args.commit, args.index, args.aliases)


if __name__ == "__main__":
    main()
