"""Install approved collection artifacts into this job only; never contact Galaxy.
The root adapter supplies read-only, hash-verified files in the private job mount.
This script runs as the dedicated job user and executes no archive setup hooks.
"""
import hashlib
import json
import os
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 8 << 20
MAX_EXPANDED = 32 << 20
MAX_FILE = 4 << 20


def read_archive(artifact, lock):
    with artifact.open('rb') as source:
        data = source.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != lock['sha256']:
        raise ValueError('collection checksum')
    import io
    files, directories, executables, total = {}, set(), set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for index, item in enumerate(archive):
            if index >= 5000 or len(item.name) > 240:
                raise ValueError('collection entries')
            name = item.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and item.isdir():
                continue
            part = PurePosixPath(name)
            if not name or part.is_absolute() or str(part) != name or any(p in ('.', '..') for p in part.parts) or '\\' in name or '\x00' in name:
                raise ValueError('collection path')
            if name in files or name in directories:
                raise ValueError('collection duplicate')
            if item.isdir():
                directories.add(name)
                continue
            if not item.isfile() or item.size < 0 or item.size > MAX_FILE:
                raise ValueError('collection entry type')
            total += item.size
            if total > MAX_EXPANDED:
                raise ValueError('collection expanded size')
            stream = archive.extractfile(item)
            if stream is None:
                raise ValueError('collection file')
            content = stream.read(MAX_FILE + 1)
            if len(content) != item.size:
                raise ValueError('collection file size')
            files[name] = content
            if item.mode & 0o111:
                executables.add(name)
    manifest = json.loads(files['MANIFEST.json'])
    info = manifest['collection_info']
    if any(info.get(key) != lock[key] for key in ('namespace', 'name', 'version')):
        raise ValueError('collection identity')
    reference = manifest.get('file_manifest_file', {})
    if reference.get('name') != 'FILES.json' or reference.get('chksum_type') != 'sha256' or hashlib.sha256(files['FILES.json']).hexdigest() != reference.get('chksum_sha256'):
        raise ValueError('collection file manifest')
    return files, info.get('dependencies', {}), executables


def install(locks_path, artifacts, project):
    locks = json.loads(locks_path.read_text())
    if not isinstance(locks, list) or len(locks) > 4:
        raise ValueError('collection locks')
    versions = {}
    for lock in locks:
        if set(lock) != {'namespace', 'name', 'version', 'sha256'} or not all(isinstance(v, str) for v in lock.values()):
            raise ValueError('collection lock')
        if not all(re.fullmatch('[a-z][a-z0-9_]{0,63}', lock[k]) for k in ('namespace', 'name')) or not re.fullmatch(r'(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})', lock['version']) or not re.fullmatch('[a-f0-9]{64}', lock['sha256']):
            raise ValueError('collection fields')
        name = lock['namespace'] + '.' + lock['name']
        if name in versions or name in ('ansible.builtin', 'ansible.legacy'):
            raise ValueError('collection duplicate lock')
        versions[name] = lock['version']
    for lock in locks:
        files, dependencies, executables = read_archive(artifacts / (lock['sha256'] + '.tar.gz'), lock)
        if not isinstance(dependencies, dict) or len(dependencies) > 4:
            raise ValueError('collection dependencies')
        for name, requirement in dependencies.items():
            if name not in versions or not isinstance(requirement, str) or len(requirement) > 128:
                raise ValueError('collection dependency lock')
            from ansible.galaxy.dependency_resolution.versioning import meets_requirements
            if not meets_requirements(versions[name], requirement):
                raise ValueError('collection dependency version')
        target = project / 'collections' / 'ansible_collections' / lock['namespace'] / lock['name']
        target.mkdir(parents=True, exist_ok=False, mode=0o700)
        for name, data in files.items():
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700 if name in executables else 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)


if __name__ == '__main__':
    try:
        install(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except Exception:
        sys.exit(1)
