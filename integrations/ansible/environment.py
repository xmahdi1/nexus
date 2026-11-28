#!/usr/bin/env python3
"""Own an isolated Ansible environment without changing system packages.

Run as a dedicated non-root controller user. Installation is explicit; health
never installs or repairs anything. Removal only accepts an owned private root.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

KIND = "nexus-ansible-environment-v1"
MARKER = ".nexus-environment.json"
LOCKFILE = Path(__file__).with_name("requirements.lock")
VERSION = "2.22.0"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def root_path(value):
    path = Path(value)
    if not re.fullmatch(r"/[A-Za-z0-9/_.-]+", value) or not path.is_absolute() or path != path.resolve() or path.parent == path or path == Path.home():
        raise ValueError("Use an absolute dedicated directory without symlinks or traversal")
    return path


def read_owned(root):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Environment root must be a private directory owned by this user")
    with os.fdopen(os.open(root / MARKER, os.O_RDONLY | os.O_NOFOLLOW), "r") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 4096:
            raise ValueError("Invalid environment ownership marker")
        record = json.load(source)
    if record.get("kind") != KIND or record.get("uid") != os.getuid() or record.get("root") != str(root):
        raise ValueError("Environment ownership mismatch")
    return record


def save_marker(root, record):
    temporary = root / (MARKER + ".new")
    private_file(temporary, json.dumps(record, sort_keys=True).encode())
    temporary.replace(root / MARKER)


@contextlib.contextmanager
def locked(root):
    with os.fdopen(os.open(root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+") as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Invalid environment lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Environment is busy") from None
        yield


def config(root):
    # No ambient user collections, inventory, callbacks, Ansible config or keys.
    return f"""[defaults]
host_key_checking = True
retry_files_enabled = False
collections_path = {root}/collections
roles_path = {root}/roles
local_tmp = {root}/tmp
inventory = {root}/inventory.json
[inventory]
any_unparsed_is_failed = True
""".encode()


def clean_environment(root):
    return {"PATH": "/usr/bin:/bin", "HOME": str(root / "home"), "LANG": "C.UTF-8",
            "ANSIBLE_CONFIG": str(root / "ansible.cfg"), "ANSIBLE_NOCOLOR": "1",
            "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": os.devnull}


def command(root, arguments, timeout=300):
    result = subprocess.run(arguments, env=clean_environment(root), cwd=root,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        # Installer output cannot contain application credentials, but do not
        # forward arbitrary subprocess output into API or audit logs.
        raise ValueError("Managed environment command failed; inspect prerequisites or the pinned wheel set")
    return result.stdout


def install(root, update=False):
    requirements = LOCKFILE.read_bytes()
    if update:
        record = read_owned(root)
    else:
        # mkdir is exclusive: never adopt/overwrite an existing environment.
        root.mkdir(mode=0o700)
        record = {"kind": KIND, "uid": os.getuid(), "root": str(root), "state": "installing", "createdAt": int(time.time())}
        private_file(root / MARKER, json.dumps(record).encode())
    with locked(root):
        read_owned(root)
        record.update(state="installing", version=VERSION, lockHash=digest(requirements))
        save_marker(root, record)
        for child in ("home", "tmp", "collections", "roles"):
            (root / child).mkdir(mode=0o700, exist_ok=True)
        cfg = root / "ansible.cfg"
        if cfg.exists() or cfg.is_symlink():
            if cfg.is_symlink() or cfg.read_bytes() != config(root):
                raise ValueError("Environment configuration was modified")
        else:
            private_file(cfg, config(root))
        if not update:
            command(root, [sys.executable, "-I", "-m", "venv", str(root / "venv")])
        lock = root / "requirements.lock"
        # Only an owned regular previous lock may be replaced.
        if lock.exists() or lock.is_symlink():
            if lock.is_symlink() or not lock.is_file():
                raise ValueError("Invalid installed requirements lock")
            lock.unlink()
        private_file(lock, requirements)
        command(root, [str(root / "venv/bin/python"), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
                       "--index-url", "https://pypi.org/simple", "--require-hashes", "--only-binary", ":all:", "--no-input", "-r", str(lock)])
        verify(root, record, installing=True)
        record.update(state="ready", updatedAt=int(time.time()))
        save_marker(root, record)
    return {"state": "ready", "version": VERSION, "root": str(root), "lockHash": record["lockHash"]}


def verify(root, record, installing=False):
    if record.get("state") != ("installing" if installing else "ready"):
        raise ValueError("Environment installation is incomplete")
    if (root / "ansible.cfg").is_symlink() or (root / "ansible.cfg").read_bytes() != config(root):
        raise ValueError("Environment configuration was modified")
    lock = root / "requirements.lock"
    if lock.is_symlink() or digest(lock.read_bytes()) != record.get("lockHash") or record.get("lockHash") != digest(LOCKFILE.read_bytes()):
        raise ValueError("Environment requires an explicit pinned update")
    expected = {}
    for line in lock.read_text().splitlines():
        if "==" in line and not line.startswith("#"):
            name, version = line.split("==", 1)
            expected[name.lower().replace("_", "-")] = version.split()[0]
    script = "import importlib.metadata,json;print(json.dumps({d.metadata['Name'].lower().replace('_','-'):d.version for d in importlib.metadata.distributions()}))"
    actual = json.loads(command(root, [str(root / "venv/bin/python"), "-I", "-c", script], timeout=30))
    if any(actual.get(name) != version for name, version in expected.items()) or set(actual) - set(expected) - {"pip", "setuptools"}:
        raise ValueError("Installed package versions differ from the reviewed lock")
    command(root, [str(root / "venv/bin/python"), "-I", "-m", "pip", "--isolated", "check"], timeout=30)
    version = command(root, [str(root / "venv/bin/ansible"), "--version"], timeout=30).decode().splitlines()[0]
    if version != f"ansible [core {VERSION}]":
        raise ValueError("Unexpected Ansible version")
    ssh = shutil.which("ssh", path="/usr/bin:/bin")
    return {"state": "ready", "version": VERSION, "root": str(root), "sshAvailable": bool(ssh), "lockHash": record["lockHash"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "update", "health", "remove"))
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() == 0 or sys.version_info[:2] not in ((3, 13), (3, 14), (3, 15)):
            raise ValueError("Use a dedicated non-root controller user with Python 3.13–3.15")
        os.umask(0o077)
        root = root_path(args.root)
        if args.action in ("install", "update"):
            result = install(root, update=args.action == "update")
        else:
            record = read_owned(root)
            with locked(root):
                if args.action == "health":
                    result = verify(root, record)
                else:
                    # shutil.rmtree unlinks symlinks rather than following them.
                    if not shutil.rmtree.avoids_symlink_attacks:
                        raise ValueError("This platform lacks safe directory removal")
                    shutil.rmtree(root)
                    result = {"state": "removed"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Ansible environment operation failed; check ownership, state and prerequisites. Existing system installations are not managed by this tool.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
