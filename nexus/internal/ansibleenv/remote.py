"""Fixed supervised environment action; requires root, never executes caller code."""
import base64
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import zlib

USER = 'nexus-ansible'
HOME = Path('/var/lib/nexus-ansible')
OWNER = Path('/var/lib/nexus-ansible-owner.json')


def private(path, uid, directory=False):
    info = path.lstat()
    if info.st_uid != uid or not (stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise ValueError('unsafe ownership')


def main(action, bundle):
    os.umask(0o077)
    if os.geteuid() != 0 or action not in ('install', 'update', 'health', 'remove'):
        raise ValueError('invalid operation')
    if sys.version_info[:2] not in ((3, 13), (3, 14), (3, 15)) or not shutil.which('runuser', path='/usr/sbin:/usr/bin'):
        print(json.dumps({'state': 'unsupported', 'reason': 'requires_python_3_13_to_3_15_venv_and_runuser'}))
        return 0
    try:
        user = pwd.getpwnam(USER)
    except KeyError:
        user = None
    if not OWNER.exists():
        if action == 'health':
            print(json.dumps({'state': 'absent'}))
            return 0
        if action != 'install' or user is not None or HOME.exists() or HOME.is_symlink() or OWNER.is_symlink():
            raise ValueError('refusing unowned account or home')
        subprocess.run(['/usr/sbin/useradd', '--system', '--user-group', '--home-dir', str(HOME), '--shell', '/usr/sbin/nologin', USER], check=True, capture_output=True, timeout=15)
        user = pwd.getpwnam(USER)
        HOME.mkdir(mode=0o700)
        os.chown(HOME, user.pw_uid, user.pw_gid)
        fd = os.open(OWNER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as target:
            json.dump({'kind': 'nexus-ansible-controller-v1', 'uid': user.pw_uid, 'gid': user.pw_gid}, target)
            target.flush()
            os.fsync(target.fileno())
    private(OWNER, 0)
    owner = json.loads(OWNER.read_text())
    if user is None or owner != {'kind': 'nexus-ansible-controller-v1', 'uid': user.pw_uid, 'gid': user.pw_gid} or user.pw_uid == 0 or user.pw_dir != str(HOME) or user.pw_shell != '/usr/sbin/nologin' or set(os.getgrouplist(USER, user.pw_gid)) != {user.pw_gid}:
        raise ValueError('controller identity changed')
    private(HOME, user.pw_uid, True)
    if action == 'health' and not (HOME / 'environment').exists():
        print(json.dumps({'state': 'absent'}))
        return 0
    files = json.loads(zlib.decompress(base64.b64decode(bundle)))
    if set(files) != {'environment.py', 'requirements.lock'}:
        raise ValueError('invalid reviewed bundle')
    with tempfile.TemporaryDirectory(prefix='.package-', dir=HOME) as directory:
        os.chown(directory, user.pw_uid, user.pw_gid)
        for name, encoded in files.items():
            data = base64.b64decode(encoded)
            fd = os.open(Path(directory) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
            with os.fdopen(fd, 'wb') as target:
                target.write(data)
            os.chmod(Path(directory) / name, 0o444)
        # The reviewed code and all pip/Ansible processes run as the dedicated
        # user. No sudo, supplementary groups, root keys or Docker socket.
        process = subprocess.run(['/usr/sbin/runuser', '-u', USER, '--', '/usr/bin/python3', '-I', str(Path(directory) / 'environment.py'), action, '--root', str(HOME / 'environment')],
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(HOME), 'LANG': 'C.UTF-8'}, capture_output=True, timeout=360)
        if process.returncode:
            raise ValueError('controller operation failed')
        result = json.loads(process.stdout)
        # Only the structured environment summary reaches saved run output.
        print(json.dumps(result))
        return 0


try:
    sys.exit(main(ACTION, BUNDLE))
except Exception:
    print(json.dumps({'state': 'failed', 'reason': 'environment_operation_unconfirmed_or_prerequisites_missing'}))
    sys.exit(1)
