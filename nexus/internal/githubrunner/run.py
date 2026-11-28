"""Fixed runner adapter. Credentials arrive exclusively on private stdin."""
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request

VERSION = '2.338.2'
PACKAGES = {
    'x86_64': ('x64', 'baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40'),
    'aarch64': ('arm64', '670adb2f268fe21dcbb58b3db0e0aa9d5b3db0e0aa9d5b3bddfe2c651481336e561ff86de945'),
}
ROOT = Path('/run/nexus-runner')
STAGE = 'prerequisites'


def package(root):
    arch, expected = PACKAGES[platform.machine()]
    url = f'https://github.com/actions/runner/releases/download/v{VERSION}/actions-runner-linux-{arch}-{VERSION}.tar.gz'
    archive = root / 'package.tar.gz'
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(url, timeout=30) as source, archive.open('xb') as target:
        while chunk := source.read(65536):
            count += len(chunk)
            if count > 256 * 1024 * 1024:
                raise ValueError('package size')
            digest.update(chunk)
            target.write(chunk)
    if digest.hexdigest() != expected:
        raise ValueError('package checksum')
    with tarfile.open(archive, 'r:gz') as source:
        if sum(member.size for member in source.getmembers()) > 768 * 1024 * 1024:
            raise ValueError('expanded package size')
        source.extractall(root, filter='data')
    archive.unlink()


def main():
    global STAGE
    os.umask(0o077)
    data = sys.stdin.buffer.read(12001)
    sys.stdin.close()
    if len(data) > 12000 or os.geteuid() != 0 or sys.version_info < (3, 12):
        raise ValueError('prerequisites')
    setup = json.loads(data)
    identity = setup['requestId']
    if not re.fullmatch('[a-f0-9]{32}', identity) or identity != os.environ.get('NEXUS_JOB_ID'):
        raise ValueError('identity mismatch')
    # This path must be a private per-unit tmpfs supplied by the supervisor.
    if not os.path.ismount(ROOT) or ROOT.lstat().st_uid != 0 or not stat.S_ISDIR(ROOT.lstat().st_mode):
        raise ValueError('isolated runtime missing')
    username = 'nxr-' + identity[:20]
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise ValueError('refusing existing identity')
    home = ROOT / 'home'
    home.mkdir(mode=0o700)
    STAGE = 'package_download_and_checksum'
    package(home)
    STAGE = 'dedicated_account'
    subprocess.run(['/usr/sbin/useradd', '--system', '--user-group', '--home-dir', str(home), '--shell', '/usr/sbin/nologin', username], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    user = pwd.getpwnam(username)
    # Root-owned receipt enables verified cleanup after cancellation as well as
    # natural exit; the runner user cannot alter supervisor artifacts.
    receipt = Path('/run/nexus-jobs') / identity / 'runner-account.json'
    fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as target:
        json.dump({'name': username, 'uid': user.pw_uid}, target)
    for directory, dirs, files in os.walk(home, followlinks=False):
        os.chown(directory, user.pw_uid, user.pw_gid)
        for name in dirs + files:
            os.chown(Path(directory) / name, user.pw_uid, user.pw_gid, follow_symlinks=False)
    os.chmod(ROOT, 0o711)

    def drop():
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)

    environment = {'HOME': str(home), 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8'}
    configure = ['./config.sh', '--unattended', '--ephemeral', '--disableupdate', '--url', setup['url'], '--name', setup['name'], '--work', '_work']
    if setup['labels']:
        configure += ['--labels', ','.join(setup['labels'])]
    if setup['group']:
        configure += ['--runnergroup', setup['group']]
    config_environment = {**environment, 'ACTIONS_RUNNER_INPUT_TOKEN': setup.pop('registrationToken')}
    try:
        STAGE = 'runner_os_dependencies'
        probe = subprocess.run(['./bin/Runner.Listener', '--version'], cwd=home, env=environment, preexec_fn=drop, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if probe.returncode:
            raise ValueError('OS dependencies missing')
        STAGE = 'github_registration'
        # Upstream reads then removes ACTIONS_RUNNER_INPUT_* variables. Never
        # put registration credentials in argv or the subsequent job environment.
        result = subprocess.run(configure, cwd=home, env=config_environment, preexec_fn=drop, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
        config_environment.clear()
        del data
        if result.returncode:
            raise ValueError('registration failed')
        STAGE = 'runner_process'
        result = subprocess.run(['./run.sh', '--once'], cwd=home, env=environment, preexec_fn=drop, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({'state': 'runner_exited', 'exitCode': result.returncode, 'version': VERSION, 'ephemeral': True}))
        return 0 if result.returncode == 0 else 1
    finally:
        config_environment.clear()
        shutil.rmtree(home)
        # Refuse forced deletion while descendants still exist. Release performs
        # the same identity-checked cleanup after the managed cgroup is empty.
        subprocess.run(['/usr/sbin/userdel', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print(json.dumps({'state': 'runner_setup_or_process_failed', 'stage': STAGE, 'guidance': 'Inspect Linux/.NET prerequisites, registration scope/token expiry and the GitHub runner list before enrolling again.'}))
        sys.exit(1)
