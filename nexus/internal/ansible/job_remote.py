"""Trusted root staging only. Every Ansible process runs as a unique job UID."""
import json
import hashlib
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path('/run/nexus-ansible-job')
SOURCE = Path('/var/lib/nexus-ansible/environment')
STAGE = 'prerequisites'


def write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(data)


def main():
    global STAGE
    os.umask(0o077)
    data = sys.stdin.buffer.read(98305)
    sys.stdin.close()
    if len(data) > 98304 or os.geteuid() != 0 or sys.version_info[:2] not in ((3, 13), (3, 14), (3, 15)):
        raise ValueError('prerequisites')
    request = json.loads(data)
    identity = request['id']
    if not re.fullmatch('[a-f0-9]{32}', identity) or identity != os.environ.get('NEXUS_JOB_ID'):
        raise ValueError('identity')
    if not os.path.ismount(ROOT) or ROOT.lstat().st_uid != 0:
        raise ValueError('missing private mount')
    username = 'nxa-' + identity[:20]
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise ValueError('existing identity')
    STAGE = 'managed_environment'
    manager = pwd.getpwnam('nexus-ansible')
    owner = Path('/var/lib/nexus-ansible-owner.json')
    if owner.is_symlink() or owner.stat().st_uid != 0 or stat.S_IMODE(owner.stat().st_mode) != 0o600:
        raise ValueError('environment owner')
    if json.loads(owner.read_text()) != {'kind': 'nexus-ansible-controller-v1', 'uid': manager.pw_uid, 'gid': manager.pw_gid}:
        raise ValueError('environment identity')
    if SOURCE.is_symlink() or SOURCE.stat().st_uid != manager.pw_uid or stat.S_IMODE(SOURCE.stat().st_mode) != 0o700:
        raise ValueError('environment root')
    marker_path = SOURCE / '.nexus-environment.json'
    lock_path = SOURCE / 'requirements.lock'
    if marker_path.is_symlink() or lock_path.is_symlink() or marker_path.stat().st_size > 4096 or lock_path.stat().st_size > 16384:
        raise ValueError('environment metadata')
    marker = json.loads(marker_path.read_text())
    if marker.get('state') != 'ready' or marker.get('version') != '2.22.0' or marker.get('root') != str(SOURCE) or marker.get('uid') != manager.pw_uid:
        raise ValueError('environment not ready')
    lock = lock_path.read_bytes()
    if hashlib.sha256(lock).hexdigest() != marker.get('lockHash'):
        raise ValueError('environment lock')
    expected = {}
    for line in lock.decode().splitlines():
        if '==' in line and not line.startswith('#'):
            name, version = line.split('==', 1)
            expected[name.lower().replace('_', '-')] = version.split()[0]
    if len(expected) != 9 or expected.get('ansible-core') != '2.22.0':
        raise ValueError('environment package set')
    source = SOURCE / 'venv'
    if source.is_symlink() or not source.is_dir():
        raise ValueError('environment venv')
    # Never follow a user-controlled symlink while copying as root. Only the
    # managed venv's interpreter symlinks may point to this system interpreter.
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink():
                internal = not os.path.isabs(os.readlink(path)) and path.resolve().is_relative_to(source.resolve())
                interpreter = path.parent == source / 'bin' and path.resolve() == Path(sys.executable).resolve()
                if not internal and not interpreter:
                    raise ValueError('environment link: ' + str(path.relative_to(source)) + ' -> ' + os.readlink(path))
            if not path.is_symlink() and not (path.is_dir() or path.is_file()):
                raise ValueError('environment entry')
    trusted = ROOT / 'trusted'
    trusted.mkdir(mode=0o755)
    venv = trusted / 'venv'
    shutil.copytree(source, venv, symlinks=True)
    for directory, dirs, files in os.walk(trusted, followlinks=False):
        os.chmod(directory, 0o755)
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, 0o555 if os.access(path, os.X_OK) else 0o444)
    callbacks = trusted / 'callbacks'
    callbacks.mkdir(mode=0o755)
    callbacks.chmod(0o755)
    write(callbacks / 'nexus_safe.py', CALLBACK.encode(), 0o444)
    (callbacks / 'nexus_safe.py').chmod(0o444)
    # Collection cache paths and filenames are fixed; the controller operator
    # stages reviewed archives. No remote URL or automatic dependency fetching.
    locks = request['bundle'].get('collections', [])
    artifacts = trusted / 'collection-artifacts'
    if locks:
        artifacts.mkdir(mode=0o755)
        artifacts.chmod(0o755)
        write(trusted / 'collections.py', COLLECTIONS.encode(), 0o444)
        (trusted / 'collections.py').chmod(0o444)
        for lock in locks:
            digest = lock['sha256']
            if not re.fullmatch('[a-f0-9]{64}', digest):
                raise ValueError('collection digest')
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in ('var', 'lib', 'nexus-ansible', 'collections', 'artifacts'):
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    info = os.fstat(fd)
                    if info.st_uid not in (0, SOURCE.stat().st_uid) or info.st_mode & 0o022:
                        raise ValueError('collection cache ownership')
                source_fd = os.open(digest + '.tar.gz', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(source_fd, 'rb') as artifact_reader:
                    info = os.fstat(artifact_reader.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, SOURCE.stat().st_uid) or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > (8 << 20):
                        raise ValueError('collection cache file')
                    archive_bytes = artifact_reader.read((8 << 20) + 1)
                if len(archive_bytes) != info.st_size or hashlib.sha256(archive_bytes).hexdigest() != digest:
                    raise ValueError('collection cache checksum')
                write(artifacts / (digest + '.tar.gz'), archive_bytes, 0o444)
                (artifacts / (digest + '.tar.gz')).chmod(0o444)
                del archive_bytes
            finally:
                os.close(fd)
    home = ROOT / 'home'
    home.mkdir(mode=0o700)
    project = home / 'project'
    project.mkdir(mode=0o700)
    for name, content in request['bundle']['files'].items():
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in ('.', '..') or part.startswith('.') for part in path.parts) or str(path) != name:
            raise ValueError('project path')
        target = project / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write(target, content.encode())
    inventory = {'all': {'hosts': {}}}
    aliases = []
    server_ids = {}
    for host in request['targets']:
        alias = host['alias']
        if not re.fullmatch('nexus_host_[a-f0-9]{64}', alias) or alias in aliases:
            raise ValueError('target alias')
        aliases.append(alias)
        if not re.fullmatch('[A-Za-z0-9_-]{1,128}', host['serverId']) or host['serverId'] in server_ids.values():
            raise ValueError('target identity')
        server_ids[alias] = host['serverId']
        write(home / (alias + '.key'), host['privateKey'].encode())
        write(home / (alias + '.hosts'), host['knownHosts'].encode())
        inventory['all']['hosts'][alias] = {
            'ansible_host': host['host'], 'ansible_port': host['port'], 'ansible_user': host['user'],
            'ansible_ssh_private_key_file': str(home / (alias + '.key')),
            'ansible_ssh_common_args': '-F /dev/null -o StrictHostKeyChecking=yes -o UserKnownHostsFile=' + str(home / (alias + '.hosts')) + ' -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o IdentityAgent=none -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o ConnectTimeout=10',
        }
    if not 1 <= len(aliases) <= 10:
        raise ValueError('target count')
    if locks:
        write(home / 'collections-lock.json', json.dumps(locks).encode())
    write(home / 'inventory.json', json.dumps(inventory).encode())
    write(home / 'vars.json', json.dumps(request['variables']).encode())
    config = f'[defaults]\ninventory = {home}/inventory.json\nstdout_callback = nexus_safe\ncallback_plugins = {callbacks}\nhost_key_checking = True\nretry_files_enabled = False\nlocal_tmp = {home}/tmp\nroles_path = {project}/roles\ncollections_path = {project}/collections\nforks = 5\n[inventory]\nany_unparsed_is_failed = True\n[ssh_connection]\nusetty = False\nssh_args = -F /dev/null -o ControlMaster=no -o ControlPersist=no -o ControlPath=none\n'
    write(home / 'ansible.cfg', config.encode())
    (home / 'tmp').mkdir(mode=0o700)
    command = [str(venv / 'bin/python'), '-I', '-m', 'ansible.cli.playbook', '-i', str(home / 'inventory.json'), '--limit', ','.join(aliases), '--extra-vars', '@' + str(home / 'vars.json')]
    options = request['options']
    if options['mode'] == 'syntax':
        command.append('--syntax-check')
    elif options['mode'] == 'check':
        command.append('--check')
    elif options['mode'] != 'apply':
        raise ValueError('mode')
    for field, flag in [('tags', '--tags'), ('skipTags', '--skip-tags')]:
        if options[field]:
            command.append(flag + '=' + ','.join(options[field]))
    if options['verbosity']:
        command.append('-' + 'v' * options['verbosity'])
    if request.get('vaultPassword') is not None:
        write(home / 'vault-password', request['vaultPassword'].encode())
        command += ['--vault-password-file', str(home / 'vault-password')]
    command.append(str(project / request['bundle']['main']))
    STAGE = 'dedicated_account'
    subprocess.run(['/usr/sbin/useradd', '--system', '--user-group', '--home-dir', str(home), '--shell', '/usr/sbin/nologin', username], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    user = pwd.getpwnam(username)
    receipt = Path('/run/nexus-jobs') / identity / 'ansible-account.json'
    write(receipt, json.dumps({'name': username, 'uid': user.pw_uid}).encode())
    for directory, dirs, files in os.walk(home):
        os.chown(directory, user.pw_uid, user.pw_gid)
        for name in files:
            os.chown(Path(directory) / name, user.pw_uid, user.pw_gid)
    os.chmod(ROOT, 0o711)

    def drop():
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)

    environment = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'ANSIBLE_CONFIG': str(home / 'ansible.cfg'), 'ANSIBLE_NOCOLOR': '1', 'PYTHONNOUSERSITE': '1', 'NEXUS_APPROVED_ALIASES': json.dumps(aliases), 'NEXUS_RECAP_FILE': str(home / 'recap.json'), 'NEXUS_TASKS_FILE': str(home / 'tasks.json')}
    del data, request
    try:
        STAGE = 'managed_environment_version'
        check = 'import importlib.metadata as m,json; expected=json.loads(' + repr(json.dumps(expected)) + '); actual={d.metadata["Name"].lower().replace("_","-"):d.version for d in m.distributions()}; assert all(actual.get(k)==v for k,v in expected.items()) and not (set(actual)-set(expected)-{"pip","setuptools"})'
        probe = subprocess.run([str(venv / 'bin/python'), '-I', '-c', check], cwd=home, env=environment, preexec_fn=drop, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if probe.returncode:
            raise ValueError('managed version')
        if locks:
            STAGE = 'collections_install'
            installed = subprocess.run([str(venv / 'bin/python'), '-I', str(trusted / 'collections.py'), str(home / 'collections-lock.json'), str(artifacts), str(project)], cwd=home, env=environment, preexec_fn=drop, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            if installed.returncode:
                raise ValueError('collection install')
        STAGE = 'playbook_process'
        result = subprocess.run(command, cwd=project, env=environment, preexec_fn=drop, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        recap = {}
        path = home / 'recap.json'
        if path.exists():
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != user.pw_uid or info.st_size > 8192:
                    raise ValueError('recap artifact')
                reported = json.loads(source.read(8193))
            fields = {'ok', 'changed', 'failures', 'unreachable', 'skipped', 'rescued', 'ignored'}
            if not isinstance(reported, dict) or set(reported) - set(aliases):
                raise ValueError('recap hosts')
            for alias, counts in reported.items():
                if not isinstance(counts, dict) or set(counts) != fields or any(type(value) is not int or not 0 <= value <= 1000000 for value in counts.values()):
                    raise ValueError('recap values')
                recap[server_ids[alias]] = counts
        tasks = []
        tasks_truncated = False
        path = home / 'tasks.json'
        if path.exists():
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != user.pw_uid or info.st_size > 48000:
                    raise ValueError('task artifact')
                history = json.loads(source.read(48001))
            if not isinstance(history, dict) or set(history) != {'events', 'truncated'} or type(history['truncated']) is not bool or not isinstance(history['events'], list) or len(history['events']) > 200:
                raise ValueError('task history')
            tasks_truncated = history['truncated']
            for event in history['events']:
                if not isinstance(event, dict) or set(event) != {'task', 'host', 'status', 'startedMs', 'durationMs'}:
                    raise ValueError('task fields')
                if event['host'] not in server_ids or event['status'] not in ('ok', 'changed', 'failed', 'ignored', 'unreachable', 'skipped'):
                    raise ValueError('task identity')
                if type(event['task']) is not int or not 1 <= event['task'] <= 1000000 or any(type(event[k]) is not int or not 0 <= event[k] <= 600000 for k in ('startedMs', 'durationMs')):
                    raise ValueError('task numeric values')
                tasks.append({'task': event['task'], 'serverId': server_ids[event['host']], 'status': event['status'], 'startedMs': event['startedMs'], 'durationMs': event['durationMs']})
        print(json.dumps({'state': 'playbook_exited', 'exitCode': result.returncode, 'hosts': recap, 'version': '2.22.0', 'tasks': tasks, 'tasksTruncated': tasks_truncated}))
        return 0 if result.returncode == 0 else 1
    finally:
        shutil.rmtree(home)
        subprocess.run(['/usr/sbin/userdel', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print(json.dumps({'state': 'playbook_setup_or_process_failed', 'stage': STAGE}))
        sys.exit(1)
