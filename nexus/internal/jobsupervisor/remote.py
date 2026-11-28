"""Fixed remote protocol. Input comes only over stdin, never shell interpolation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import pwd

BASE = Path('/run/nexus-jobs')


def reply(state, **values):
    print(json.dumps({'state': state, 'verified': False, **values}))


def private(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if info.st_uid != 0 or not expected(info.st_mode) or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise ValueError('unsafe private artifact')


def write_new(path, content):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())


def probe():
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir() or not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
        return False
    if not os.access('/usr/bin/systemctl', os.X_OK) or not os.access('/usr/bin/systemd-run', os.X_OK):
        return False
    try:
        process = subprocess.run(['/usr/bin/systemctl', 'show', '--property=Version', '--value'], capture_output=True, timeout=5)
    except Exception:
        return False
    version = re.match(rb'(\d+)', process.stdout.strip())
    return process.returncode == 0 and version is not None and int(version.group(1)) >= 240


def main():
    os.umask(0o077)
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    payload = sys.stdin.buffer.read(200001)
    if len(payload) > 200000:
        return reply('unknown', detail='invalid_request')
    request = json.loads(payload)
    if not probe():
        return reply('unsupported', noDispatch=request.get('action') == 'start', detail='requires_root_systemd_cgroup_v2_python3')
    action = request['action']
    if action == 'probe':
        return reply('supported', verified=True)
    identity, digest = request['id'], request['hash']
    if not re.fullmatch('[a-f0-9]{32}', identity) or not re.fullmatch('[a-f0-9]{64}', digest):
        return reply('unknown', detail='invalid_identity')
    unit = 'nexus-job-' + identity + '.service'
    # Unit descriptions are visible to other local users. Keep command hashes
    # in the private metadata only, so low-entropy secret arguments cannot be
    # guessed from a public fingerprint.
    description = 'nexus-job:' + identity
    directory = BASE / identity
    if action == 'start':
        command = request['command']
        encoded_input = request.get('input', '')
        if not isinstance(encoded_input, str) or len(encoded_input) > 131072:
            return reply('unknown', detail='invalid_command')
        private_input = base64.b64decode(encoded_input, validate=True)
        if len(private_input) > 98304:
            return reply('unknown', detail='invalid_command')
        if not isinstance(command, str) or not command or '\x00' in command or len(command.encode()) > 16384:
            return reply('unknown', detail='invalid_command')
        bound = command if not private_input else 'nexus:job-command-input:v1\x00' + command + '\x00' + hashlib.sha256(private_input).hexdigest()
        if hashlib.sha256(bound.encode()).hexdigest() != digest:
            return reply('unknown', detail='invalid_command')
        runtime = request['runtimeSeconds']
        isolation = request.get('isolation', '')
        if isolation not in ('', 'github-runner', 'ansible', 'backup'):
            return reply('unknown', detail='invalid_request')
        if not isinstance(runtime, int) or not 1 <= runtime <= (86400 if isolation == 'backup' else 3600 if isolation == 'github-runner' else 600):
            return reply('unknown', detail='invalid_runtime')
        if not BASE.exists():
            BASE.mkdir(mode=0o700)
        private(BASE, True)
        # Exclusive reservation survives lost dispatch acknowledgements. Never
        # replay an existing ID, even if the earlier systemd-run failed.
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            return reply('unknown', detail='identity_already_reserved')
        # Reserve BEFORE checking capacity: a duplicate identity must stay
        # uncertain even at capacity, including concurrent start requests. This
        # newly-created directory has no payload or possible dispatched process.
        if sum(1 for _ in BASE.iterdir()) > 1024:
            directory.rmdir()
            return reply('capacity_exceeded', noDispatch=True, detail='private_artifact_limit')
        metadata = json.dumps({'id': identity, 'hash': digest, **({'isolation': isolation} if isolation else {})}).encode()
        write_new(directory / 'metadata.json', metadata)
        write_new(directory / 'request.json', json.dumps({'id': identity, 'hash': digest, 'command': command, 'input': encoded_input}).encode())
        worker = base64.b64decode(request['worker'], validate=True)
        if len(worker) > 32768:
            return reply('unknown', detail='invalid_worker')
        write_new(directory / 'worker.py', worker)
        command = ['systemd-run', '--quiet', '--unit=' + unit, '--description=' + description]
        for setting in ['Type=exec', 'RemainAfterExit=yes', 'Restart=no', 'Slice=system.slice', 'KillMode=control-group', 'SendSIGKILL=yes', 'TimeoutStopSec=5s', 'RuntimeMaxSec=' + str(runtime) + 's', 'UMask=0077', 'WorkingDirectory=/', 'StandardOutput=null', 'StandardError=null']:
            command.append('--property=' + setting)
        if isolation == 'backup':
            command += ['--property=NoNewPrivileges=yes', '--property=MemoryMax=2G', '--property=CPUQuota=200%', '--property=TasksMax=256']
        if isolation in ('github-runner', 'ansible'):
            mount = '/run/nexus-runner' if isolation == 'github-runner' else '/run/nexus-ansible-job'
            for setting in ['TemporaryFileSystem=' + mount + ':rw,exec,nosuid,nodev,size=1G,mode=0711', 'PrivateTmp=yes', 'InaccessiblePaths=-/run/docker.sock -/run/containerd/containerd.sock -/run/podman/podman.sock', 'ProtectHome=yes', 'NoNewPrivileges=yes', 'MemoryMax=2G', 'CPUQuota=200%', 'TasksMax=256']:
                command.append('--property=' + setting)
        command += ['/usr/bin/python3', '-I', '-S', str(directory / 'worker.py')]
        try:
            process = subprocess.run(command, capture_output=True, timeout=10)
        except Exception:
            return reply('unknown', detail='dispatch_acknowledgement_lost')
        return reply('accepted' if process.returncode == 0 else 'unknown', detail='inspect_before_any_retry')
    private(BASE, True)
    private(directory, True)
    private(directory / 'metadata.json')
    metadata = json.loads((directory / 'metadata.json').read_text())
    if metadata.get('id') != identity or metadata.get('hash') != digest or set(metadata) - {'id', 'hash', 'isolation'} or metadata.get('isolation', '') not in ('', 'github-runner', 'ansible', 'backup'):
        return reply('unknown', detail='artifact_identity_mismatch')
    properties = ['Description', 'InvocationID', 'LoadState', 'ActiveState', 'SubState', 'Result', 'ControlGroup', 'KillMode', 'SendSIGKILL', 'Restart', 'Transient', 'NoNewPrivileges', 'PrivateTmp', 'ProtectHome', 'TemporaryFileSystem']

    def cgroup_empty():
        events = Path('/sys/fs/cgroup/system.slice/' + unit + '/cgroup.events')
        return not events.exists() or dict(line.split() for line in events.read_text().splitlines()).get('populated') == '0'

    def inspect():
        result = subprocess.run(['systemctl', 'show', '--no-pager', '--property=' + ','.join(properties), unit], capture_output=True, timeout=5)
        values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        if values.get('LoadState') == 'not-found' and (directory / 'cancel.json').exists():
            # A successful stop may garbage-collect the transient unit before
            # its acknowledgement arrives. This private receipt is written only
            # AFTER observing the bound unit invocation, never from a bare ID.
            private(directory / 'cancel.json')
            control = json.loads((directory / 'cancel.json').read_text())
            invocation = control.get('invocationID', '')
            if control.get('id') != identity or control.get('hash') != digest or not re.fullmatch('[a-f0-9]{32}', invocation) or (request.get('invocationID') and request['invocationID'] != invocation) or not cgroup_empty():
                raise ValueError('stopped identity unavailable')
            return {'ActiveState': 'inactive', 'Result': 'success'}, True, invocation
        if result.returncode or values.get('Description') != description or values.get('LoadState') != 'loaded' or values.get('Transient') != 'yes':
            raise ValueError('unit identity unavailable')
        if values.get('KillMode') != 'control-group' or values.get('SendSIGKILL') != 'yes' or values.get('Restart') != 'no':
            raise ValueError('unit containment changed')
        if metadata.get('isolation') == 'backup' and values.get('NoNewPrivileges') != 'yes':
            raise ValueError('backup containment changed')
        if metadata.get('isolation') in ('github-runner', 'ansible'):
            mount = '/run/nexus-runner:' if metadata['isolation'] == 'github-runner' else '/run/nexus-ansible-job:'
            if values.get('NoNewPrivileges') != 'yes' or values.get('PrivateTmp') != 'yes' or values.get('ProtectHome') != 'yes' or mount not in values.get('TemporaryFileSystem', ''):
                raise ValueError('job containment changed')
        invocation = values.get('InvocationID', '')
        if not re.fullmatch('[a-f0-9]{32}', invocation) or (request.get('invocationID') and request['invocationID'] != invocation):
            raise ValueError('unit invocation changed')
        group = '/system.slice/' + unit
        if values.get('ControlGroup', '') not in {'', group}:
            raise ValueError('cgroup identity changed')
        empty = cgroup_empty()
        return values, empty, invocation

    values, empty, invocation = inspect()
    if action == 'cancel' and not empty:
        cancel_file = directory / 'cancel.json'
        if values.get('Result') != 'timeout' and not cancel_file.exists():
            write_new(cancel_file, json.dumps({**metadata, 'invocationID': invocation}).encode())
        process = subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=15)
        values, empty, invocation = inspect()
        if not empty:
            return reply('unknown', detail='cgroup_not_empty', invocationID=invocation)
    receipt = {}
    if (directory / 'status.json').exists():
        private(directory / 'status.json')
        receipt = json.loads((directory / 'status.json').read_text())
        if receipt.get('id') != identity or receipt.get('hash') != digest:
            return reply('unknown', detail='receipt_identity_mismatch')
    complete = empty and receipt.get('state') == 'complete' and isinstance(receipt.get('exitCode'), int)
    state = 'running'
    if complete:
        state = 'exited' if receipt['exitCode'] == 0 and not receipt.get('outputError') else 'failed'
    elif empty and (directory / 'cancel.json').exists() and values.get('ActiveState') in {'inactive', 'failed'}:
        state = 'cancelled'
    elif empty and values.get('Result') == 'timeout':
        state = 'timed_out'
    elif empty and values.get('ActiveState') in {'inactive', 'failed'}:
        # We can prove the managed cgroup stopped, but cannot invent a shell
        # outcome when the worker died before writing its final receipt.
        state = 'interrupted'
    elif empty or values.get('ActiveState') not in {'active', 'activating', 'deactivating'}:
        return reply('unknown', detail='missing_terminal_receipt', invocationID=invocation)
    output = b''
    if (directory / 'output').exists():
        private(directory / 'output')
        with (directory / 'output').open('rb') as file:
            output = file.read(65536)
    if action == 'release':
        if not empty or state not in {'exited', 'failed', 'cancelled', 'timed_out', 'interrupted'}:
            return reply('unknown', detail='release_requires_verified_terminal_state', invocationID=invocation)
        subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=15)
        subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True, timeout=5)
        for filename, prefix, home in [('runner-account.json', 'nxr-', '/run/nexus-runner/home'), ('ansible-account.json', 'nxa-', '/run/nexus-ansible-job/home')]:
            account = directory / filename
            if not account.exists():
                continue
            private(account)
            record = json.loads(account.read_text())
            if record.get('name') != prefix + identity[:20] or not isinstance(record.get('uid'), int) or record['uid'] <= 0:
                return reply('unknown', detail='unexpected_artifact', invocationID=invocation)
            try:
                user = pwd.getpwnam(record['name'])
            except KeyError:
                user = None
            if user is not None:
                if user.pw_uid != record['uid'] or user.pw_dir != home or user.pw_shell != '/usr/sbin/nologin':
                    return reply('unknown', detail='unexpected_artifact', invocationID=invocation)
                if subprocess.run(['/usr/sbin/userdel', record['name']], capture_output=True, timeout=15).returncode:
                    return reply('unknown', detail='unexpected_artifact', invocationID=invocation)
        # Only known regular private artifacts from this exact reserved run.
        allowed = {'metadata.json', 'request.json', 'worker.py', 'command.sh', 'status.json', 'status.new', 'output', 'cancel.json', 'runner-account.json', 'ansible-account.json'}
        for file in directory.iterdir():
            if file.name not in allowed:
                return reply('unknown', detail='unexpected_artifact', invocationID=invocation)
            private(file)
        for file in directory.iterdir():
            file.unlink()
        directory.rmdir()
    return reply(state, verified=True, empty=empty, invocationID=invocation, exitCode=receipt.get('exitCode') if complete else None, output=base64.b64encode(output).decode(), truncated=bool(receipt.get('truncated')), released=action == 'release')


try:
    main()
except Exception:
    # Never echo exception text: it may contain payload or remote file contents.
    reply('unknown', detail='inspection_or_dispatch_unavailable')
