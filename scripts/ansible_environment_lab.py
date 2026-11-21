#!/usr/bin/env python3
"""Validate the embedded controller lifecycle in an owned disposable container.

Uses no host mounts, ports, Docker sockets or real Nexus configuration. Requires
an already-local official Python 3.14 image with useradd/runuser. All installation
files, users and package downloads remain in the container's disposable overlay.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Already-local trusted Python 3.14 image ID')
    args = parser.parse_args()
    if not __import__('re').fullmatch(r'(sha256:)?[a-f0-9]{12,64}', args.image):
        parser.error('Use a local trusted image ID')
    docker = ['docker', '--host', 'unix:///var/run/docker.sock']
    subprocess.run(docker + ['image', 'inspect', args.image], check=True, capture_output=True)
    root = Path(__file__).resolve().parent.parent
    generated = (root / 'nexus/internal/ansibleenv/bundle_generated.go').read_text()
    bundle = json.loads(generated.split('const bundle = ', 1)[1].strip())
    remote = (root / 'nexus/internal/ansibleenv/remote.py').read_text()
    nonce = uuid.uuid4().hex
    name = 'nexus-ansible-environment-lab-' + nonce
    container = None
    try:
        container = subprocess.check_output(docker + ['run', '-d', '--name', name, '--label', 'nexus.ansible.environment.lab=' + nonce,
            '--pids-limit', '128', '--memory', '512m', '--cpus', '1', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE',
            '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--security-opt', 'no-new-privileges', args.image, 'sleep', '900'], text=True).strip()
        subprocess.run(docker + ['exec', container, 'ln', '-s', '/usr/local/bin/python3', '/usr/bin/python3'], check=True, capture_output=True)
        def action(value, expected=0):
            script = 'ACTION=' + repr(value) + '\nBUNDLE=' + repr(bundle) + '\n' + remote
            result = subprocess.run(docker + ['exec', '-i', container, '/usr/bin/python3', '-I', '-c', script], capture_output=True, text=True, timeout=420)
            if result.returncode != expected:
                raise RuntimeError('Environment action failed: ' + value + ': ' + result.stdout[-1000:] + result.stderr[-1000:])
            data = json.loads(result.stdout)
            print(value + ': ' + json.dumps(data, sort_keys=True), flush=True)
            return data
        assert action('health')['state'] == 'absent'
        assert action('install')['state'] == 'ready'
        assert action('health')['version'] == '2.22.0'
        assert action('install', 1)['state'] == 'failed', 'existing environment was adopted'
        assert action('update')['state'] == 'ready'
        subprocess.run(docker + ['exec', container, '/usr/bin/python3', '-I', '-c', "from pathlib import Path;p=Path('/var/lib/nexus-ansible/environment/ansible.cfg');p.write_bytes(p.read_bytes()+b'\\n# modified\\n')"], check=True, capture_output=True)
        assert action('health', 1)['state'] == 'failed', 'modified configuration was accepted'
        # Removal validates ownership independently of installation health.
        assert action('remove')['state'] == 'removed'
        assert action('health')['state'] == 'absent'
        # The ownership marker and dedicated identity survive removal; reinstall
        # is explicit and cannot adopt an unrelated account or home.
        assert action('install')['state'] == 'ready'
        assert action('remove')['state'] == 'removed'
        print('Dedicated-user installation, update, integrity checks, removal and reinstall passed.', flush=True)
    finally:
        if container:
            metadata = json.loads(subprocess.check_output(docker + ['inspect', container], text=True))[0]
            if metadata['Name'] != '/' + name or metadata['Config']['Labels'].get('nexus.ansible.environment.lab') != nonce or metadata.get('Mounts'):
                raise RuntimeError('Refusing cleanup without exact lab ownership and an empty mount list')
            subprocess.run(docker + ['rm', '-f', container], check=True, capture_output=True)


if __name__ == '__main__':
    main()
