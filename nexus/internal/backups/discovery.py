"""Read-only source inventory; container environment values are never requested."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

request = json.loads(sys.stdin.buffer.read(8193))
rows = []
seen = set()
truncated = False


def add(source, consistency, state='ready', note=''):
    global truncated
    key = json.dumps(source, sort_keys=True)
    if key in seen:
        return
    seen.add(key)
    if len(rows) >= 250:
        truncated = True
        return
    rows.append({'id': hashlib.sha256(key.encode()).hexdigest(), 'source': source,
                 'consistency': consistency, 'state': state, 'note': note})


def file(path, label=None):
    path = Path(path)
    try:
        if not path.exists() or path.is_symlink():
            return
        name = str(path)
        if name in ('/proc', '/sys', '/dev', '/run') or any(name.startswith(prefix + '/') for prefix in ('/proc', '/sys', '/dev', '/run')):
            return
        if name.startswith(request['workRoot']):
            return
        kind = 'sqlite' if path.is_file() and path.suffix.lower() in ('.db', '.sqlite', '.sqlite3') else 'files'
        add({'kind': kind, 'path': name, 'label': (label or name)[:120]},
            'SQLite snapshot' if kind == 'sqlite' else 'File copy; live writes may be inconsistent')
    except OSError:
        return


prefix = request.get('path', '')
if prefix:
    parent = Path(prefix)
    file(parent)
    try:
        children = sorted(parent.iterdir(), key=lambda p: p.name)[:101]
        if len(children) > 100:
            truncated = True
        for child in children[:100]:
            file(child)
    except OSError:
        pass
else:
    for name in ('/', '/etc', '/home', '/srv', '/opt', '/var/www', '/var/lib'):
        file(name)
    try:
        for line in Path('/proc/mounts').read_text().splitlines()[:500]:
            fields = line.split()
            if len(fields) >= 3 and fields[2] not in ('proc', 'sysfs', 'devtmpfs', 'cgroup', 'cgroup2', 'tmpfs', 'overlay', 'squashfs'):
                file(fields[1].replace('\\040', ' '))
    except OSError:
        pass
path = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
tools = {name: shutil.which(name, path=path) is not None for name in ('pg_dumpall', 'pg_dump', 'mysqldump', 'mariadb-dump', 'mongodump', 'docker')}
tools['restic'] = Path(request['workRoot'] + '/tools/restic-0.20.0').is_file()
for kind, tool, port, user in [('postgres', 'pg_dumpall', 5432, 'postgres'), ('mysql', 'mysqldump', 3306, 'root'), ('mariadb', 'mariadb-dump', 3306, 'root'), ('mongodb', 'mongodump', 27017, '')]:
    if tools[tool]:
        add({'kind': kind, 'label': 'Native ' + kind, 'database': {'host': '127.0.0.1', 'port': port, 'user': user}},
            'Logical database export', 'needs_setup', 'Enter database access settings; discovery does not read database contents.')
if tools['docker']:
    docker = [shutil.which('docker', path=path), '--host', 'unix:///var/run/docker.sock']
    def query(arguments):
        result = subprocess.run(docker + arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, env={'PATH': path})
        if result.returncode or len(result.stdout) > 2 << 20:
            raise ValueError('Docker discovery unavailable')
        return result.stdout.decode().splitlines()
    try:
        containers = query(['ps', '--all', '--no-trunc', '--format={{json .}}'])
        if len(containers) > 64:
            truncated = True
        for line in containers[:64]:
            item = json.loads(line)
            identity = item['ID']
            label = item.get('Names', identity)[:80]
            image = item.get('Image', '').rsplit('/', 1)[-1].split(':', 1)[0]
            kind = {'postgres': 'postgres', 'postgresql': 'postgres', 'timescaledb': 'postgres', 'mysql': 'mysql', 'percona': 'mysql', 'mariadb': 'mariadb', 'mongo': 'mongodb', 'mongodb': 'mongodb'}.get(image)
            if kind:
                add({'kind': kind, 'containerId': identity, 'label': label + ' · ' + kind, 'database': {'containerEnvironment': kind != 'mongodb'}},
                    'Logical database export', 'needs_setup' if kind == 'mongodb' else 'ready',
                    'Set MongoDB credentials if authentication is enabled.' if kind == 'mongodb' else 'Uses configured container credentials; the dump tool must exist in this container.')
            details = query(['inspect', '--format={{json .Mounts}}', '--', identity])
            for mount in json.loads(details[0] if details else '[]')[:64]:
                if mount.get('Type') == 'bind':
                    add({'kind': 'docker-bind', 'containerId': identity, 'path': mount['Source'], 'label': (label + ' · ' + mount.get('Destination', 'bind'))[:120]},
                        'File copy; live application writes may be inconsistent')
        volumes = query(['volume', 'ls', '--format={{json .}}'])
        if len(volumes) > 128:
            truncated = True
        for line in volumes[:128]:
            item = json.loads(line)
            local = item.get('Driver') == 'local'
            add({'kind': 'docker-volume', 'volume': item['Name'], 'label': item['Name'][:120]},
                'File copy; live application writes may be inconsistent', 'ready' if local else 'unsupported',
                '' if local else 'Plugin volume: use its provider export or select a mounted path.')
    except Exception:
        tools['dockerDiscovery'] = False
    else:
        tools['dockerDiscovery'] = True
while len(json.dumps({'sources': rows, 'tools': tools, 'truncated': truncated}).encode()) > 240 << 10:
    rows.pop()
    truncated = True
print(json.dumps({'sources': rows, 'tools': tools, 'truncated': truncated}))
