#!/usr/bin/env python3
"""Dedicated Linux SSH/SFTP/proxy/cron/terminal/inventory lab, with no host Docker
socket, host network or privileged container. All writable target data is disposable.
"""
import argparse
import os
from pathlib import Path
import subprocess
import socket
import tempfile
import time
import uuid
parser=argparse.ArgumentParser()
parser.add_argument('--network-controls',action='store_true',help='Grant NET_ADMIN only inside the disposable container to test IPv4 UFW rules')
parser.add_argument('--ipv6',action='store_true',help='Also validate IPv6 UFW rules inside the disposable network namespace')
parser.add_argument('--base-image',choices=['debian:bookworm-slim','ubuntu:24.04'],default='debian:bookworm-slim')
args=parser.parse_args()
if args.ipv6 and not args.network_controls:parser.error('--ipv6 requires --network-controls')
root=Path(__file__).resolve().parent.parent
docker=['docker','--host','unix:///var/run/docker.sock']
subprocess.run(docker+['build','--build-arg','BASE_IMAGE='+args.base_image,'-t','nexus:disposable-ssh-lab',str(root/'scripts/ssh_lab')],check=True)
with tempfile.TemporaryDirectory(prefix='nexus-ssh-lab-') as directory:
    key=Path(directory)/'client'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    nonce=uuid.uuid4().hex
    network_options=['--cap-add','NET_ADMIN','-e','NEXUS_LAB_FIREWALL=1','-e','NEXUS_LAB_FIREWALL_IPV6='+('1' if args.ipv6 else '0')] if args.network_controls else []
    container=subprocess.check_output(docker+['run','-d','--rm','--pids-limit','128','--memory','256m','--security-opt','no-new-privileges','-p','127.0.0.1::22','--mount',f'type=bind,source={key}.pub,target=/fixture-authorized-key,readonly','-e','NEXUS_LAB_NONCE='+nonce,*network_options,'nexus:disposable-ssh-lab'],text=True).strip()
    try:
        public=''
        for _ in range(100):
            result=subprocess.run(docker+['exec',container,'cat','/etc/ssh/ssh_host_ed25519_key.pub'],capture_output=True,text=True)
            if result.returncode==0:
                public=result.stdout;break
            time.sleep(.1)
        if not public:raise RuntimeError('Disposable SSH target did not initialize')
        address=subprocess.check_output(docker+['port',container,'22'],text=True).strip()
        for _ in range(300):
            try:
                host,port=address.rsplit(':',1)
                with socket.create_connection((host,int(port)),timeout=1) as connection:
                    if connection.recv(128).startswith(b'SSH-'):break
            except OSError:time.sleep(.1)
        else:
            subprocess.run(docker+['logs',container],check=False)
            subprocess.run(docker+['exec',container,'cat','/tmp/caddy-fixture.log'],check=False)
            raise RuntimeError('Disposable SSH listener did not become ready')
        env={k:v for k,v in os.environ.items() if not k.startswith('NEXUS_')}
        env.update(NEXUS_DISPOSABLE_SSH_ADDR=address,NEXUS_DISPOSABLE_KEY_FILE=str(key),NEXUS_DISPOSABLE_HOST_KEY=public,NEXUS_DISPOSABLE_NONCE=nonce,NEXUS_DISPOSABLE_FIREWALL='1' if args.network_controls else '0',NEXUS_DISPOSABLE_IPV6='1' if args.ipv6 else '0')
        subprocess.run(['go','test','-race','./internal/api','-run','^TestDedicatedDisposableLinuxLab$','-count=1','-v'],cwd=root/'nexus',env=env,check=True)
    finally:
        subprocess.run(docker+['stop','--time','2',container],stdout=subprocess.DEVNULL,check=False)
