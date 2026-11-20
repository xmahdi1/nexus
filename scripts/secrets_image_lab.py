#!/usr/bin/env python3
"""Offline schema-8 → schema-12 image upgrade and matching-old-image rollback.
Requires local Docker, bcrypt, cryptography, and an already-local schema-8 image.
Never starts application workers, publishes ports, or reads a deployment .env.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

parser=argparse.ArgumentParser()
parser.add_argument('--old-image',required=True,help='Already-local trusted schema-8 image ID')
parser.add_argument('--new-image',default='nexus:phase1-security-check')
args=parser.parse_args()
if not re.fullmatch(r'(sha256:)?[a-f0-9]{12,64}',args.old_image):parser.error('old image must be a local image ID')
docker=['docker','--host','unix:///var/run/docker.sock']
for tag in [args.old_image,args.new_image]:subprocess.run(docker+['image','inspect',tag],check=True,capture_output=True)
with tempfile.TemporaryDirectory(prefix='nexus-secret-image-lab-') as directory:
    key=os.urandom(32)
    env={k:v for k,v in os.environ.items() if not k.startswith('NEXUS_')}
    env.update(
        NEXUS_PASSWORD_HASH=bcrypt.hashpw(b'Offline image fixture only',bcrypt.gensalt(rounds=4)).decode(),
        NEXUS_ENCRYPTION_KEY=base64.b64encode(key).decode(),
        NEXUS_TOTP_ENABLED='false',
        NEXUS_DB_PATH='/data/fixture.db',
    )
    def cli(image,*arguments,check=True,extra_env=None):
        command=docker+['run','--rm','--read-only','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','128m','--user',f'{os.getuid()}:{os.getgid()}','--mount',f'type=bind,source={directory},target=/data']
        for name in ['NEXUS_PASSWORD_HASH','NEXUS_ENCRYPTION_KEY','NEXUS_TOTP_ENABLED','NEXUS_DB_PATH']:command+=['-e',name]
        return subprocess.run(command+[image,*arguments],env=extra_env or env,check=check,capture_output=True,text=True,timeout=60)
    cli(args.old_image,'db-migrate','/data/fixture.db')
    cli(args.old_image,'owner-bootstrap','--from-env','owner')
    cli(args.old_image,'owner-activate','owner')
    path=Path(directory)/'fixture.db'
    values=json.dumps({'PASSWORD':os.urandom(20).hex(),'PORT':'5432'},separators=(',',':'),sort_keys=True)
    nonce=os.urandom(12)
    ssh_cipher=base64.b64encode(nonce+AESGCM(key).encrypt(nonce,b'fixture private SSH material',None)).decode()
    with sqlite3.connect(path) as database:
        assert database.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==8,'schema-8 image required'
        database.execute("INSERT INTO servers(id,name,host,port,username,private_key_enc)VALUES('fixture','Fixture','192.0.2.1',22,'fixture',?)",(ssh_cipher,))
        database.execute("INSERT INTO deployed_apps(id,server_id,name,status,vars_json)VALUES('app','fixture','preserved','running',?)",(values,))
        owner=database.execute("SELECT id,username,password_hash,status FROM users WHERE username='owner'").fetchone()
        admissions=database.execute('SELECT * FROM account_admissions ORDER BY user_id').fetchall()
    # No key means no data conversion; ledger/variables must remain intact.
    assert cli(args.new_image,'db-migrate','/data/fixture.db',check=False).returncode!=0,'keyless conversion accepted'
    cli(args.new_image,'db-migrate','--from-env','/data/fixture.db')
    with sqlite3.connect(path) as database:
        assert database.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert database.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==12
        assert 'vars_json' not in [row[1] for row in database.execute('PRAGMA table_info(deployed_apps)')]
        app=database.execute("SELECT id,server_id,name,status,vars_enc FROM deployed_apps WHERE id='app'").fetchone()
        assert app[2:4]==('preserved','running')
        assert app[4].startswith('v1:')
        sealed=base64.b64decode(app[4][3:])
        associated=b'nexus:deployment-variables:v1\0app\0fixture'
        assert AESGCM(key).decrypt(sealed[:12],sealed[12:],associated).decode()==values
        assert database.execute("SELECT id,username,password_hash,status FROM users WHERE username='owner'").fetchone()==owner
        assert database.execute('SELECT * FROM account_admissions ORDER BY user_id').fetchall()==admissions
        assert database.execute("SELECT private_key_enc FROM servers WHERE id='fixture'").fetchone()[0]==ssh_cipher
        database.execute("INSERT INTO vault_connections(server_id,port,tls_name,ca_pem,namespace)VALUES('fixture',8200,'vault.fixture','','')")
        job_output=os.urandom(20).hex()
        job_aad=b'nexus:job-output:v1\0job\0fixture'
        job_nonce=os.urandom(12)
        job_cipher='v1:'+base64.b64encode(job_nonce+AESGCM(key).encrypt(job_nonce,job_output.encode(),job_aad)).decode()
        database.execute("INSERT INTO supervised_runs(id,task_id,server_id,actor_id,command_hash,state,output_enc,exit_code,created_at,finished_at)VALUES('job','fixture-task','fixture',? ,?,'exited',?,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",(owner[0],'0'*64,job_cipher))
    wrong=dict(env,NEXUS_ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode())
    assert cli(args.new_image,'db-migrate','--from-env','/data/fixture.db',extra_env=wrong,check=False).returncode!=0,'wrong-key reopen accepted'
    assert cli(args.old_image,'db-migrate','/data/fixture.db',check=False).returncode!=0,'old binary accepted new schema'
    snapshots=list(Path(directory).glob('fixture.db.pre-migration-*.db'))
    assert snapshots,'missing pre-migration recovery set'
    for snapshot in snapshots:
        assert snapshot.stat().st_mode & 0o777==0o600,'snapshot must remain private'
        cli(args.old_image,'db-migrate','/data/'+snapshot.name)
        with sqlite3.connect(snapshot) as database:
            assert database.execute('SELECT max(version) FROM schema_migrations').fetchone()[0]==8
            assert database.execute("SELECT vars_json FROM deployed_apps WHERE id='app'").fetchone()[0]==values
    current_key=Path(directory)/'current-key.base64'
    current_key.write_bytes(base64.b64encode(key)+b'\n')
    current_key.chmod(0o600)
    cli(args.new_image,'key-rotate','--offline','--key-file','/data/current-key.base64','/data/fixture.db','/data/rotated')
    rotated=Path(directory)/'rotated'
    assert (rotated/'READY').is_file(),'rotation not completed'
    new_key=base64.b64decode((rotated/'encryption-key.base64').read_bytes().strip())
    assert new_key!=key
    for item in rotated.iterdir():
        assert item.stat().st_mode & 0o777==0o600,'rotation files must remain private'
    rotated_env=dict(env,NEXUS_ENCRYPTION_KEY=base64.b64encode(new_key).decode())
    cli(args.new_image,'db-migrate','--from-env','/data/rotated/nexus.db',extra_env=rotated_env)
    assert cli(args.new_image,'db-migrate','--from-env','/data/rotated/nexus.db',check=False).returncode!=0,'rotated DB accepted old key'
    with sqlite3.connect(rotated/'nexus.db') as database:
        sealed=base64.b64decode(database.execute("SELECT vars_enc FROM deployed_apps WHERE id='app'").fetchone()[0][3:])
        assert AESGCM(new_key).decrypt(sealed[:12],sealed[12:],associated).decode()==values
        sealed=base64.b64decode(database.execute("SELECT private_key_enc FROM servers WHERE id='fixture'").fetchone()[0])
        assert AESGCM(new_key).decrypt(sealed[:12],sealed[12:],None)==b'fixture private SSH material'
        assert database.execute("SELECT id,username,password_hash,status FROM users WHERE username='owner'").fetchone()==owner
        assert database.execute("SELECT port,tls_name,ca_pem,namespace FROM vault_connections WHERE server_id='fixture'").fetchone()==(8200,'vault.fixture','','')
        job_sealed=base64.b64decode(database.execute("SELECT output_enc FROM supervised_runs WHERE id='job'").fetchone()[0][3:])
        assert AESGCM(new_key).decrypt(job_sealed[:12],job_sealed[12:],job_aad).decode()==job_output
    cli(args.new_image,'db-migrate','--from-env','/data/fixture.db')
    print('Offline image upgrade, rotation and recovery checks passed.')
