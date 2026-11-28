#!/usr/bin/env python3
"""Run real pinned Ansible as isolated job UIDs in an owned container.

No host mounts/ports/keys or live Nexus configuration. The container installs the
reviewed environment, then executes local-only playbooks, including Vault files.
Systemd/mount namespace/cgroup proof is covered separately by supervision_lab.
"""

import argparse
import json
from pathlib import Path
import re
import secrets
import subprocess
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True, help="Already-local trusted Python 3.14 image ID")
parser.add_argument(
    "--ssh",
    action="store_true",
    help="Also install an owned loopback SSH target in the disposable container",
)
args = parser.parse_args()
if not re.fullmatch(r"(sha256:)?[a-f0-9]{12,64}", args.image):
    parser.error("Use an existing local image ID")
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
subprocess.run(docker + ["image", "inspect", args.image], check=True, capture_output=True)
root = Path(__file__).resolve().parent.parent
generated = (root / "nexus/internal/ansibleenv/bundle_generated.go").read_text()
bundle = json.loads(generated.split("const bundle = ", 1)[1].strip())
environment = (root / "nexus/internal/ansibleenv/remote.py").read_text()
remote = (root / "nexus/internal/ansible/job_remote.py").read_text()
callback = (root / "nexus/internal/ansible/job_callback.py").read_text()
collections = (root / "nexus/internal/ansible/collections.py").read_text()
nonce = uuid.uuid4().hex
name = "nexus-ansible-execution-lab-" + nonce
container = None
try:
    container = subprocess.check_output(
        docker
        + [
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "nexus.ansible.execution.lab=" + nonce,
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "DAC_OVERRIDE",
            "--cap-add",
            "SETUID",
            "--cap-add",
            "SETGID",
            "--cap-add",
            "SYS_CHROOT",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/run/nexus-ansible-job:rw,exec,nosuid,nodev,size=512m,mode=0711",
            args.image,
            "sleep",
            "900",
        ],
        text=True,
    ).strip()
    subprocess.run(
        docker + ["exec", container, "ln", "-s", "/usr/local/bin/python3", "/usr/bin/python3"],
        check=True,
        capture_output=True,
    )
    install = subprocess.run(
        docker
        + [
            "exec",
            "-i",
            container,
            "/usr/bin/python3",
            "-I",
            "-c",
            "ACTION='install'\nBUNDLE=" + repr(bundle) + "\n" + environment,
        ],
        capture_output=True,
        text=True,
        timeout=420,
    )
    if install.returncode or json.loads(install.stdout).get("state") != "ready":
        raise RuntimeError(
            "Reviewed Ansible environment installation failed: "
            + install.stdout[-1000:]
            + install.stderr[-1000:]
        )
    print("Pinned environment installed.", flush=True)
    ssh_target = None
    if args.ssh:
        setup = """
import os,pwd,subprocess,json
from pathlib import Path
env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
subprocess.run(['apt-get','update','-qq'],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['apt-get','install','-y','-qq','openssh-server','openssh-client'],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['useradd','--create-home','--shell','/bin/sh','fixture-target'],check=True)
password=subprocess.check_output(['openssl','passwd','-6','-stdin'],input=os.urandom(32).hex().encode()).decode().strip()
subprocess.run(['usermod','--password',password,'fixture-target'],check=True)
subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f','/tmp/fixture-client'],check=True)
user=pwd.getpwnam('fixture-target')
ssh=Path(user.pw_dir)/'.ssh';ssh.mkdir(mode=0o700);os.chown(ssh,user.pw_uid,user.pw_gid)
authorized=ssh/'authorized_keys';authorized.write_bytes(Path('/tmp/fixture-client.pub').read_bytes());authorized.chmod(0o600);os.chown(authorized,user.pw_uid,user.pw_gid)
Path('/run/sshd').mkdir(exist_ok=True)
Path('/tmp/fixture-sshd.conf').write_text('Port 2222\\nListenAddress 127.0.0.1\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nPasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin no\\nUsePAM no\\nAllowUsers fixture-target\\nSubsystem sftp internal-sftp\\n')
subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f','/tmp/fixture-sshd.conf'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=open('/tmp/fixture-sshd.log','w'))
Path('/tmp/fixture-known-hosts').write_text('[127.0.0.1]:2222 '+Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text())
import time
time.sleep(.2)
probe=subprocess.run(['ssh','-F','/dev/null','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/tmp/fixture-known-hosts','-o','BatchMode=yes','-i','/tmp/fixture-client','-p','2222','fixture-target@127.0.0.1','id -u'],capture_output=True,text=True)
if probe.returncode:raise RuntimeError(probe.stderr+Path('/tmp/fixture-sshd.log').read_text())
print(json.dumps({'user':'fixture-target','privateKey':Path('/tmp/fixture-client').read_text(),'knownHosts':'[127.0.0.1]:2222 '+Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text()}))
"""
        ssh_target = json.loads(
            subprocess.run(
                docker + ["exec", "-i", container, "/usr/bin/python3", "-I", "-c", setup],
                capture_output=True,
                text=True,
                timeout=240,
                check=True,
            ).stdout
        )
        print("Owned loopback SSH target ready; no host ports published.", flush=True)
    password = secrets.token_hex(20)
    secret = secrets.token_hex(20)
    encrypt = "from ansible.parsing.vault import VaultLib,VaultSecret;import sys,json;v=json.load(sys.stdin);sys.stdout.write(VaultLib([('default',VaultSecret(v['password'].encode()))]).encrypt(('private_value: '+v['secret']+'\\n').encode()).decode())"
    encrypted = subprocess.run(
        docker
        + [
            "exec",
            "-i",
            container,
            "/var/lib/nexus-ansible/environment/venv/bin/python",
            "-I",
            "-c",
            encrypt,
        ],
        input=json.dumps({"password": password, "secret": secret}),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    alias = "nexus_host_" + "a" * 64
    playbook = """---
- hosts: all
  connection: local
  gather_facts: false
  vars_files: [secrets.yml]
  tasks:
    - name: Private task names never leave the controller
      ansible.builtin.assert:
        that:
          - lookup('pipe', 'id -u') != '0'
          - lookup('pipe', 'id -G') == lookup('pipe', 'id -g')
          - lookup('pipe', 'cat /dev/stdin') == ''
          - lookup('env', 'NEXUS_JOB_ID') == ''
          - lookup('env', 'SSH_AUTH_SOCK') == ''
          - private_value == expected_value
    - ansible.builtin.debug:
        msg: "{{ private_value }}"
    - ansible.builtin.copy:
        dest: "{{ proof_dest }}"
        content: "{{ private_value }}"
        mode: '0600'
      no_log: true
"""
    collection_setup = r"""
import hashlib,io,json,tarfile
from pathlib import Path
plugin=b'from ansible.module_utils.basic import AnsibleModule\ndef main():\n    module=AnsibleModule(argument_spec={},supports_check_mode=True)\n    module.exit_json(changed=False,fixture=True)\nif __name__ == \"__main__\":\n    main()\n'
cache=Path('/var/lib/nexus-ansible/collections/artifacts');cache.mkdir(parents=True,mode=0o755)
locks=[]
for collection_name,dependencies in [('base',{}),('example',{'fixture.base':'>=1.0.0,<2.0.0'})]:
 file_manifest=b'{"files": []}'
 manifest={'collection_info':{'namespace':'fixture','name':collection_name,'version':'1.0.0','dependencies':dependencies},'file_manifest_file':{'name':'FILES.json','chksum_type':'sha256','chksum_sha256':hashlib.sha256(file_manifest).hexdigest()}}
 output=io.BytesIO()
 with tarfile.open(fileobj=output,mode='w:gz') as archive:
  for name,data in {'MANIFEST.json':json.dumps(manifest).encode(),'FILES.json':file_manifest,'plugins/modules/probe.py':plugin}.items():
   item=tarfile.TarInfo(name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
 data=output.getvalue();digest=hashlib.sha256(data).hexdigest()
 path=cache/(digest+'.tar.gz');path.write_bytes(data);path.chmod(0o644)
 locks.append({'namespace':'fixture','name':collection_name,'version':'1.0.0','sha256':digest})
print(json.dumps(locks))
"""
    collection_locks = json.loads(
        subprocess.run(
            docker + ["exec", "-i", container, "/usr/bin/python3", "-I", "-c", collection_setup],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    cases = [("local", mode) for mode in ["syntax", "check", "apply", "failure", "collection"]]
    if args.ssh:
        cases.extend(("ssh", mode) for mode in ["syntax", "check", "apply", "unreachable"])
    for connection, mode in cases:
        identity = uuid.uuid4().hex
        subprocess.run(
            docker + ["exec", container, "mkdir", "-p", "/run/nexus-jobs/" + identity],
            check=True,
            capture_output=True,
        )
        selected_playbook = (
            playbook
            if connection == "local"
            else playbook.replace("connection: local", "connection: ssh")
        )
        if mode == "collection":
            selected_playbook += (
                "    - name: Exercise the locked collection\n      fixture.example.probe:\n"
            )
        if mode == "failure":
            selected_playbook += '    - ansible.builtin.fail:\n        msg: "{{ private_value }}"\n      no_log: true\n'
        destination = (
            "/run/nexus-ansible-job/home/job-proof"
            if connection == "local"
            else "/home/fixture-target/job-proof"
        )
        payload = {
            "id": identity,
            "bundle": {
                "main": "main.yml",
                "files": {"main.yml": selected_playbook, "secrets.yml": encrypted},
                "variables": [],
            },
            "options": {
                "mode": mode if mode in ["syntax", "check", "apply"] else "apply",
                "tags": [],
                "skipTags": [],
                "verbosity": 0,
                "timeoutSeconds": 120,
            },
            "variables": {"expected_value": secret, "proof_dest": destination},
            "targets": [
                {
                    "serverId": "fixture-target",
                    "alias": alias,
                    "host": "127.0.0.1",
                    "port": 22,
                    "user": "fixture",
                    "privateKey": "fixture-only",
                    "knownHosts": "fixture-only",
                }
            ],
            "vaultPassword": password,
        }
        if mode == "collection":
            payload["bundle"]["collections"] = collection_locks
        if connection == "ssh":
            payload["targets"][0].update(ssh_target, port=2222)
        if mode == "unreachable":
            payload["targets"][0]["port"] = 1
        script = "CALLBACK=" + repr(callback) + "\nCOLLECTIONS=" + repr(collections) + "\n" + remote
        result = subprocess.run(
            docker
            + [
                "exec",
                "-i",
                "-e",
                "NEXUS_JOB_ID=" + identity,
                container,
                "/usr/bin/python3",
                "-I",
                "-c",
                script,
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=180,
        )
        if (
            secret in result.stdout + result.stderr
            or password in result.stdout + result.stderr
            or "Private task names" in result.stdout
        ):
            raise RuntimeError("Private content escaped recap boundary")
        expected = 2 if mode == "failure" else 4 if mode == "unreachable" else 0
        if result.returncode != (1 if expected else 0):
            print(
                subprocess.run(
                    docker + ["exec", container, "cat", "/tmp/fixture-sshd.log"],
                    capture_output=True,
                    text=True,
                ).stdout,
                flush=True,
            )
            raise RuntimeError(
                "Real playbook failed: "
                + mode
                + ": "
                + result.stdout[-1500:]
                + result.stderr[-1000:]
            )
        summary = json.loads(result.stdout)
        if summary["state"] != "playbook_exited" or summary["exitCode"] != expected:
            raise RuntimeError("Playbook did not complete")
        assert isinstance(summary["tasksTruncated"], bool) and not summary["tasksTruncated"]
        assert len(summary["tasks"]) <= 200
        for task in summary["tasks"]:
            assert set(task) == {"task", "serverId", "status", "startedMs", "durationMs"}, task
            assert task["serverId"] == "fixture-target" and task["task"] >= 1, task
            assert task["status"] in {
                "ok",
                "changed",
                "failed",
                "ignored",
                "unreachable",
                "skipped",
            }, task
            assert 0 <= task["startedMs"] <= 600000 and 0 <= task["durationMs"] <= 600000, task
        if mode != "syntax":
            assert summary["tasks"], "No task timing recorded"
            if mode == "failure":
                assert any(t["status"] == "failed" for t in summary["tasks"])
            if mode == "unreachable":
                assert any(t["status"] == "unreachable" for t in summary["tasks"])
            counts = summary["hosts"]["fixture-target"]
            if mode == "unreachable":
                assert counts["ok"] == 2 and counts["unreachable"] == 1, counts
            else:
                assert (
                    counts["ok"] == (4 if mode == "collection" else 3)
                    and counts["failures"] == (1 if mode == "failure" else 0)
                    and counts["changed"] == 1
                ), counts
        if connection == "ssh" and mode in ["check", "apply"]:
            verify = "from pathlib import Path;import sys,stat;p=Path('/home/fixture-target/job-proof');value=sys.stdin.read();assert (not p.exists()) if not value else (p.read_text()==value and stat.S_IMODE(p.stat().st_mode)==0o600)"
            subprocess.run(
                docker + ["exec", "-i", container, "/usr/bin/python3", "-I", "-c", verify],
                input=secret if mode == "apply" else "",
                check=True,
                capture_output=True,
                text=True,
            )
        cleanup = (
            "import pwd;from pathlib import Path;assert not Path('/run/nexus-ansible-job/home').exists();\ntry:pwd.getpwnam('nxa-"
            + identity[:20]
            + "')\nexcept KeyError:pass\nelse:raise AssertionError('account retained')\nimport shutil;shutil.rmtree('/run/nexus-ansible-job/trusted')"
        )
        subprocess.run(
            docker + ["exec", container, "/usr/bin/python3", "-I", "-c", cleanup],
            check=True,
            capture_output=True,
        )
        print(
            connection
            + " "
            + mode
            + ": real Ansible, separate UID, Vault-file decryption, bounded task timing/recap and cleanup passed.",
            flush=True,
        )
finally:
    if container:
        metadata = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[
            0
        ]
        if (
            metadata["Name"] != "/" + name
            or metadata["Config"]["Labels"].get("nexus.ansible.execution.lab") != nonce
            or any(m.get("Type") != "tmpfs" for m in metadata.get("Mounts", []))
        ):
            raise RuntimeError("Refusing cleanup without exact fixture ownership")
        subprocess.run(docker + ["rm", "-f", container], check=True, capture_output=True)
