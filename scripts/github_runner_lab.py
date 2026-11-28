#!/usr/bin/env python3
"""Exercise runner setup in an owned, network-isolated container with fake config/run programs.

No GitHub enrollment, host mounts, published ports, or host account changes.
Real systemd/cgroup/mount-namespace coverage is in supervision_lab.py --suite engine.
"""

import argparse
import json
from pathlib import Path
import re
import secrets
import subprocess
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--image", required=True, help="Already-local trusted Python 3.12+ image ID with useradd"
)
args = parser.parse_args()
if not re.fullmatch(r"(sha256:)?[a-f0-9]{12,64}", args.image):
    parser.error("Use an existing local image ID")
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
subprocess.run(docker + ["image", "inspect", args.image], check=True, capture_output=True)
identity = uuid.uuid4().hex
name = "nexus-runner-lab-" + identity
root = Path(__file__).resolve().parent.parent
source = (
    (root / "nexus/internal/githubrunner/run.py")
    .read_text()
    .split("if __name__ == '__main__':", 1)[0]
)
fixture = r'''
def fake_package(home):
    (home/'bin').mkdir(mode=0o700)
    config = """#!/usr/bin/python3
import os,sys
token=os.environ['ACTIONS_RUNNER_INPUT_TOKEN']
assert len(token)>=20 and all(token not in arg for arg in sys.argv)
assert os.geteuid()!=0 and os.getgroups()==[]
print(token)
print(token,file=sys.stderr)
"""
    run = """#!/usr/bin/python3
import os,sys
assert '--once' in sys.argv
assert sys.stdin.buffer.read()==b''
assert os.geteuid()!=0 and os.getgroups()==[]
assert not any(key.startswith('ACTIONS_RUNNER_INPUT_') or key in ['SSH_AUTH_SOCK','NEXUS_ENCRYPTION_KEY'] for key in os.environ)
"""
    for filename,body in [('config.sh',config),('run.sh',run),('bin/Runner.Listener','#!/bin/sh\nexit 0\n')]:
        p=home/filename
        p.write_text(body)
        p.chmod(0o700)
package=fake_package
result=main()
assert result==0
assert not (ROOT/'home').exists()
try:
    pwd.getpwnam('nxr-'+os.environ['NEXUS_JOB_ID'][:20])
except KeyError:
    pass
else:
    raise AssertionError('runner account retained after natural completion')
'''
token = secrets.token_hex(20)
payload = json.dumps(
    {
        "requestId": identity,
        "registrationToken": token,
        "url": "https://github.com/example/repository",
        "name": "fixture",
        "labels": ["trusted"],
        "group": "",
        "lifetimeSeconds": 900,
    }
)
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
            "nexus.runner.lab=" + identity,
            "--network",
            "none",
            "--pids-limit",
            "128",
            "--memory",
            "256m",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/run/nexus-runner:rw,exec,nosuid,nodev,size=32m,mode=0711",
            "-e",
            "NEXUS_JOB_ID=" + identity,
            args.image,
            "sleep",
            "120",
        ],
        text=True,
    ).strip()
    subprocess.run(
        docker + ["exec", container, "ln", "-s", "/usr/local/bin/python3", "/usr/bin/python3"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        docker + ["exec", container, "mkdir", "-p", "/run/nexus-jobs/" + identity],
        check=True,
        capture_output=True,
    )
    result = subprocess.run(
        docker + ["exec", "-i", container, "/usr/bin/python3", "-I", "-c", source + fixture],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if token in result.stdout + result.stderr:
        raise RuntimeError("registration token escaped adapter output suppression")
    if result.returncode:
        raise RuntimeError(
            "isolated runner fixture failed: " + result.stdout[-1000:] + result.stderr[-1000:]
        )
    print(
        "Runner fixture passed: separate UID/groups, token excluded from argv/job environment/saved output, temporary workspace/account cleanup; no GitHub calls."
    )
finally:
    if container:
        metadata = json.loads(subprocess.check_output(docker + ["inspect", container], text=True))[
            0
        ]
        if (
            metadata["Name"] != "/" + name
            or metadata["Config"]["Labels"].get("nexus.runner.lab") != identity
            or any(m.get("Type") != "tmpfs" for m in metadata.get("Mounts", []))
        ):
            raise RuntimeError("Refusing cleanup without exact ownership")
        subprocess.run(docker + ["rm", "-f", container], check=True, capture_output=True)
