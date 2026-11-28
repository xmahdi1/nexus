#!/usr/bin/env python3
"""Real systemd/cgroup supervision in a disposable QEMU guest.

QEMU uses software emulation in an unprivileged, cap-drop container: no host
cgroups, KVM, privileged mode, host network, Docker socket or filesystem mounts.
Only a random loopback SSH port is published. All guest state is disposable.
"""

import os
import argparse
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--guest", choices=["debian12", "ubuntu24"], default="debian12")
parser.add_argument(
    "--suite", choices=["all", "engine", "scheduler", "operations", "inventory"], default="all"
)
args = parser.parse_args()
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
image = "nexus:disposable-supervision-lab-" + args.guest
build = docker + ["build", "-t", image]
if args.guest == "ubuntu24":
    build += [
        "--build-arg",
        "GUEST_IMAGE=ubuntu:24.04",
        "--build-arg",
        "KERNEL_PACKAGE=linux-image-virtual",
    ]
subprocess.run(build + [str(root / "scripts/supervision_lab")], check=True)
with tempfile.TemporaryDirectory(prefix="nexus-supervision-lab-") as directory:
    private_key = Path(directory) / "client"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)], check=True
    )
    payload = Path(directory) / "public"
    payload.mkdir(mode=0o755)
    (payload / "client.pub").write_bytes(private_key.with_suffix(".pub").read_bytes())
    nonce = uuid.uuid4().hex
    (payload / "nonce").write_text(nonce)
    container = subprocess.check_output(
        docker
        + [
            "create",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "768m",
            "-p",
            "127.0.0.1::2222",
            image,
        ],
        text=True,
    ).strip()
    try:
        subprocess.run(
            docker + ["cp", str(payload), container + ":/fixture"], check=True, capture_output=True
        )
        subprocess.run(docker + ["start", container], check=True, capture_output=True)
        public = ""
        for _ in range(120):
            result = subprocess.run(
                docker + ["exec", container, "cat", "/guest/etc/ssh/ssh_host_ed25519_key.pub"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                public = result.stdout
                break
            time.sleep(0.1)
        published = subprocess.run(
            docker + ["port", container, "2222/tcp"], capture_output=True, text=True
        )
        if published.returncode:
            subprocess.run(docker + ["logs", "--tail", "70", container], check=False)
            raise RuntimeError("Disposable guest container exited before SSH was published")
        address = published.stdout.strip()
        host, port = address.rsplit(":", 1)
        ready = False
        for _ in range(240):
            try:
                with socket.create_connection((host, int(port)), timeout=1) as connection:
                    connection.settimeout(1)
                    if connection.recv(128).startswith(b"SSH-"):
                        ready = True
                        break
            except OSError:
                pass
            time.sleep(0.25)
        if not ready or not public:
            subprocess.run(docker + ["logs", "--tail", "70", container], check=False)
            raise RuntimeError("Disposable systemd guest SSH did not become ready")
        env = {key: value for key, value in os.environ.items() if not key.startswith("NEXUS_")}
        env.update(
            NEXUS_SUPERVISION_SSH=address,
            NEXUS_SUPERVISION_KEY=str(private_key),
            NEXUS_SUPERVISION_HOST_KEY=public,
            NEXUS_SUPERVISION_NONCE=nonce,
        )
        suites = [
            ("engine", "./internal/jobsupervisor", "^TestDisposableSystemdSupervisor$", 240),
            ("scheduler", "./internal/scheduler", "^TestSupervisedVM", 180),
            ("operations", "./internal/operations", "^TestInteractiveVM", 120),
            ("inventory", "./internal/inventory", "^TestInventoryVM", 90),
        ]
        for name, package, pattern, timeout in suites:
            if args.suite in ["all", name]:
                subprocess.run(
                    ["go", "test", "-race", package, "-run", pattern, "-count=1", "-v"],
                    cwd=root / "nexus",
                    env=env,
                    check=True,
                    timeout=timeout,
                )
    finally:
        subprocess.run(docker + ["rm", "-f", container], check=False, stdout=subprocess.DEVNULL)
