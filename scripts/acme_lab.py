#!/usr/bin/env python3
"""Real DNS-01 using isolated Pebble; no public CA, host DNS or trust changes.
Requires the pinned fixture images already pulled locally. Owns and cleans only
its randomly named network/containers. Does not read a deployment .env.
"""

import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import urllib.request
import uuid

root = Path(__file__).resolve().parent.parent
docker = ["docker", "--host", "unix:///var/run/docker.sock"]
pebble = "ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef"
challenges = "ghcr.io/letsencrypt/pebble-challtestsrv@sha256:0152c8cb506e2ecba2900ed47d23932e27e3e6575a7d2c8ef93c7719ee3dea4c"
for image in [pebble, challenges]:
    subprocess.run(docker + ["image", "inspect", image], check=True, capture_output=True)
network = "nexus-acme-" + uuid.uuid4().hex
containers = []
subprocess.run(docker + ["network", "create", network], check=True, capture_output=True)
try:

    def start(image, options, arguments):
        container = subprocess.check_output(
            docker
            + [
                "run",
                "-d",
                "--rm",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--network",
                network,
                *options,
                image,
                *arguments,
            ],
            text=True,
        ).strip()
        containers.append(container)
        return container

    challenge = start(
        challenges,
        ["-p", "127.0.0.1::8055", "-p", "127.0.0.1::8053/udp", "-p", "127.0.0.1::8053/tcp"],
        ["-defaultIPv6", "", "-http01", "", "-https01", "", "-tlsalpn01", ""],
    )
    details = json.loads(subprocess.check_output(docker + ["inspect", challenge], text=True))[0]
    address = details["NetworkSettings"]["Networks"][network]["IPAddress"]
    server = start(
        pebble,
        ["-p", "127.0.0.1::14000", "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_AUTHZREUSE=0"],
        ["-config", "test/config/pebble-config.json", "-strict", "-dnsserver", address + ":8053"],
    )

    def port(container, port):
        return subprocess.check_output(docker + ["port", container, port], text=True).strip()

    with tempfile.TemporaryDirectory(prefix="nexus-acme-lab-") as directory:
        ca = Path(directory) / "pebble.pem"
        subprocess.run(
            docker + ["cp", server + ":/test/certs/pebble.minica.pem", str(ca)],
            check=True,
            capture_output=True,
        )
        url = "https://" + port(server, "14000/tcp") + "/dir"
        trust = ssl.create_default_context(cafile=str(ca))
        for _ in range(100):
            try:
                with urllib.request.urlopen(url, context=trust, timeout=1) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("ACME fixture did not become ready")
        env = {k: v for k, v in os.environ.items() if not k.startswith("NEXUS_")}
        env.update(
            NEXUS_ACME_LAB_DIRECTORY=url,
            NEXUS_ACME_LAB_MANAGEMENT="http://" + port(challenge, "8055/tcp"),
            NEXUS_ACME_LAB_DNS=port(challenge, "8053/udp"),
            NEXUS_ACME_LAB_CA=str(ca),
        )
        subprocess.run(
            [
                "go",
                "test",
                "-race",
                "./internal/proxy",
                "-run",
                "^TestDisposableACMEDNS01$",
                "-count=1",
                "-v",
            ],
            cwd=root / "nexus",
            env=env,
            check=True,
            timeout=180,
        )
finally:
    for container in reversed(containers):
        subprocess.run(
            docker + ["stop", "--time", "2", container], check=False, stdout=subprocess.DEVNULL
        )
    subprocess.run(docker + ["network", "rm", network], check=False, stdout=subprocess.DEVNULL)
