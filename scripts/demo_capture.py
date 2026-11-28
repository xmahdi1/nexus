#!/usr/bin/env python3
"""Capture the real Nexus UI using a disposable, local Docker image."""

import argparse
import base64
from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import secrets
import subprocess
from threading import Thread
import time
from urllib.parse import urlsplit

import bcrypt

ROOT = Path(__file__).resolve().parents[1]
READ_PATHS = {
    "/",
    "/login",
    "/dashboard",
    "/servers",
    "/services",
    "/favicon.ico",
    "/logo.svg",
    "/icons/icon.png",
    "/api/auth/permissions",
    "/api/auth/me",
    "/api/features",
    "/api/servers",
    "/api/monitor/status",
    "/api/services",
}
SEED = """
import sqlite3
with sqlite3.connect('/data/nexus.db') as db:
    db.executemany(
        "INSERT INTO servers(id,name,host,port,username,tags) VALUES(?,?,?,?,?,?)",
        [
            ('edge', 'Edge gateway', '127.0.0.1', 8080, 'fixture', 'edge,production'),
            ('build', 'Build host', '127.0.0.1', 8080, 'fixture', 'ci,staging'),
            ('archive', 'Archive node', '192.0.2.31', 22, 'fixture', 'storage'),
        ],
    )
    db.executemany(
        "INSERT INTO services(id,name,url,description,category,sort_order) VALUES(?,?,?,?,?,?)",
        [
            ('grafana', 'Grafana', 'https://metrics.example.test', 'Host metrics and alerts', 'Operations', 1),
            ('registry', 'Container registry', 'https://registry.example.test', 'Build artifacts', 'Development', 2),
            ('backups', 'Backup reports', 'https://backup.example.test', 'Nightly backup status', 'Operations', 3),
        ],
    )
    db.execute("INSERT INTO roles(id,name) VALUES('demo-services','Demo services')")
    db.execute("INSERT INTO role_permissions(role_id,permission_key) VALUES('demo-services','services.read')")
    db.execute(
        "INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) "
        "SELECT 'demo-services',id,'user','demo-services','global','','demo-fixture',CURRENT_TIMESTAMP "
        "FROM users WHERE username='demo'"
    )
    db.execute(
        "INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) "
        "SELECT 'demo-monitor-' || id,'system-monitor','service','collector','server',id,'demo-fixture',CURRENT_TIMESTAMP FROM servers"
    )
"""


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, text=True, **kwargs)


def forward_to(host, port, origin):
    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            self.forward()

        def do_POST(self):
            self.forward()

        def forward(self):
            path = urlsplit(self.path).path
            if self.headers.get("Host") != origin or (
                self.headers.get("Origin", f"http://{origin}") != f"http://{origin}"
            ):
                self.send_error(403)
                return
            read = path in READ_PATHS or re.fullmatch(r"/assets/[A-Za-z0-9_.-]+", path)
            login = self.command == "POST" and path == "/api/auth/login"
            if not login and (self.command != "GET" or not read):
                self.send_error(403)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= size <= 4096 or self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            headers = {
                "Host": origin,
                "X-Forwarded-Proto": "https",
                "X-Forwarded-For": "127.0.0.1",
                "Origin": f"https://{origin}",
            }
            for name in ("Cookie", "Content-Type"):
                if name in self.headers:
                    headers[name] = self.headers[name]
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request(self.command, path, self.rfile.read(size) if size else None, headers)
                result = conn.getresponse()
                data = result.read()
                self.send_response(result.status)
                for name, value in result.getheaders():
                    if name.lower() in {"content-type", "set-cookie", "cache-control"}:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (OSError, http.client.HTTPException):
                self.send_error(502)
            finally:
                conn.close()

        def log_message(self, *_args):
            pass

    return Proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="already built local Nexus image")
    parser.add_argument("output", type=Path, help="directory for PNG and GIF output")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    image = docker(
        "image", "inspect", "--format", "{{.Id}}", args.image, capture_output=True
    ).stdout.strip()
    name = f"nexus-demo-{secrets.token_hex(5)}"
    password = secrets.token_urlsafe(24)
    config = {
        "NEXUS_PASSWORD_HASH": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        "NEXUS_ENCRYPTION_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "NEXUS_TRUST_PROXY": "true",
        "NEXUS_TOTP_ENABLED": "false",
        "NEXUS_PORT": "8080",
    }
    env = {**os.environ, **config}
    config_args = [argument for key in config for argument in ("--env", key)]
    with ExitStack() as cleanup:
        docker("network", "create", "--internal", name, stdout=subprocess.DEVNULL)
        cleanup.callback(docker, "network", "rm", name, stdout=subprocess.DEVNULL)
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            name,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "100",
            "--cpus",
            "1",
            "--memory",
            "256m",
            "--tmpfs",
            "/data:rw,noexec,nosuid,size=64m,uid=1000,gid=1000,mode=0700",
            *config_args,
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            "sleep infinity",
            env=env,
            stdout=subprocess.DEVNULL,
        )
        cleanup.callback(docker, "rm", "-f", name, stdout=subprocess.DEVNULL)
        commands = (
            ("db-migrate", "/data/nexus.db"),
            ("owner-bootstrap", "--from-env", "--display-name", "Demo operator", "demo"),
            ("owner-activate", "demo"),
        )
        for command in commands:
            docker("exec", name, "./nexus", *command, stdout=subprocess.DEVNULL)
        docker("exec", "-i", name, "python3", "-", input=SEED)
        docker("exec", "-d", name, "./nexus")
        host = docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
            capture_output=True,
        ).stdout.strip()
        for _ in range(50):
            conn = http.client.HTTPConnection(host, 8080, timeout=0.5)
            try:
                conn.request("GET", "/health/ready")
                if conn.getresponse().status == 200:
                    break
            except OSError:
                pass
            finally:
                conn.close()
            time.sleep(0.2)
        else:
            raise RuntimeError("Nexus demo did not become ready")
        proxy = cleanup.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler))
        origin = f"127.0.0.1:{proxy.server_port}"
        proxy.RequestHandlerClass = forward_to(host, 8080, origin)
        thread = Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        cleanup.callback(proxy.shutdown)
        subprocess.run(
            ["node", str(ROOT / "scripts/demo_capture.mjs"), str(output)],
            check=True,
            env={**os.environ, "NEXUS_LAB_URL": f"http://{origin}", "NEXUS_LAB_PASSWORD": password},
        )


if __name__ == "__main__":
    main()
