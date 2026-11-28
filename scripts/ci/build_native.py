#!/usr/bin/env python3
"""Build only generated outputs; never reads deployment configuration or starts workers."""

from pathlib import Path
import os
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]
source = root / "nexus-vue/dist"
target = root / "nexus/internal/static/dist"
if not (source / "index.html").is_file():
    raise SystemExit("Build the frontend first: npm --prefix nexus-vue run build")
if target.is_symlink():
    raise SystemExit("Refusing to replace a symlink at the generated frontend directory")
if target.exists():
    shutil.rmtree(target)
shutil.copytree(source, target)
env = {name: value for name, value in os.environ.items() if not name.startswith("NEXUS_")}
env["CGO_ENABLED"] = "1"
subprocess.run(
    ["go", "build", "-trimpath", "-tags", "production", "-o", "nexus", "./cmd/nexus"],
    cwd=root / "nexus",
    env=env,
    check=True,
)
print("Built nexus/nexus with the production frontend. No service started.")
