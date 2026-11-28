#!/usr/bin/env python3
"""Parse tracked Python/YAML/shell inputs without creating bytecode or services."""

import ast
from pathlib import Path
import subprocess

import yaml

root = Path(__file__).resolve().parents[2]
paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
counts = {"python": 0, "yaml": 0, "shell": 0}
for name in paths:
    if not name:
        continue
    path = root / name
    if not path.is_file():
        continue
    if path.suffix == ".py":
        ast.parse(path.read_text(), filename=name)
        counts["python"] += 1
    elif path.suffix in {".yml", ".yaml"}:
        # BaseLoader keeps GitHub's `on` key a string under YAML 1.1 parsers.
        list(yaml.load_all(path.read_text(), Loader=yaml.BaseLoader))
        counts["yaml"] += 1
    elif path.suffix == ".sh":
        subprocess.run(["sh", "-n", str(path)], check=True)
        counts["shell"] += 1
print("Tracked script syntax passed:", counts)
