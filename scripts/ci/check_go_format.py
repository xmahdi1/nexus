#!/usr/bin/env python3
"""Read-only Go formatting validation. Prints filenames, never source or diffs."""

from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
files = subprocess.check_output(["git", "ls-files", "-z", "*.go"], cwd=root).decode().split("\0")
files = [path for path in files if path]
result = subprocess.run(
    ["gofmt", "-l", *files], cwd=root, text=True, capture_output=True, check=True
)
if result.stdout:
    print("Run gofmt on these tracked files:\n" + result.stdout, file=sys.stderr)
    sys.exit(1)
print(f"Go formatting passed ({len(files)} tracked files).")
