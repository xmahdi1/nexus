#!/usr/bin/env python3
"""Export tracked source to a new directory without reading untracked private files.

Worktree mode includes tracked edits; --ref exports an immutable Git tree. A
release must use --ref plus its verified clean commit, never the worktree mode.
"""

import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("destination", type=Path)
parser.add_argument("--ref")
args = parser.parse_args()
destination = args.destination.resolve()
if destination == root or root in destination.parents:
    parser.error("use a new destination outside the checkout")
if destination.exists():
    parser.error("destination must not exist")
if args.ref:
    reference = subprocess.check_output(
        ["git", "rev-parse", "--verify", args.ref + "^{tree}"], cwd=root, text=True
    ).strip()
    files = (
        subprocess.check_output(["git", "ls-tree", "-r", "-z", "--name-only", reference], cwd=root)
        .decode()
        .split("\0")
    )
else:
    reference = None
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
destination.mkdir(mode=0o700)
exported = []
for name in files:
    if not name:
        continue
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit("unsafe tracked path")
    if (
        path.parts[0] in {".git", ".aws", ".codex", ".claude", ".agents", "deployment"}
        or (path.parts[0] == "docs" and path.parts[:2] != ("docs", "site"))
        or path.name in {"AGENTS.md", "CLAUDE.md", "SKILL.md", "docs.zip"}
        or (path.name.startswith(".env") and path.name != ".env.example")
    ):
        raise SystemExit("private path is tracked; refuse source export")
    source = root / name
    if source.is_symlink():
        raise SystemExit("source export requires explicit review of tracked symlinks")
    if not reference and not source.is_file():
        continue
    target = destination / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if reference:
        mode = subprocess.check_output(
            ["git", "ls-tree", reference, "--", name], cwd=root, text=True
        ).split()[0]
        if mode not in {"100644", "100755"}:
            raise SystemExit("unsupported tracked file mode")
        target.write_bytes(
            subprocess.check_output(["git", "show", reference + ":" + name], cwd=root)
        )
        target.chmod(0o755 if mode == "100755" else 0o644)
    else:
        shutil.copy2(source, target)
    exported.append(name)
print(json.dumps({"tree": reference, "files": len(exported), "destination": str(destination)}))
