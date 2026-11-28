#!/usr/bin/env python3
"""Check repository-relative links and images in tracked Markdown files."""

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[2]
tracked = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0"))
directories = {parent for name in tracked if name for parent in Path(name).parents}
link = re.compile(r"\]\(<?([^\s)>]+)>?")
errors = []

for filename in sorted(tracked):
    if not filename.endswith(".md"):
        continue
    file = root / filename
    if not file.is_file():
        continue
    fenced = False
    for line_number, line in enumerate(file.read_text().splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        for target in link.findall(line):
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            path = (file.parent / unquote(url.path)).resolve()
            if not path.is_relative_to(root):
                errors.append(f"{filename}:{line_number}: link leaves the repository: {target}")
                continue
            relative = path.relative_to(root)
            if relative.as_posix() not in tracked and relative not in directories:
                errors.append(f"{filename}:{line_number}: missing tracked target: {target}")

if errors:
    raise SystemExit("\n".join(errors))
print("Tracked Markdown links passed")
