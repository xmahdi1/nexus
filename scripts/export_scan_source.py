#!/usr/bin/env python3
"""Export Git-visible source only, excluding ignored runtime/private files.
Prints a temporary directory suitable for `gitleaks dir --redact DIRECTORY`.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
root=Path(__file__).resolve().parent.parent
export=Path(tempfile.mkdtemp(prefix='nexus-source-scan-'))
files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
for name in files:
    if not name:continue
    parts=Path(name).parts
    if any(part in {'.aws','.codex','.claude','.agents','.git','.idea','node_modules','dist','docs'} for part in parts):continue
    if any(part.startswith('.env') and part!='.env.example' for part in parts):continue
    source=root/name
    if source.is_file() and not source.is_symlink():
        target=export/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
print(export)
