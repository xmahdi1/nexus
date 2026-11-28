#!/usr/bin/env python3
"""Print a tracked-only temporary source directory for local security scanners."""

from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
destination = Path(tempfile.mkdtemp(prefix="nexus-source-scan-")) / "source"
subprocess.run(
    [sys.executable, str(root / "scripts/ci/export_source.py"), str(destination)],
    check=True,
    stdout=subprocess.DEVNULL,
)
print(destination)
