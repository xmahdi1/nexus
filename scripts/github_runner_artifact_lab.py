#!/usr/bin/env python3
"""Verify the exact runner archive and --version as this non-root user.

Downloads only the fixed public release, uses an owned temporary directory and
isolated environment, never registers a runner or reads deployment credentials.
"""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

if os.geteuid() == 0:
    raise RuntimeError("Run the artifact check as a non-root user")
root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "runner_artifact_fixture", root / "nexus/internal/githubrunner/run.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory(prefix="nexus-runner-artifact-") as directory:
    path = Path(directory)
    module.package(path)
    size = sum(p.lstat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())
    if size > 768 * 1024 * 1024:
        raise RuntimeError("Pinned archive exceeds the reviewed workspace package budget")
    result = subprocess.run(
        [str(path / "bin/Runner.Listener"), "--version"],
        cwd=path,
        env={"HOME": directory, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode or result.stdout.strip() != module.VERSION:
        raise RuntimeError("Pinned runner version/prerequisite check failed")
    print(
        "Pinned official runner archive checksum, safe extraction, size budget and non-root version probe passed: "
        + module.VERSION
    )
