#!/usr/bin/env python3
"""Validate repository Compose using a temporary fictional environment only."""

from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="nexus-compose-check-") as directory:
    fixture = Path(directory)
    (fixture / ".env").write_text(
        "NEXUS_PASSWORD_HASH=fixture-not-real\nNEXUS_ENCRYPTION_KEY=fixture-not-real\n"
    )
    subprocess.run(
        [
            "docker",
            "compose",
            "--project-directory",
            str(fixture),
            "-f",
            str(root / "docker-compose.yml"),
            "config",
            "--quiet",
        ],
        check=True,
    )
print("Compose configuration passed with fictional environment data.")
