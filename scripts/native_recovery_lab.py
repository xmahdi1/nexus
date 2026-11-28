#!/usr/bin/env python3
"""Build and test the native CLI with owned temporary databases and keys.

No Docker, listeners, workers, deployment .env, or real credentials are used.
This does not replace image/old-image or remote integration acceptance.
"""

import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
env = {name: value for name, value in os.environ.items() if not name.startswith("NEXUS_")}
with tempfile.TemporaryDirectory(prefix="nexus-native-recovery-") as directory:
    binary = Path(directory) / "nexus"
    subprocess.run(
        ["go", "build", "-buildvcs=false", "-o", str(binary), "./cmd/nexus"],
        cwd=root / "nexus",
        env=env,
        check=True,
        timeout=180,
    )
    env["NEXUS_NATIVE_LAB_BINARY"] = str(binary)
    subprocess.run(
        [
            "go",
            "test",
            "-race",
            "./cmd/nexus",
            "-run",
            "^TestNativeCLILegacyUpgradeRotationAndRecovery$",
            "-count=1",
            "-v",
        ],
        cwd=root / "nexus",
        env=env,
        check=True,
        timeout=120,
    )
