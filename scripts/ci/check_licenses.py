#!/usr/bin/env python3
"""Inventory declared dependency licenses and fail on unreviewed expressions.

This checks dependency policy, not legal certification. Build-only MPL/CC-BY
packages remain identified separately; their notices must accompany redistribution.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=root / "docs/validation/ci/licenses.json")
args = parser.parse_args()
permissive = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "CC0-1.0",
    "BlueOak-1.0.0",
    "Unlicense",
}
build_only = {"MPL-2.0", "CC-BY-4.0"}
records = []
failures = []


def allowed(expression, dev):
    # Conservative supported SPDX subset. Unknown operators/exceptions or
    # identifiers require review rather than guessing compatibility.
    words = re.findall(r"[A-Za-z0-9.+-]+", expression)
    permitted = permissive | (build_only if dev else set())
    return bool(words) and all(word in permitted or word in {"AND", "OR"} for word in words)


folder = root / "nexus-vue"
lock = json.loads((folder / "package-lock.json").read_text())
for name, item in lock["packages"].items():
    if not name:
        continue
    manifest = folder / name / "package.json"
    if not manifest.is_file():
        continue  # Optional packages for other platforms are checked there.
    data = json.loads(manifest.read_text())
    license_id = data.get("license", "")
    if isinstance(license_id, dict):
        license_id = license_id.get("type", "")
    if not license_id and data.get("licenses"):
        license_id = " OR ".join(license["type"] for license in data["licenses"])
    dev = bool(item.get("dev"))
    record = {
        "ecosystem": "npm",
        "name": data["name"],
        "version": data["version"],
        "license": license_id,
        "buildOnly": dev,
    }
    records.append(record)
    if not allowed(license_id, dev):
        failures.append(record)

modules_text = subprocess.check_output(
    ["go", "list", "-m", "-json", "all"], cwd=root / "nexus", text=True
)
decoder = json.JSONDecoder()
while modules_text.strip():
    modules_text = modules_text.lstrip()
    module, consumed = decoder.raw_decode(modules_text)
    modules_text = modules_text[consumed:]
    if module.get("Main"):
        continue
    directory = module.get("Dir")
    if not directory and module.get("Version"):
        downloaded = json.loads(
            subprocess.check_output(
                ["go", "mod", "download", "-json", module["Path"] + "@" + module["Version"]],
                cwd=root / "nexus",
                text=True,
            )
        )
        directory = downloaded.get("Dir")
    license_id = ""
    if directory:
        candidates = [
            p
            for p in Path(directory).iterdir()
            if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING"))
        ]
        for path in candidates:
            text = " ".join(path.read_text(errors="replace").split())
            if "Permission is hereby granted, free of charge" in text:
                license_id = "MIT"
            elif "Apache License" in text and "Version 2.0" in text:
                license_id = "Apache-2.0"
            elif "Redistribution and use in source and binary forms" in text:
                license_id = "BSD-3-Clause" if "endorse or promote" in text else "BSD-2-Clause"
            elif "ISC License" in text:
                license_id = "ISC"
            if license_id:
                break
    record = {
        "ecosystem": "go",
        "name": module["Path"],
        "version": module.get("Version", ""),
        "license": license_id,
        "buildOnly": False,
    }
    records.append(record)
    if license_id not in permissive:
        failures.append(record)

args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(
    json.dumps(
        {
            "dependencies": records,
            "unreviewed": failures,
            "scope": "installed npm platform; Go module licenses; OCI OS and asset notices require separate inventory",
        },
        indent=2,
    )
    + "\n"
)
if failures:
    for record in failures:
        print(
            "Unreviewed dependency license:",
            record["name"],
            record["version"],
            record["license"] or "UNKNOWN",
        )
    raise SystemExit(1)
print(
    f"License inventory/policy passed for {len(records)} dependency records. This is not a legal audit."
)
