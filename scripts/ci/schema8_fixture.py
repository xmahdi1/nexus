#!/usr/bin/env python3
"""Build an unpublished schema8 compatibility CLI from frozen migration code.

This is a format-compatibility fixture, not a claimed historical released binary.
It permits cold CI recovery tests without a maintainer's private image cache.
Keep testing genuine historical binaries separately when those are available.
The temporary copy has no server startup and never changes the working checkout.
"""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--tag", default="nexus:ci-schema8")
args = parser.parse_args()
if not re.fullmatch(r"nexus:ci-schema8(?:-[a-z0-9_.-]+)?", args.tag):
    parser.error("use an owned nexus:ci-schema8 fixture tag")
with tempfile.TemporaryDirectory(prefix="nexus-schema8-source-") as directory:
    source = Path(directory) / "source"
    subprocess.run(["python3", str(root / "scripts/ci/export_source.py"), str(source)], check=True)
    path = source / "nexus/internal/db/migrate.go"
    text = path.read_text()
    start = text.index("var schemaMigrations = []migration{") + len(
        "var schemaMigrations = []migration{"
    )
    end = text.index("\n}", start)
    entries = text[start:end].strip().splitlines()
    first = entries[:8]
    assert [int(re.match(r"\s*\{(\d+),", line).group(1)) for line in first] == list(range(1, 9))
    path.write_text(text[:start] + "\n" + "\n".join(first) + text[end:])
    path = source / "nexus/internal/db/db.go"
    text, removed = re.subn(r"(?m)^\tsteps\[(?:8|9|35)\]\.Up = .*\n", "", path.read_text())
    assert removed == 3, "review fixture construction after changing migration setup"
    # db.go no longer directly uses these newer key-bound migrations.
    text = text.replace('\n\t"github.com/xmahdi1/nexus/internal/db/migrations"', "")
    path.write_text(text)
    (
        source / "Dockerfile.schema8"
    ).write_text("""FROM golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY nexus/ .
COPY integrations/ansible/environment.py integrations/ansible/requirements.lock /integrations/ansible/
RUN CGO_ENABLED=1 go build -buildvcs=false -o /fixture ./cmd/nexus
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=build /fixture /fixture
ENTRYPOINT ["/fixture"]
""")
    subprocess.run(
        [
            "docker",
            "--host",
            "unix:///var/run/docker.sock",
            "build",
            "-f",
            str(source / "Dockerfile.schema8"),
            "-t",
            args.tag,
            str(source),
        ],
        check=True,
    )
print(
    "Built unpublished schema8 compatibility CLI; use its immutable local image ID for recovery tests."
)
