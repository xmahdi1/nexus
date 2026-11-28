# Releasing Nexus

The Release workflow builds Linux AMD64 and ARM64 images on separate native
runners. Each runner downloads its image from a temporary loopback registry by
digest, checks the binary's metadata, runs startup and recovery tests, scans
the container, and records an SPDX SBOM. The workflow calculates the final
OCI index digest from those two tested image manifests.

## Validate a candidate

After the workflow is merged into `main`, dispatch a build:

```sh
gh workflow run release.yml --ref main -f version=0.1.0-rc.1 -f publish=false
```

The run summary lists the source commit and final OCI index digest. The build
uploads validation reports and the index. Local image archives are discarded.
Use `version=edge` for a development build. Edge metadata includes the
workflow run number.

## Configure first publication

In the Nexus repository, open **Settings → Environments** and create
`release`. Restrict it to `main` and set a required reviewer. Keep
administrator bypass disabled. If you both dispatch and approve as the sole
maintainer, allow self-review. Select an independent reviewer when available.

Generate a dedicated age encryption identity on your machine. Store its
contents in the release environment secret `NEXUS_RELEASE_AGE_IDENTITY`.
Set the corresponding public recipient as the repository Actions variable
`NEXUS_RELEASE_RECIPIENT`. Set the release environment variable
`NEXUS_RELEASE_ENABLED` to `enabled`.

The archive payloads are encrypted before transfer between Actions jobs.
During approval, inspect the archived reports and the digest in the run
summary. The publish job decrypts the payloads after approval. It uses the
repository workflow token to access GHCR.

## Publish an approved version

Confirm checks on the intended `main` commit. Create and push the matching
version tag once the release owner approves that version. Configure Git signing
before creating the tag.

```sh
git switch main
git pull --ff-only
git tag -s v0.1.0 -m 'Nexus 0.1.0'
git push origin refs/tags/v0.1.0
gh workflow run release.yml --ref main -f version=0.1.0 -f publish=true
```

The release workflow checks that the tag points at the dispatch commit.
Approve its environment deployment only after reviewing the digest. The job
imports the exact tested images, signs the OCI index, generates provenance,
and checks that the digest can be read anonymously before adding release tags.

An initial GHCR package may be private. If the publication run stops at the
public read check, review the staged digest and choose **Change visibility →
Public** in the Nexus package settings. Rerun the failed job in the same
workflow run, and review the approved digest again. The encrypted artifacts
expire after three days.

The GitHub release contains the signed digest, release notes, installer,
architecture SBOMs, provenance, and checksums. A release candidate uses
`v0.2.0-rc.1` and leaves stable image channels alone.

| Image reference | Meaning |
| --- | --- |
| `0.1.0` or `0.2.0-rc.1` | Exact image version. Publication rejects a different digest at the same tag. |
| `latest` or `0.1` | Latest published stable version overall or in the selected minor series. |
| `edge` | Latest approved development build. |
| `sha-<commit>` | First published image for a source commit. |
| `@sha256:<digest>` | Exact signed image. Use this for deployment and rollback. |

The application reports the installed version in **Settings** and through its
authenticated `/api/version` endpoint. Run `nexus version` on the command
line for the full commit, build date and platform.

## Install or upgrade from a release

Download `deploy.py` and `SHA256SUMS` from the approved GitHub release on a
Linux machine with Docker, Compose v2, Python 3 and Cosign. Verify the
installer checksum before running it.

```sh
sha256sum --ignore-missing --check SHA256SUMS
python3 deploy.py --release 0.1.0 --directory ./nexus
```

You can supply a release digest or choose `latest` or `edge` explicitly.
The installer resolves the reference to a digest and checks its Cosign
signature against the Nexus release workflow on `main` before running the
image. The generated Compose file uses the immutable digest.

Choose **Migrate** with a new directory to upgrade. The installer copies your
existing database and configuration, tests the migration with the original
key, and checks the new service's readiness. Keep the recovery copy and old
image or executable. If you roll back, stop the new service and use the old
image or executable with its matching database and configuration. Follow the
[deployment and recovery guide](DEPLOYMENT.md).
