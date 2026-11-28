# Contributing to Nexus

Use a focused branch from `main`, such as `feature/explorer-topology` or
`fix/backup-retention`. Keep commits small and describe the change plainly.
Run checks on the branch before opening a PR. Include the checks you ran,
any changes to permissions or persisted data, and screenshots for UI changes.

## Local setup

Install the Go version in [go.mod](nexus/go.mod), a C compiler, Node.js 22.20,
npm, Python 3, and Docker with Compose v2 for packaging tests.

```sh
make install
make check
make build
```

The Go service is in `nexus/`. The Vue app is in `nexus-vue/`. Integration
clients live in `integrations/` and disposable fixtures in `scripts/`.

## Browser and recovery tests

```sh
npm --prefix nexus-vue run browser:install
make browser
make recovery
```

Use `make scripts-check` to check formatting and syntax for fixture scripts.
Use disposable accounts and infrastructure for integrations. Keep production
credentials, data, logs, and private notes out of test artifacts and PRs.

See [support](SUPPORT.md) for ordinary issues and [security](SECURITY.md) for
private vulnerability reports.

## Capture the demo

Build a local Nexus Docker image from tracked source. Install the fixture
dependencies with `make install`, Playwright Chromium as above, and FFmpeg.
Then run:

```sh
make scripts-check
docs/validation/ci-tools/bin/python scripts/demo_capture.py nexus:local /tmp/nexus-demo-media
```

The script creates a disposable demo container and serves browser traffic through
a loopback fixture. It generates a new account and deletes the container and its
data after capture.
