# Deploy Nexus

## Requirements

Use a Linux host with Git, Python 3, Docker Engine, and Compose v2 for the guided
installer. The Docker engine must be local because the installer uses bind
mounts. Keep persistent storage for the Nexus database and configuration. Managed
hosts must be reachable over SSH, with SFTP for file editing. Tools such as
Docker, nginx, and UFW need the matching host software and OS permissions.

## Guided install and migration

Run from the checkout:

```sh
python3 scripts/deploy.py
```

Choose **New**, pick an empty installation directory and a loopback port, and
confirm the plan. The generated `.env` contains the data key and password hash.
Keep it private. Nexus checks its local health endpoint after startup. Configure
a private TLS reverse proxy before signing in.

For **Migrate**, have the existing `.env`, database location, and old container
name or native executable ready. For a container, give the database path inside
that container. For a native installation, stop it and provide the database and
executable paths. Use a new target directory and an available loopback port.
The installer copies the database, preserves the existing key, and migrates the
copy. Keep the source installation stopped during and after cutover.

## Manual Compose install

You can run the repository Compose file from a clean checkout. The setup command below
requires the Go version in [go.mod](nexus/go.mod) and a C compiler for SQLite.

```sh
cp .env.example .env
cd nexus
go run ./cmd/nexus setup
cd ..
```

Put the generated values in the root `.env` and keep the bcrypt hash
single-quoted. Restrict host access to the file and configure file ownership
for the Nexus runtime UID/GID. Compose mounts this file into the container.

```sh
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 nexus
```

The Compose service exposes `127.0.0.1:8090`. The named volume holds
`/data/nexus.db` by default. Preserve the volume and `.env` for upgrades.
On a private TLS reverse proxy, set `NEXUS_TRUST_PROXY=true` only when the proxy
overwrites forwarded scheme and client IP headers. Preserve the incoming Host
and allow WebSocket upgrades. Keep the backend off untrusted networks. Use the guided installer to build from
tracked source when your working checkout contains private local files.

## First owner and additional accounts

At a fresh install, sign in with the configured administrator password and an
empty username. To transition to named accounts, take a rollback copy of the
database and configuration. Stop the service and run owner activation using
the same image, environment, and mounted data. For the repository Compose file:

```sh
docker compose stop nexus
docker compose run --rm --no-deps nexus owner-bootstrap --from-env owner
docker compose run --rm --no-deps nexus owner-activate owner
docker compose up -d
```

Sign in with the new owner username. Additional users join by invitation.
Enable MFA and store recovery codes separately from the data key.

## Recover or roll back

Before upgrading, record the current image ID or save the native executable.
Keep a consistent database snapshot with the matching configuration and key.
Back up remote application files, data volumes, and Vault data separately.

The guided migrator keeps a recovery set under `recovery/` in the target
directory. If the new installation fails, stop it. Restart the old installation
with its original data and configuration, or restore the compatible snapshot
before launching the previous executable. Starting old code against a migrated
database can fail or damage compatibility. Never run both controllers against
the same managed environment during cutover.

Check `/health/ready`, sign in, and verify your server list, grants, and backup
schedules after recovery. Exercise recovery on a disposable system before relying
on it. Keep recovery materials out of support tickets and source control.
