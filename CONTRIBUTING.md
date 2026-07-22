# Contributing to Nexus

## Development Setup

1. Fork and clone the repo
2. Follow the [Build from Source](README.md#build-from-source) instructions
3. Create a branch: `git checkout -b your-feature`

## Project Structure

```
nexus/                          ← repo root
├── README.md
├── LICENSE
├── .gitignore
├── CONTRIBUTING.md
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── nexus/                      ← Go backend
│   ├── cmd/nexus/              ← entrypoint (main.go)
│   └── internal/
│       ├── api/                ← HTTP handlers and router (Chi)
│       ├── auth/               ← JWT and pending token management
│       ├── compose/            ← Docker Compose over SSH
│       ├── config/             ← env loading, password/TOTP management
│       ├── crypto/             ← AES-GCM encrypt/decrypt
│       ├── db/                 ← database setup
│       ├── docker/             ← Docker CLI client and log streaming
│       ├── filemanager/        ← SFTP operations
│       ├── metrics/            ← metrics collection and WebSocket stream
│       ├── models/             ← GORM models
│       ├── monitor/            ← server monitoring and Telegram bot
│       ├── proxy/              ← nginx/Caddy proxy management
│       ├── scheduler/          ← background task runner
│       ├── ssh/                ← SSH connection pool and TOFU
│       ├── static/             ← embedded frontend (dist goes here at build time)
│       ├── templates/          ← app marketplace
│       └── terminal/           ← SSH terminal WebSocket
└── nexus-vue/                  ← Vue 3 frontend
    └── src/
        ├── components/         ← UI components
        ├── composables/        ← Vue composables (useConfirm, etc.)
        ├── lib/                ← API client, auth, theme utilities
        ├── locales/            ← i18n translation files
        ├── router/             ← Vue Router
        ├── stores/             ← Pinia stores
        └── views/              ← page views
```

## Guidelines

- **Backend:** standard Go formatting (`gofmt`), no new external dependencies without discussion
- **Commits:** conventional commits preferred (`feat:`, `fix:`, `chore:`)
- Keep PRs focused — one feature or fix per PR

## Reporting Issues

Please include your Go version, browser, and steps to reproduce.