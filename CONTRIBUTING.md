# Contributing to DockPanel

Thanks for your interest in contributing! This guide covers development setup, code style, and the PR process.

## Development Setup

### Prerequisites

- **Go 1.26+**: https://go.dev/dl/ (any Go ≥ 1.21 works too: `GOTOOLCHAIN=auto` fetches the pinned toolchain from `panel/go/go.mod`)
- **Node.js 20+**: For building the frontend
- **Docker**: For running PostgreSQL locally

### Getting Started

```bash
git clone https://github.com/ovexro/dockpanel.git
cd dockpanel

# Enable the repo's git hooks (secrets scan, version consistency,
# npm audit + govulncheck). See scripts/hooks/README.md.
git config core.hooksPath scripts/hooks

# Start PostgreSQL
docker run -d --name dockpanel-postgres \
  -e POSTGRES_USER=dockpanel \
  -e POSTGRES_PASSWORD=dockpanel \
  -e POSTGRES_DB=dockpanel \
  -p 5450:5432 postgres:16

# Create config
sudo mkdir -p /etc/dockpanel
cat <<EOF | sudo tee /etc/dockpanel/api.env
DATABASE_URL=postgresql://dockpanel:dockpanel@127.0.0.1:5450/dockpanel
JWT_SECRET=$(openssl rand -hex 32)
AGENT_SOCKET=/var/run/dockpanel/agent.sock
AGENT_TOKEN=$(uuidgen)
LISTEN_ADDR=127.0.0.1:3080
EOF

# Build everything (API, agent, CLI, MCP server — all Go, in panel/go)
bash scripts/build-go.sh panel/go/bin
cd panel/frontend && npm install && npx vite build && cd ../..

# Run (agent needs root for system operations)
sudo ./panel/go/bin/dockpanel-agent &
./panel/go/bin/dockpanel-api &
cd panel/frontend && npm run dev
```

The frontend dev server proxies `/api` to `127.0.0.1:3080` (see `panel/frontend/vite.config.ts`).

## Architecture

```
panel/
├── go/          # Go module: every shipped binary
│   ├── cmd/                     # dockpanel-api, dockpanel-agent, dockpanel (CLI), dockpanel-mcp
│   ├── internal/agent/          # host-level operations (Docker, Nginx, SSL, terminal)
│   │   ├── routes/              # HTTP endpoint handlers (43 files)
│   │   ├── services/            # Business logic (42 files)
│   │   └── safecmd/             # the only way the agent spawns processes
│   ├── internal/api/            # API server, auth, DB, multi-server dispatch
│   │   ├── rt_*.go              # REST endpoints (61 files)
│   │   ├── svc_*.go             # Background tasks and shared logic (44 files)
│   │   └── migrations/          # SQL migrations (140 files)
│   ├── internal/cli/            # CLI tool (Cobra)
│   └── internal/mcp/            # read-only MCP server
└── frontend/    # React 19 + TypeScript + Tailwind 4
    └── src/pages/      # Lazy-loaded page components (52 files)
```

**Agent** handles host-level operations: Docker, Nginx config, SSL certificates, file system, terminal (PTY), backups. Runs as root. Communicates via Unix socket (local) or HTTPS (remote servers).

**Backend** handles coordination: auth (JWT + 2FA), PostgreSQL persistence, multi-server agent dispatch, background services (alerts, monitoring, auto-healing, scheduled backups/deploys). Runs as unprivileged user.

**Frontend** is a React SPA with lazy-loaded pages. Each major feature maps to a page file in `src/pages/`.

## Code Style

- **Go**: `gofmt` and `go vet` must be clean (CI enforces both). Read `panel/go/internal/agent/PORTING.md` and `panel/go/internal/api/PORTING.md` for the package layout and naming rules.
- **TypeScript**: Strict mode enabled. Minimize `as any` casts. No `console.log` in production code (use `logger.ts`).
- **SQL migrations**: Use `IF NOT EXISTS` / `IF EXISTS` where possible. Timestamp prefix format: `YYYYMMDDHHMMSS_description.sql`.

## Making Changes

1. **Fork and branch**: Create a feature branch from `main`.
2. **Read before editing**: Understand existing code before modifying. Check `FEATURES.md` for the feature manifest.
3. **Keep it focused**: One feature or fix per PR. Don't bundle unrelated changes.
4. **Build and test everything**: `cd panel/go && go vet ./... && go test ./...` (set `DATABASE_URL` to run the DB-backed API tests).
5. **Test manually**: Run the panel locally and verify your changes work end-to-end.

## Pull Request Process

1. Describe what the PR does and why.
2. List any new environment variables, migrations, or dependencies.
3. Confirm you've built and tested locally.
4. Keep PRs reasonably sized — large PRs are harder to review.

## Filing Issues

- **Bug reports**: Include OS, DockPanel version, steps to reproduce, and relevant logs (`journalctl -u dockpanel-api -n 50`).
- **Feature requests**: Describe the use case, not just the solution.

## Key Files

| What | Where |
|------|-------|
| Feature manifest | `FEATURES.md` |
| API config | `panel/backend/src/config.rs` |
| Agent startup | `panel/agent/src/main.rs` |
| API startup | `panel/backend/src/main.rs` |
| DB schema | `panel/backend/migrations/` |
| Frontend routes | `panel/frontend/src/main.tsx` |
