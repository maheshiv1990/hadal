# Hadal

Full-stack web app: **Rust (actix-web) + SolidJS + PostgreSQL**, served by **nginx**, run with **Docker Compose**.

```
browser ──► nginx :8000 ─┬─ /        → SolidJS static build (SPA fallback)
                         └─ /api/*   → backend:8080 (actix-web) ──► db:5432 (Postgres)
```

## Layout

| Path | What |
|------|------|
| `backend/` | actix-web API. sqlx (Postgres), migrations in `backend/migrations/` run automatically on startup |
| `frontend/` | SolidJS + Vite + TypeScript |
| `nginx/` | nginx config + Dockerfile that builds the frontend and serves it |
| `docker-compose.yml` | `db`, `backend`, `nginx` services |

## Run everything with Docker

```sh
cp .env.example .env      # then set POSTGRES_PASSWORD (openssl rand -hex 24)
docker compose up -d --build
open http://localhost:8000
```

## Local development (hot reload)

```sh
docker compose up -d db                 # Postgres only, on 127.0.0.1:5432
cd backend && cargo run                 # API on :8080 (reads ../.env via DATABASE_URL)
cd frontend && npm install && npm run dev   # Vite on :5173, proxies /api → :8080
```

`cargo run` loads a `.env` from the current directory, so either `cp ../.env .env` inside `backend/` or export `DATABASE_URL`.

## API

| Method | Path | |
|--------|------|-|
| GET | `/api/health` | liveness + DB check |
| GET | `/api/notes` | list (latest 100) |
| POST | `/api/notes` | `{ "title": "...", "body": "..." }` |
| GET | `/api/notes/{id}` | fetch one |
| DELETE | `/api/notes/{id}` | delete |

## Adding a migration

Add `backend/migrations/<timestamp>_<name>.sql`. It is embedded at compile time and applied on the next backend start.

## Tests

```sh
cd backend && cargo test
cd frontend && npm run build   # type-check + build
```

## CASA verification

Hadal must pass the App Defense Alliance CASA v2.1.1 assessment, and every change is checked against it.

```sh
scripts/install-hooks.sh        # once per clone
scripts/verify.sh quick         # CASA rules + register, fmt, clippy, tests, typecheck, secrets
scripts/verify.sh full          # + cargo-deny, cargo-audit, npm audit, build, semgrep, git-history secrets
python3 scripts/casa_check.py list-rules
```

- Requirement status for all 55 CASA items: [docs/casa/controls.md](docs/casa/controls.md), generated from [docs/casa/requirements.json](docs/casa/requirements.json).
- **pre-commit** runs the quick gate, then a Claude review of the staged diff. **pre-push** runs the full gate. **CI** runs the full gate plus an OWASP ZAP baseline. Release tags fail while any requirement is still `pending`.
- Exceptions and accepted risks: [docs/casa/exceptions.md](docs/casa/exceptions.md).
