# Hadal: CASA-gated project

Hadal (actix-web backend in `backend/`, SolidJS frontend in `frontend/`, nginx in
`nginx/`) will request restricted Google OAuth scopes, so it must pass the App Defense
Alliance **CASA v2.1.1** assessment. Every change must keep it assessable.

## The gate (non-negotiable)

- `scripts/verify.sh quick` must pass before you finish any task. A Claude Code Stop
  hook enforces this; a PostToolUse hook lints every file you edit.
- `.githooks/pre-commit` runs the quick gate plus a Claude review of the staged diff.
  `.githooks/pre-push` and CI run `scripts/verify.sh full`. Release tags run with
  `CASA_STRICT=1`, where any `pending` requirement fails.
- New clone: run `scripts/install-hooks.sh` once.
- Never bypass the gate (`--no-verify`, deleting rules or tests, loosening
  `deny.toml`) without the user's explicit approval, plus an entry in
  `docs/casa/exceptions.md`.

## Requirement register

`docs/casa/requirements.json` is the source of truth for all 55 CASA audit items.
`docs/casa/controls.md` is generated from it; never edit it by hand.
- When you implement a control, add the test, lint or tool that proves it to the
  item's `evidence` and set `status: verified`.
- If the gate says a `not_applicable` item now applies (its `reopen_if` matched),
  implement the control. Do not weaken the pattern to make it go away.
- After editing the register, run `python3 scripts/casa_check.py render`.

## Coding rules (each one is enforced by `scripts/casa_check.py list-rules`)

Backend (Rust):
- SQL is static text with `.bind()`; never `format!` or concatenate SQL (5.1.8).
- No `unwrap`/`expect`/`panic`/`println`/`dbg`/`unsafe` outside tests (Cargo.toml lints).
- Errors go through `AppError`: log the detail server-side and return a generic message (6.2.1).
- Request structs that derive `Deserialize` use `#[serde(deny_unknown_fields)]` (3.1.2).
- Never log passwords, tokens, cookies, `DATABASE_URL` or payment data (6.5.1).
- No OS commands, filesystem reads, Origin-based auth, wildcard CORS or raw redirects.
- Cookies: `.secure(true).http_only(true).same_site(..)` (2.3.x).
- Every route sits behind `security_headers()` and the rate limiter in `main.rs`.
- New dependencies: permissive licenses only (`deny.toml`), and no RUSTSEC advisories.
  Prefer turning off default features you don't use.

Frontend (SolidJS):
- No `innerHTML`/`dangerouslySetInnerHTML`/`eval`/`new Function` (5.1.3, 5.1.7).
- No `localStorage`/`sessionStorage`/`indexedDB`/`document.cookie` (6.6.1). Auth stays in HttpOnly cookies.
- No tokens or secrets in URLs (2.1.1). `target="_blank"` needs `rel="noopener noreferrer"`.

Auth (Google OAuth Authorization Code + PKCE, opaque server-side sessions) lives in
`backend/src/auth/`. Keep it that way:
- New API routes go inside a scope wrapped in `auth::require_session` and take
  `AuthUser`. Only `/api/health` and the sign-in/register endpoints are public (3.1.1).
- Every query on user data is scoped by `owner_id = user.user_id`; never trust an id or
  owner from the request (3.1.4, lint:notes-owner-scope). Return 404 for others' rows.
- Cookies only via `auth::cookies::SetCookie` (lint:set-cookie-outside-helper).
- Outbound HTTP only in `auth/google.rs`, to fixed Google endpoints (5.1.5, lint:outbound-http).
- Redirects only through `auth::redirect()` with a fixed target; `redirect_uri` stays in config.
- Password accounts live in `auth/password.rs`: Argon2id via `hash_password` /
  `verify_password` only, one "invalid email or password" error, no `Debug` on
  request types holding passwords. They stay separate from Google accounts. Any
  password change or reset must revoke the user's other sessions (2.2.2).
- Secrets in config use `config::Secret`. Don't store Google tokens without encryption.
- DB-backed tests use `test_support::{test_db, signed_in_user, test_app!}`; `verify.sh`
  starts the throwaway DB (`scripts/test-db.sh`).

## Suppressions

Use `// casa-allow: <rule-id> -- <justification>` only where the code is provably safe,
and record it in `docs/casa/exceptions.md`. The pre-commit Claude review audits each one.
