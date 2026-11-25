# CASA exceptions and accepted risks

Every suppression (`casa-allow`), dependency-policy change (`backend/deny.toml`),
scanner ignore, or known limitation of the gate is recorded here with a reason.
The pre-commit Claude review rejects suppressions that aren't justified here.

## Active suppressions

`casa-allow`:

| Location | Rule | Why it is safe |
| --- | --- | --- |
| `backend/src/auth/mod.rs`, `redirect()` (`Location` header) | `open-redirect` | The only redirect helper. Its target is a closed enum: Google's authorization endpoint (an `AuthorizeUrl`, which only `GoogleClient::authorize_url` can construct from a constant base URL), `/`, or `/?login=failed`. No part of the request picks the target. |
| `backend/src/auth/mod.rs`, `CallbackParams` | `permissive-deserialize` | Google's redirect adds query params we don't use (`scope`, `authuser`, `prompt`, `hd`), so unknown fields must be tolerated. The struct is read-only input to the sign-in check and is never persisted, so mass assignment can't happen. Duplicate params are still rejected. |

Scanner ignores:

| Location | Scanner | Reason |
| --- | --- | --- |
| `scripts/test_casa_check.py` (`hardcoded-secret` self-test case) | gitleaks (`# gitleaks:allow`) | The value `GOCSPX-abcdefgh123` is a fake sample that proves the `hardcoded-secret` rule fires. It is not a real credential and is never used at runtime. |
| `backend/src/auth/testdata/push_signer.pk8` | none needed (binary DER, not PEM) | A 2048-bit RSA key generated for the tests only. It stands in for Google's signing key so the push-token checks are tested with real RS256 signatures. It is loaded with `include_bytes!` inside `#[cfg(test)]` only, signs nothing outside the tests, and its public half is never trusted by the running app, which only accepts keys fetched from Google. |

## Dependency policy (`backend/deny.toml`)

| Decision | Reason |
| --- | --- |
| Licenses allow-list: MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0 | Permissive only. Copyleft is rejected. |
| `licenses.private.ignore = true` | Our own crate is `publish = false` and proprietary. |
| actix-web built with `default-features = false, features = ["macros"]` | Drops `cookie 0.16` (RUSTSEC-2026-0594) and `h2 0.3` (RUSTSEC-2026-0258). HTTP/2 belongs at the TLS-terminating proxy. |
| `chrono` replaced by `time` | RUSTSEC-2026-0543 (chrono unmaintained). |
| `reqwest` with `default-features = false, features = ["rustls-no-provider", "json", "form"]` | Only for calls to Google's fixed endpoints in `auth/google.rs`: code exchange, token refresh and revocation, and the read-only Gmail API. Default features would add aws-lc-rs, HTTP/2 and system proxy support, none of which we need. TLS is a rustls `ClientConfig` on the `ring` provider (already used by sqlx) with `webpki-roots`. |
| `ring` as a direct dependency (`default-features = false, features = ["alloc"]`) | AES-256-GCM for refresh tokens and imported mail (`backend/src/crypto.rs`). Already in the tree as the rustls crypto provider, so it adds no new crate. ISC/Apache-2.0-style license. |
| `webpki-roots` (CDLA-Permissive-2.0) | Mozilla's CA set, compiled in, so the container's trust store can't weaken verification of Google's certificate. |
| `argon2` 0.6 with `default-features = false, features = ["alloc", "password-hash", "zeroize"]` | RustCrypto, MIT/Apache-2.0. Salts come from the `getrandom` 0.3 we already use, so the crate's own `getrandom` feature is off. |
| No advisory ignores | `[advisories] ignore = []`; keep it that way. |

## Architecture notes the assessor will ask about

- **Rate-limit keying behind nginx.** The backend trusts `X-Real-IP` only when
  `TRUST_PROXY_HEADERS=true`. That is set in docker-compose, where the backend
  publishes no port and is reachable only through nginx, which overwrites the
  header. Publishing port 8080 directly while this is true would let clients
  spoof their IP to dodge the limit. Tests cover both modes.
- **TLS layout.** Browser to nginx: TLS 1.2/1.3 (4.1.1). Backend to Postgres:
  TLS with `sslmode=verify-full` against a private CA whose key is discarded
  after signing (4.1.2). nginx to backend is plain HTTP on the private compose
  network: it never leaves the host and the backend port isn't published. Put
  it on TLS too if the two ever run on different machines.
- **Production certificates: Let's Encrypt.** hadalspace.com and
  www.hadalspace.com share one certificate (HTTP-01 webroot), renewed by the
  certbot service within 30 days of expiry; nginx reloads every 6 hours.
  Port 80 serves only `/.well-known/acme-challenge/` and the HTTPS redirect.
  HSTS uses `includeSubDomains`, so every *.hadalspace.com host must serve
  HTTPS.
- **HSTS is 5 minutes in local compose.** Browsers apply HSTS to every port of
  `localhost`, so a 2-year value would force HTTPS on unrelated local dev
  servers. The image default (production) is 2 years; `HSTS_MAX_AGE` overrides.
- **ID token signature is not checked (OIDC Core 1.0 §3.1.3.7, step 6).** The
  backend receives the ID token directly from Google's token endpoint, over a
  TLS connection it opened and verified, in exchange for a single-use code bound
  to a PKCE verifier. The spec allows TLS server validation in place of the JWS
  signature in that case. Every claim is still validated (iss, aud/azp, exp, iat,
  nonce, email_verified). If ID tokens are ever accepted from any other source
  (the browser, another service), signature verification against Google's JWKS
  becomes mandatory. That is the case for Gmail push (next item), which does
  verify signatures.
- **`POST /api/gmail/push` has no session (Gmail push, off unless
  `GMAIL_PUSH_*` is set).** Google's Cloud Pub/Sub calls it, so a session
  can't protect it. A Google-signed token does: RS256 only (`none` and HMAC
  are refused), checked with `ring` against Google's published keys
  (fetched from a fixed URL, cached for an hour, refetched for an unknown
  key ID at most once a minute), with `iss` Google, `aud` our exact push URL,
  `email` our subscription's service account and verified, and `exp`/`iat`
  current. Any failure is a 401 and the body isn't read. A valid notification
  only names a Gmail address; the lookup by that address
  (`mail::watched_mailboxes`) is the one mail query not keyed by a signed-in
  user, and it returns rows with their stored owner, which scopes everything
  after it. The notification's history ID is ignored: each sync reads from
  the point it stored. Replaying a genuine notification only triggers a
  sync that finds nothing new. Rate limiting is the global per-IP limit;
  Pub/Sub retries a 429 with backoff.
- **Push sync runs without a request.** Watches are only kept for users who
  signed in within `GMAIL_PUSH_ACTIVE_DAYS` (default 7): mail isn't pulled
  in for people who stopped using Hadal, and their watches are stopped at
  Google. One Gmail address linked by two Hadal users is synced separately
  for each, and its watch is only stopped when neither still wants it.
  Messages trashed in Gmail are deleted from Hadal at the next sync.
- **Live updates (`GET /api/mail/events`, Server-Sent Events).** Inside the
  session scope. An event carries only the changed mailbox's ID; the page
  reloads its data through the usual owner-scoped endpoints. Each stream
  re-checks its session every 20 s *without* sliding the idle window, so an
  open tab neither keeps a session alive nor outlives a logout. At most 5
  streams per user (one more ends that user's oldest, so reloading a page
  never locks its owner out) and 2,000 in all (then 429).
- **Google tokens are not stored.** Sign-in requests only `openid email profile`
  (non-sensitive: the name is stored as first/last name, nothing else), and
  Google's access and refresh tokens are dropped after the exchange. When
  restricted scopes are added, their tokens need encrypted storage and revocation
  on logout (reopen 2.2.1, 6.7.1).
- **The auth migration deleted existing notes.** Notes created before sign-in
  existed had no owner and were readable by everyone, so
  `20261124000000_auth.sql` removes them instead of assigning them to a user.
  The notes feature was later removed entirely, and
  `20261127000000_drop_notes.sql` drops the table.
- **Sign-in state lives in the database.** `/api/auth/login` writes one
  `oauth_logins` row per attempt (10-minute expiry, purged every 5 minutes) and
  is limited to 10 per minute per IP.
- **Email + password accounts are separate from Google accounts.** Registration
  emails are not verified, so linking accounts by address would let anyone
  take over a Google user's mail by registering their address first. A
  password account and a Google account with the same email are different
  users (`password_and_google_accounts_stay_separate`).
- **Registration says when an email is taken.** `POST /api/auth/register`
  returns 409 for an address that already has a password account, which tells
  a caller the account exists. Hiding it needs email verification (reply "check
  your inbox" either way), which doesn't exist yet. Until then it's bounded by
  the per-IP auth limit. Sign-in itself doesn't reveal accounts: one message,
  and the same Argon2 work for unknown emails.
- **Not yet built for password accounts:** email verification, password reset
  and a breached-password check. Password change exists
  (`POST /api/auth/password`) and signs out every other session, so 2.2.2 is
  verified (`password_change_signs_out_every_other_session`). A future reset
  flow must revoke sessions the same way. All of this sits behind
  `PASSWORD_AUTH_ENABLED`, which is off by default and in production.

## Gate limitations

- The pre-commit gate checks the working tree, not only the staged snapshot. It can
  pass a commit whose staged content differs from the tree. CI re-checks the
  committed tree.
- **Local bypass variables.** Two environment variables skip local checks with
  the same effect as `git commit --no-verify`. CI still runs the full gate on
  every push, and that remains the authoritative check.
  - `CASA_IN_REVIEW=1` makes `.githooks/pre-commit`, `.githooks/pre-push`,
    `scripts/claude-review.sh`, `scripts/claude-stop-gate.sh` and the
    `casa_check.py` lint hook exit at once. It exists so the Claude review
    (which runs with it set) doesn't trigger the hooks again. Never set it by hand.
  - `CASA_SKIP_CLAUDE_REVIEW=1` skips only the pre-commit Claude review, for
    when the `claude` CLI is unavailable. It prints `SKIPPED`, but the commit
    leaves no trace. Re-run `scripts/claude-review.sh` on that change before
    pushing.
- **DB-backed tests need Postgres.** `scripts/verify.sh` starts a throwaway
  container (`scripts/test-db.sh`, port 55432, data on tmpfs) unless
  `TEST_DATABASE_URL` is set. CI uses a service container. The tests fail rather
  than skip when no database is available.
- Semgrep runs in CI only unless installed locally (`pipx install semgrep`).
- DAST (OWASP ZAP baseline) runs in CI against the docker-compose stack.
  Warnings are reported as an artifact. Only FAIL-level alerts break the build.
- The Claude review is advisory-strength: it can miss issues. The deterministic
  checks and the CASA lab assessment remain authoritative.
