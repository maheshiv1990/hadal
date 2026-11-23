# CASA exceptions and accepted risks

Every suppression (`casa-allow`), dependency-policy change (`backend/deny.toml`),
scanner ignore, or known limitation of the gate is recorded here with a reason.
The pre-commit Claude review rejects suppressions that aren't justified here.

## Active suppressions

_None._

## Dependency policy (`backend/deny.toml`)

| Decision | Reason |
| --- | --- |
| Licenses allow-list: MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0 | Permissive only. Copyleft is rejected. |
| `licenses.private.ignore = true` | Our own crate is `publish = false` and proprietary. |
| actix-web built with `default-features = false, features = ["macros"]` | Drops `cookie 0.16` (RUSTSEC-2026-0594) and `h2 0.3` (RUSTSEC-2026-0258). HTTP/2 belongs at the TLS-terminating proxy. |
| `chrono` replaced by `time` | RUSTSEC-2026-0543 (chrono unmaintained). |
| No advisory ignores | `[advisories] ignore = []`; keep it that way. |

## Architecture notes the assessor will ask about

- **Rate-limit keying behind nginx.** The backend trusts `X-Real-IP` only when
  `TRUST_PROXY_HEADERS=true`. That is set in docker-compose, where the backend
  publishes no port and is reachable only through nginx, which overwrites the
  header. Publishing port 8080 directly while this is true would let clients
  spoof their IP to dodge the limit. Tests cover both modes.
- **Backend to Postgres is plaintext** on the private compose network (pending 4.1.2).

## Gate limitations

- The pre-commit gate checks the working tree, not only the staged snapshot. It can
  pass a commit whose staged content differs from the tree. CI re-checks the
  committed tree.
- Semgrep runs in CI only unless installed locally (`pipx install semgrep`).
- DAST (OWASP ZAP baseline) runs in CI against the docker-compose stack.
  Warnings are reported as an artifact. Only FAIL-level alerts break the build.
- The Claude review is advisory-strength: it can miss issues. The deterministic
  checks and the CASA lab assessment remain authoritative.
