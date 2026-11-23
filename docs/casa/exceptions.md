# CASA exceptions and accepted risks

Every suppression (`casa-allow`), dependency-policy change (`backend/deny.toml`),
scanner ignore, or known limitation of the gate is recorded here with a reason.
The pre-commit Claude review rejects suppressions that aren't justified here.

## Active suppressions

`casa-allow`: _none._

Scanner ignores:

| Location | Scanner | Reason |
| --- | --- | --- |
| `scripts/test_casa_check.py` (`hardcoded-secret` self-test case) | gitleaks (`# gitleaks:allow`) | The value `GOCSPX-abcdefgh123` is a fake sample that proves the `hardcoded-secret` rule fires. It is not a real credential and is never used at runtime. |

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
- Semgrep runs in CI only unless installed locally (`pipx install semgrep`).
- DAST (OWASP ZAP baseline) runs in CI against the docker-compose stack.
  Warnings are reported as an artifact. Only FAIL-level alerts break the build.
- The Claude review is advisory-strength: it can miss issues. The deterministic
  checks and the CASA lab assessment remain authoritative.
