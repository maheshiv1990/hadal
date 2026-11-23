#!/usr/bin/env bash
# CASA verification gate. Single entry point used by the Claude Code Stop hook,
# git hooks and CI, so every path runs the same checks.
#
#   scripts/verify.sh quick   fast, offline: CASA rules + register, fmt, clippy,
#                             tests, typecheck, secret scan       (pre-commit, Claude)
#   scripts/verify.sh full    quick + dependency audits, frontend build, SAST,
#                             git-history secret scan             (pre-push, CI)
#
# Env: CASA_STRICT=1        pending CASA requirements fail (release builds)
#      CI=true              a missing scanner is a failure, not a warning
set -uo pipefail

MODE="${1:-full}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

failed=()
skipped=()

step() {
  local name="$1"; shift
  printf '\n==> %s\n' "$name"
  if "$@"; then
    printf -- '--- ok: %s\n' "$name"
  else
    printf -- '--- FAILED: %s\n' "$name"
    failed+=("$name")
  fi
}

# Returns 0 if the tool exists. Missing tools fail in CI, warn locally.
have() {
  if command -v "$1" >/dev/null 2>&1; then return 0; fi
  if [[ "${CI:-}" == "true" ]]; then
    failed+=("missing tool: $1")
  else
    skipped+=("$1 (not installed; CI enforces it)")
  fi
  return 1
}

# gitleaks over the working tree (tracked + untracked, honouring .gitignore),
# without walking target/ or node_modules/.
secrets_worktree() {
  local tmp rc
  tmp="$(mktemp -d)"
  git ls-files -co --exclude-standard -z | rsync -a --from0 --files-from=- ./ "$tmp/" \
    && gitleaks dir "$tmp" --no-banner --redact --log-level warn -v
  rc=$?
  rm -rf "$tmp"
  return $rc
}

frontend_deps() {
  [[ -d frontend/node_modules ]] || (cd frontend && npm ci --no-audit --no-fund --ignore-scripts)
}

# ---- quick ----------------------------------------------------------------
step "casa: checker self-tests"      python3 -m unittest -q scripts/test_casa_check.py
step "casa: static rules"            python3 scripts/casa_check.py lint
step "casa: requirement register"    python3 scripts/casa_check.py requirements
step "backend: rustfmt"              bash -c 'cd backend && cargo fmt --check'
step "backend: clippy (CASA lints)"  bash -c 'cd backend && cargo clippy --locked --all-targets -q -- -D warnings'
step "backend: tests"                bash -c 'cd backend && cargo test --locked -q'
step "frontend: typecheck"           bash -c "$(declare -f frontend_deps); frontend_deps && cd frontend && npm run -s typecheck"
if have gitleaks; then step "secrets: working tree (gitleaks)" secrets_worktree; fi

# ---- full -----------------------------------------------------------------
if [[ "$MODE" == "full" ]]; then
  if have cargo-deny;  then step "deps: cargo-deny (advisories, licenses, sources)" bash -c 'cd backend && cargo deny --locked check'; fi
  if have cargo-audit; then step "deps: cargo-audit" bash -c 'cd backend && cargo audit -q'; fi
  step "deps: npm audit"     bash -c 'cd frontend && npm audit --audit-level=low'
  step "frontend: build"     bash -c 'cd frontend && npm run -s build'
  if have semgrep; then
    step "sast: semgrep" semgrep scan --error --quiet --metrics=off \
      --config p/owasp-top-ten --config p/rust --config p/typescript --config p/secrets \
      --exclude frontend/node_modules --exclude backend/target backend/src frontend/src
  fi
  if have gitleaks && git rev-parse -q --verify HEAD >/dev/null; then
    step "secrets: git history (gitleaks)" gitleaks git --no-banner --redact --log-level warn .
  fi
fi

# ---- summary --------------------------------------------------------------
echo
for s in "${skipped[@]+"${skipped[@]}"}"; do echo "skipped: $s"; done
if ((${#failed[@]})); then
  echo "CASA GATE FAILED (${MODE}):"
  for f in "${failed[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "CASA GATE PASSED (${MODE})"
