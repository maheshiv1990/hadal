#!/usr/bin/env bash
# Claude Code Stop hook: Claude cannot finish a turn while the CASA quick gate
# fails. Skips work when nothing changed since the last passing run.
set -uo pipefail
[[ -n "${CASA_IN_REVIEW:-}" ]] && exit 0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
input="$(cat)"
active="$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null || echo false)"

state="$({ git rev-parse -q --verify HEAD; git status --porcelain=v1 -uall;
           git ls-files -mo --exclude-standard -z | xargs -0 shasum 2>/dev/null; } | shasum | cut -c1-40)"
dir="$(git rev-parse --git-path casa)"; mkdir -p "$dir"
[[ -f "$dir/pass" && "$(cat "$dir/pass")" == "$state" ]] && exit 0
if [[ "$active" == "true" && -f "$dir/fail" && "$(cat "$dir/fail")" == "$state" ]]; then
  # Nothing changed since the failing run: don't loop forever, tell the user.
  echo '{"systemMessage":"CASA gate is still failing (unchanged since last attempt). Run scripts/verify.sh quick."}'
  exit 0
fi

if out="$(scripts/verify.sh quick 2>&1)"; then
  echo "$state" > "$dir/pass"; rm -f "$dir/fail"
  exit 0
fi
echo "$state" > "$dir/fail"
{
  echo "CASA gate failed. Fix these before finishing (see CLAUDE.md):"
  printf '%s\n' "$out" | grep -E '^(--- FAILED|  - |error|[^ ].*:[0-9]+: \[)|^    |^error\[|^test .* FAILED|panicked|-->' | head -80
} >&2
exit 2
