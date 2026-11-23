#!/usr/bin/env bash
# One-time setup per clone: route git hooks to the versioned .githooks/ directory.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
chmod +x .githooks/* scripts/*.sh scripts/casa_check.py
echo "CASA git hooks installed (pre-commit: quick gate + Claude review, pre-push: full gate)."
