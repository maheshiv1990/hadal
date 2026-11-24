#!/usr/bin/env bash
# Throwaway Postgres for the backend's DB-backed tests (auth, sessions, IDOR).
# Separate from the docker-compose database, so tests never touch dev data.
#
#   eval "$(scripts/test-db.sh start)"   start it (if needed), export TEST_DATABASE_URL
#   scripts/test-db.sh stop              remove it
#
# The password is random per machine and kept in .git/casa/ (never committed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="hadal-casa-testdb"
PORT="${HADAL_TEST_DB_PORT:-55432}"
STATE="$(git -C "$ROOT" rev-parse --git-path casa)"
[[ "$STATE" = /* ]] || STATE="$ROOT/$STATE"
PW_FILE="$STATE/testdb.pw"

url() {
  printf 'postgres://hadal_test:%s@127.0.0.1:%s/hadal_test' "$(cat "$PW_FILE")" "$PORT"
}

start() {
  command -v docker >/dev/null || { echo "docker is required for the test database" >&2; exit 1; }
  mkdir -p "$STATE"
  if [[ ! -s "$PW_FILE" ]]; then
    (umask 077; openssl rand -hex 24 > "$PW_FILE")
  fi
  if [[ -z "$(docker ps -q --filter "name=^${NAME}$")" ]]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
      -e POSTGRES_USER=hadal_test -e POSTGRES_DB=hadal_test \
      -e POSTGRES_PASSWORD="$(cat "$PW_FILE")" \
      -p "127.0.0.1:${PORT}:5432" --tmpfs /var/lib/postgresql/data \
      postgres:17-alpine >/dev/null
  fi
  for _ in $(seq 1 60); do
    if docker exec "$NAME" pg_isready -q -U hadal_test -d hadal_test 2>/dev/null; then
      printf 'export TEST_DATABASE_URL=%q\n' "$(url)"
      return 0
    fi
    sleep 0.5
  done
  echo "test database did not become ready" >&2
  exit 1
}

case "${1:-start}" in
  start) start ;;
  stop)  docker rm -f "$NAME" >/dev/null 2>&1 || true ;;
  *)     echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
