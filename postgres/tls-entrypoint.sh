#!/bin/sh
# Starts Postgres with TLS required for every network connection (CASA 4.1.2).
#
# Postgres refuses a private key that isn't owned by it with mode 0600, and a
# bind-mounted file can't be chowned, so the certificate and key are copied
# from /certs-src (read-only mount of certs/db) into a private directory.
# Then the image's normal entrypoint runs with SSL switched on.
set -eu

TLS=/var/lib/postgresql/tls
install -d -o postgres -g postgres -m 0700 "$TLS"
install -o postgres -g postgres -m 0600 /certs-src/server.key "$TLS/server.key"
install -o postgres -g postgres -m 0644 /certs-src/server.crt "$TLS/server.crt"

# Unix socket (inside the container only: healthcheck, admin) stays as the
# image sets it up. Over the network: TLS with a password, or nothing.
cat > "$TLS/pg_hba.conf" <<'EOF'
local     all  all             trust
hostssl   all  all  all        scram-sha-256
hostnossl all  all  all        reject
EOF
chown postgres:postgres "$TLS/pg_hba.conf"
chmod 0600 "$TLS/pg_hba.conf"

exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$TLS/server.crt" \
  -c ssl_key_file="$TLS/server.key" \
  -c ssl_min_protocol_version=TLSv1.2 \
  -c hba_file="$TLS/pg_hba.conf" \
  "$@"
