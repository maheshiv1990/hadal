#!/bin/sh
# Runs from the nginx image's entrypoint before nginx starts. With
# CERT_RELOAD_HOURS > 0 (production), nginx reloads on that interval so it
# picks up certificates certbot renewed. A reload drops no connections.
set -eu
hours="${CERT_RELOAD_HOURS:-0}"
case "$hours" in ''|*[!0-9]*) echo "reload-certs: CERT_RELOAD_HOURS must be a number" >&2; exit 1 ;; esac
[ "$hours" -gt 0 ] || exit 0
(
  while sleep "$((hours * 3600))"; do
    nginx -s reload
  done
) &
echo "reload-certs: reloading nginx every ${hours}h for renewed certificates"
