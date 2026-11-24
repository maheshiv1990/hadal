#!/usr/bin/env bash
# Issues the first Let's Encrypt certificate for hadalspace.com and
# www.hadalspace.com on a production server, then starts the stack with it.
# The certbot service in docker-compose.prod.yml renews it from then on.
#
#   scripts/letsencrypt-init.sh <contact-email> [--staging]
#
# Needs: DNS A/AAAA records for both names pointing at this server, ports 80
# and 443 reachable, and .env filled in (see production.env.example).
# Use --staging first: Let's Encrypt rate-limits failed production requests.
#
# nginx can't start without a certificate, and Let's Encrypt can't issue one
# until nginx serves the HTTP-01 challenge, so a throwaway self-signed
# certificate is put in place first and replaced by the real one.
set -euo pipefail

EMAIL="${1:-}"
STAGING="${2:-}"
if [[ -z "$EMAIL" || "$EMAIL" != *@* ]]; then
  echo "usage: $0 <contact-email> [--staging]" >&2
  exit 2
fi
if [[ -n "$STAGING" && "$STAGING" != "--staging" ]]; then
  echo "unknown option: $STAGING" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
DOMAIN="${DOMAIN:-hadalspace.com}"
CERT_NAME="${CERT_NAME:-$DOMAIN}"
compose() { docker compose -f docker-compose.yml -f docker-compose.prod.yml "$@"; }
in_certbot() { compose run --rm --no-deps --entrypoint sh "$@" certbot -c "$CMD"; }

CMD="test -s /etc/letsencrypt/live/$CERT_NAME/fullchain.pem && ! grep -q 'temporary-bootstrap' /etc/letsencrypt/live/$CERT_NAME/.hadal 2>/dev/null"
if in_certbot; then
  echo "A certificate for $CERT_NAME already exists; the certbot service renews it."
  echo "Starting the stack."
  compose up -d --build
  exit 0
fi

echo "==> Temporary self-signed certificate so nginx can start"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=$DOMAIN" -keyout "$tmp/privkey.pem" -out "$tmp/fullchain.pem" 2>/dev/null
CMD="mkdir -p /etc/letsencrypt/live/$CERT_NAME && cp /bootstrap/privkey.pem /bootstrap/fullchain.pem /etc/letsencrypt/live/$CERT_NAME/ && chmod 600 /etc/letsencrypt/live/$CERT_NAME/privkey.pem && echo temporary-bootstrap > /etc/letsencrypt/live/$CERT_NAME/.hadal"
in_certbot -v "$tmp:/bootstrap:ro"

echo "==> Starting nginx (and the app) to answer the challenge"
compose up -d --build nginx

echo "==> Removing the temporary certificate"
CMD="rm -rf /etc/letsencrypt/live/$CERT_NAME /etc/letsencrypt/archive/$CERT_NAME /etc/letsencrypt/renewal/$CERT_NAME.conf"
in_certbot

echo "==> Requesting the certificate from Let's Encrypt${STAGING:+ (staging)}"
compose run --rm --no-deps --entrypoint certbot certbot certonly \
  --webroot -w /var/www/certbot \
  --cert-name "$CERT_NAME" -d "$DOMAIN" -d "www.$DOMAIN" \
  --key-type ecdsa --email "$EMAIL" --agree-tos --no-eff-email --non-interactive \
  ${STAGING:+--staging}

echo "==> Loading it into nginx and starting renewals"
compose exec nginx nginx -s reload
compose up -d
echo "Done. Check it with: scripts/check-tls.sh $DOMAIN 443 80"
[[ -n "$STAGING" ]] && echo "Staging certificates aren't trusted by browsers: delete them and re-run without --staging."
exit 0
