# syntax=docker/dockerfile:1
# Build context is the repo root (see docker-compose.yml).

# ---- Build the SolidJS frontend ----
FROM node:24-alpine AS frontend
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Serve it with nginx ----
FROM nginx:1.29-alpine
# Rendered to /etc/nginx/conf.d/default.conf at start-up.
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=frontend /app/dist /usr/share/nginx/html
COPY --chmod=0755 nginx/reload-certs.sh /docker-entrypoint.d/40-reload-certs.sh
# Settings for default.conf.template. Defaults are production-safe (2-year
# HSTS, standard ports); docker-compose.yml (local) and
# docker-compose.prod.yml (hadalspace.com) set the rest.
ENV SERVER_NAME=_ \
    SSL_CERTIFICATE=/etc/nginx/certs/cert.pem \
    SSL_CERTIFICATE_KEY=/etc/nginx/certs/key.pem \
    HTTPS_REDIRECT_PORT_SUFFIX= \
    HSTS_MAX_AGE=63072000 \
    CERT_RELOAD_HOURS=0
RUN mkdir -p /var/www/certbot
EXPOSE 80 443
