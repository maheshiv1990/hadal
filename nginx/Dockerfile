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
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=frontend /app/dist /usr/share/nginx/html
EXPOSE 80
