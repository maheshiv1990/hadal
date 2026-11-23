# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# Cache dependencies: build a dummy main first, then the real source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src target/release/deps/hadal_backend* target/release/.fingerprint/hadal-backend-*

COPY src ./src
COPY migrations ./migrations
# COPY keeps source mtimes, which can predate the dummy build; touch so cargo
# always rebuilds the real binary instead of shipping the empty `fn main`.
RUN touch src/main.rs && cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home app

COPY --from=builder /app/target/release/hadal-backend /usr/local/bin/hadal-backend

USER app
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD curl -fsS http://localhost:8080/api/health || exit 1

CMD ["hadal-backend"]
