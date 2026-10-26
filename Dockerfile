# syntax=docker/dockerfile:1.7
FROM oven/bun:1.4.4 AS web
WORKDIR /app/ui
COPY ui/package.json ui/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui/ ./
RUN bun run build

# Pinned toolchain (rust-toolchain.toml, CI). Cargo.toml rust-version 1.89 is the MSRV.
FROM rust:1.97.1-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY src ./src
COPY tests ./tests
# Prebuilt UI: build.rs sees ui/dist/index.html and skips the bun build.
COPY --from=web /app/ui/dist ./ui/dist
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --create-home --home-dir /nonexistent --shell /usr/sbin/nologin maxio \
  && mkdir -p /data \
  && chown -R maxio:maxio /data

COPY --from=builder /app/target/release/maxio /usr/local/bin/maxio

ENV MAXIO_DATA_DIR="/data"
EXPOSE 9000
VOLUME ["/data"]
USER maxio:maxio
# Liveness is also served at /minio/health/live for MinIO-compatible probes.
# This image has no curl or mc, so a copied MinIO `mc ready` / curl check
# cannot run inside the container. Probe from outside, or use this command.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["maxio", "healthcheck", "--url", "http://127.0.0.1:9000/maxio/health/live", "--timeout-ms", "2000"]

# SIGTERM starts a drain of in-flight requests (MAXIO_SHUTDOWN_TIMEOUT_SECS,
# default 8). Docker then sends SIGKILL after its stop timeout, which defaults
# to 10 seconds. Raise `docker stop -t` above the drain timeout when uploads
# should be allowed to finish.
STOPSIGNAL SIGTERM
ENTRYPOINT ["maxio"]
CMD ["serve"]
