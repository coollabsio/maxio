FROM rust:1-bookworm AS builder

# Install bun
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

WORKDIR /app
COPY . .

# Build frontend
RUN cd ui && bun install && bun run build

# Build binary
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/maxio /usr/local/bin/maxio

ENV MAXIO_DATA_DIR="/data"
EXPOSE 9000
VOLUME ["/data"]

ENTRYPOINT ["maxio"]
