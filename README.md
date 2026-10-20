<div align="center">

# MaxIO

S3-compatible object storage server — single-binary replacement for MinIO.

</div>

> **Warning:** MaxIO is under active development. Do not use it in production yet.

MaxIO is a lightweight S3-compatible object storage server written in Rust. One binary, one data directory, no database. Buckets are directories and objects are files, so a backup is a copy of the data dir.

- Works with `mc`, AWS CLI, and any S3 SDK (AWS Signature V4, presigned URLs)
- Built-in web console at `/ui/`
- Multipart upload, versioning, tagging, CORS, range and conditional requests, checksums
- Server-side encryption (SSE-S3, SSE-C) and optional erasure coding

See [COMPATIBILITY.md](COMPATIBILITY.md) for the full list of supported S3 and MinIO features.

## Quick Start

The web console is at `http://localhost:9000/ui/`.

Sign-in sticks on plain `http://localhost`, `http://127.0.0.1`, and `http://[::1]`. The session cookie is marked `Secure` when the request is HTTPS (`X-Forwarded-Proto: https`) or the host is anything else, so a public HTTP listener does not store a console session. A TLS proxy must forward `X-Forwarded-Proto: https`. To allow the console over plain HTTP on a non-loopback host, set `MAXIO_SECURE_COOKIES=false` (anyone on that network can read the session).

The server refuses to start with the built-in `maxioadmin` / `maxioadmin` keys. Set your own keys, as below. `--allow-insecure-dev` keeps those defaults and also omits `Secure` on every host; use it only on a machine you trust.

### Docker

```bash
# Local credentials for this server. The secret is generated, not a shared default.
export MAXIO_ACCESS_KEY="local-admin"
export MAXIO_SECRET_KEY="$(openssl rand -hex 24)"

docker run -d --name maxio -p 9000:9000 -v "$(pwd)/data:/data" \
  -e MAXIO_ACCESS_KEY -e MAXIO_SECRET_KEY \
  ghcr.io/coollabsio/maxio

printf 'Open http://localhost:9000/ui/ and sign in with %s / %s\n' \
  "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
```

Images are on [GHCR](https://ghcr.io/coollabsio/maxio) and Docker Hub (`coollabsio/maxio`).

### Build from source

Install [Rust](https://rustup.rs) (the version in `rust-toolchain.toml`) and [bun](https://bun.sh) **1.4.2**. `cargo build` runs bun to compile the web console and embed it in the binary.

```bash
curl -fsSL https://bun.sh/install | bash -s "bun-v1.4.2"
export PATH="$HOME/.bun/bin:$PATH"

export MAXIO_ACCESS_KEY="local-admin"
export MAXIO_SECRET_KEY="$(openssl rand -hex 24)"

cargo build --release
./target/release/maxio --data-dir ./data --port 9000

printf 'Open http://localhost:9000/ui/ and sign in with %s / %s\n' \
  "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `MAXIO_PORT` | `9000` | Listen port |
| `MAXIO_ADDRESS` | `0.0.0.0` | Bind address |
| `MAXIO_DATA_DIR` | `./data` | Storage directory |
| `MAXIO_ACCESS_KEY` | `maxioadmin` | Access key (aliases: `MINIO_ROOT_USER`, `MINIO_ACCESS_KEY`) |
| `MAXIO_SECRET_KEY` | `maxioadmin` | Secret key (aliases: `MINIO_ROOT_PASSWORD`, `MINIO_SECRET_KEY`) |
| `MAXIO_REGION` | `us-east-1` | S3 region (aliases: `MINIO_REGION_NAME`, `MINIO_REGION`) |
| `MAXIO_DEFAULT_BUCKETS` | _(none)_ | Comma-separated buckets to create at startup (alias: `MINIO_DEFAULT_BUCKETS`) |
| `MAXIO_ALLOW_INSECURE_DEV` | `false` | Keep the built-in `maxioadmin` keys and omit `Secure` on console cookies for every host. Local only |
| `MAXIO_SECURE_COOKIES` | `true` | `Secure` cookies on HTTPS and on non-loopback hosts. Plain `http://localhost` still stores a session. Set `false` to allow that on any host |
| `MAXIO_ERASURE_CODING` | `false` | Enable erasure coding |
| `MAXIO_CHUNK_SIZE` | `10485760` | Erasure coding chunk size in bytes |
| `MAXIO_PARITY_SHARDS` | `0` | Parity shards per object |
| `MAXIO_MASTER_KEY` | _(auto)_ | Base64 32-byte SSE-S3 master key. If unset, stored in `<data-dir>/.maxio-keys.json` — back this file up |
| `MAXIO_MAX_CONSOLE_BODY_BYTES` | `1048576` | Max body size for console JSON routes |

Each variable also has a CLI flag (for example `--port`). Run `maxio --help` for the full list.

## Usage

```bash
# MAXIO_ACCESS_KEY and MAXIO_SECRET_KEY are the values exported in Quick Start.
mc alias set maxio http://localhost:9000 "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
mc mb maxio/my-bucket
mc cp file.txt maxio/my-bucket/
```

## Durability

Object bytes, sidecars, multipart parts, version files, and bucket configuration are published with a temp file, `fsync`, rename, and a directory `fsync`. A crash during a write leaves the previous object in place, or a temp file that is not part of the bucket listing.

On startup MaxIO deletes those temp files, restores or drops stranded erasure-coded publish backups, and removes multipart uploads whose metadata never landed. Uploads that have readable metadata are kept so a client can finish them. An hourly sweep aborts uploads that have been idle for 7 days and deletes temp files older than a day (a live upload is younger than that).

Back up the data directory and, when SSE-S3 is in use, `<data-dir>/.maxio-keys.json`. The keyring is not recoverable.

### `maxio check`

Stop the server, then scan the data directory:

```bash
maxio check --data-dir ./data
maxio check --data-dir ./data --repair
```

The report lists stale temp files, stranded backups, object bytes without a sidecar, sidecars without bytes, plain-object size / etag / checksum mismatches, multipart debris, and erasure-coded chunks that do not match their manifest. Exit status is 1 when anything is still unresolved.

`--repair` fixes the cases that are determined by the bytes already on disk:

- delete temp files and finished publish backups; restore a backup when the live object is missing
- recreate a sidecar for plain object bytes that have none (etag and size taken from the file)
- delete a sidecar whose bytes are gone, and delete a multipart upload that has no readable metadata
- rewrite a plain object's size, etag, and checksum so they match the file
- rebuild a missing or corrupt data chunk when parity shards can reconstruct it

It does not invent bucket configuration, rewrite encrypted sidecars (those are MAC-protected), or choose between a plain file and an erasure-coded directory for the same key. Those are reported and left unchanged.

## Shutdown and limits

`SIGTERM` and `SIGINT` stop the accept loop, finish requests already in progress, and exit. The drain waits up to `MAXIO_SHUTDOWN_TIMEOUT_SECS` (default 8) and then aborts what is left. Docker sends `SIGTERM` and, after its own stop timeout (default 10 seconds), `SIGKILL`. The default drain finishes inside that window. To let a long upload complete, raise both the MaxIO timeout and `docker stop -t`.

One client cannot hold the process open without bound. Over-limit calls return S3 errors: `EntityTooLarge` (400) when a single PUT, part, copy, or finished multipart object is too big, and `SlowDown` (503) when the connection or in-flight request cap is hit. A header block larger than the cap is rejected, an idle keep-alive connection is closed, and a request that runs too long returns `RequestTimeout` (400).

| Variable | Default | Description |
|---|---|---|
| `MAXIO_SHUTDOWN_TIMEOUT_SECS` | `8` | Drain timeout after SIGTERM/SIGINT |
| `MAXIO_MAX_OBJECT_SIZE` | 5 GiB | Max PutObject / CopyObject. Use multipart above this |
| `MAXIO_MAX_PART_SIZE` | 5 GiB | Max one multipart part |
| `MAXIO_MAX_MULTIPART_OBJECT_SIZE` | 5 TiB | Max assembled multipart object |
| `MAXIO_MAX_HEADER_BYTES` | `65536` | Max request header bytes (hyper's floor is 8192) |
| `MAXIO_MAX_CONNECTIONS` | `1024` | Accepted connections. Further connections get `SlowDown`. `0` disables |
| `MAXIO_MAX_CONCURRENT_REQUESTS` | `256` | In-flight requests. Further requests get `SlowDown`. Health checks are exempt. `0` disables |
| `MAXIO_REQUEST_TIMEOUT_SECS` | `3600` | Max request duration, including the body. `0` disables |
| `MAXIO_IDLE_TIMEOUT_SECS` | `60` | Keep-alive idle timeout. `0` disables |

## Load test

`tests/loadtest.py` starts MaxIO and measures small-object PUT/GET, a multipart upload, mixed reads and writes, and a listing. It prints throughput, latency percentiles, and peak RSS.

```bash
SKIP_FRONTEND=1 cargo build
python3 tests/loadtest.py
```

`MAXIO_LOAD_SMALL`, `MAXIO_LOAD_CONCURRENCY`, `MAXIO_LOAD_MULTIPART_MB`, and `MAXIO_LOAD_PART_MB` change the size of the run. A run on this development machine (`MAXIO_LOAD_SMALL=2000`, `MAXIO_LOAD_CONCURRENCY=16`, `MAXIO_LOAD_MULTIPART_MB=64`, one Python client) produced:

| Scenario | Result |
|---|---|
| PUT 4 KiB × 2000 | 1721 obj/s, p50 8.6 ms, p95 13.7 ms, p99 16.3 ms |
| GET 4 KiB × 2000 | 2387 obj/s, p50 6.1 ms, p95 11.3 ms, p99 13.9 ms |
| Multipart 64 MiB (8 × 8 MiB, serial) | 34.0 MiB/s, 1.9 s |
| Mixed read/write × 2000 | 2030 op/s, p50 7.4 ms, p95 13.7 ms, p99 16.9 ms |
| List 2001 keys (two pages) | 255 ms |
| Peak RSS | 48.7 MiB |

The multipart figure is one client uploading parts one after another, not the parallel warp number in Benchmarks. The process stayed up and RSS stayed under 50 MiB. No crash or leak showed up in this run.

## Benchmarks

MaxIO vs MinIO on a Hetzner CCX13 (`./tests/bench-remote.sh`, MaxIO >= 0.3.2):

| Scenario | MaxIO | MinIO |
|----------|-------|-------|
| PUT 4KiB         | 3221.82 obj/s | 975.72 obj/s |
| PUT 1MiB         | 348.93 MiB/s | 207.11 MiB/s |
| PUT 64MiB        | 285.48 MiB/s | 333.53 MiB/s |
| GET 4KiB         | 6699.48 obj/s | 3145.10 obj/s |
| GET 1MiB         | 1864.38 MiB/s | 760.68 MiB/s |
| Mixed 1MiB       | 606.38 MiB/s | 343.56 MiB/s |
| Multipart 100MiB | 2376.32 MiB/s | 1781.91 MiB/s |

## Contributing

See [CLAUDE.md](CLAUDE.md) for the development workflow, architecture, and tests.

## Core Maintainer

| [<img src="https://github.com/andrasbacsai.png" width="120" /><br />Andras Bacsai](https://github.com/andrasbacsai) |
|---|

## License

[Apache-2.0](LICENSE)
