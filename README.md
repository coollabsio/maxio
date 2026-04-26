<div align="center">

# MaxIO

S3-compatible object storage server — single-binary replacement for MinIO.

Rust · Axum · Svelte 5 · Tailwind CSS v4 · shadcn-svelte

</div>

## About the Project

> **Warning:** MaxIO is under active development. Do not use it in production yet.

MaxIO is a lightweight, single-binary S3-compatible object storage server written in Rust. No JVM, no database, no runtime dependencies — just one binary and a data directory. Buckets are directories, objects are files. Back up by copying the data dir.

## Features

- **Single Binary** — Frontend assets are compiled into the binary via `rust-embed`. Nothing extra to deploy
- **Pure Filesystem Storage** — No database. Buckets are directories, objects are files, metadata in `.meta.json` sidecars
- **AWS Signature V4** — Compatible with `mc`, AWS CLI, and any S3 SDK
- **Web Console** — Built-in UI at `/ui/` for browsing, uploading, and managing objects
- **S3 API Coverage** — ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation, ListObjectsV1/V2, ListObjectVersions, PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects (batch), CopyObject, Multipart Upload (including UploadPartCopy), Object Tagging, CORS, Versioning, GetBucketEncryption, PutBucketEncryption, DeleteBucketEncryption
- **Server-Side Encryption** — AES-256-GCM at rest with per-object Data Encryption Keys, sidecar HMAC-SHA256 integrity binding, and AAD-bound frames. Supports SSE-S3 (server-managed keyring with rotatable master key), SSE-C (customer-supplied keys), bucket default encryption, and composes with Erasure Coding (encrypt-then-EC)
- **Conditional Requests** — `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` headers (RFC 7232)
- **Range Requests** — HTTP 206 Partial Content support via `Range` header on GetObject
- **Checksum Verification** — CRC32, CRC32C, SHA-1, and SHA-256 checksums on upload with automatic validation and persistent storage
- **Erasure Coding** — Optional chunked storage with per-chunk SHA-256 integrity verification and Reed-Solomon parity for automatic recovery from corrupted or missing data

## Benchmarks MaxIO vs MinIO

Hetzner CCX13 (./tests/bench-remote.sh <remote server>)

Before optimization (MaxIO <0.3.2)

| Scenario | MaxIO | MinIO |
|----------|-------|-------|
| PUT 4KiB         | 14.66 MiB/s, 3753.64 obj/s | 4.60 MiB/s, 1178.18 obj/s |
| PUT 1MiB         | 337.18 MiB/s, 337.18 obj/s | 214.06 MiB/s, 214.06 obj/s |
| PUT 64MiB        | 253.11 MiB/s, 3.95 obj/s | 330.56 MiB/s, 5.17 obj/s |
| GET 4KiB         | 0.82 MiB/s, 208.89 obj/s | 12.57 MiB/s, 3218.50 obj/s |
| GET 1MiB         | 203.54 MiB/s, 203.54 obj/s | 930.64 MiB/s, 930.64 obj/s |
| Mixed 1MiB       | 275.17 MiB/s, 366.98 obj/s | 339.91 MiB/s, 453.40 obj/s |
| Multipart 100MiB | 451.29 MiB/s, 45.13 obj/s | 1888.60 MiB/s, 188.86 obj/s |

After optimization (MaxIO >= 0.3.2)

| Scenario | MaxIO | MinIO |
|----------|-------|-------|
| PUT 4KiB         | 12.59 MiB/s, 3221.82 obj/s | 3.81 MiB/s, 975.72 obj/s |
| PUT 1MiB         | 348.93 MiB/s, 348.93 obj/s | 207.11 MiB/s, 207.11 obj/s |
| PUT 64MiB        | 285.48 MiB/s, 4.46 obj/s | 333.53 MiB/s, 5.21 obj/s |
| GET 4KiB         | 26.17 MiB/s, 6699.48 obj/s | 12.29 MiB/s, 3145.10 obj/s |
| GET 1MiB         | 1864.38 MiB/s, 1864.38 obj/s | 760.68 MiB/s, 760.68 obj/s |
| Mixed 1MiB       | 606.38 MiB/s, 808.94 obj/s | 343.56 MiB/s, 458.19 obj/s |
| Multipart 100MiB | 2376.32 MiB/s, 237.63 obj/s | 1781.91 MiB/s, 178.19 obj/s |


## Installation

### Build from Source

```bash
# Build frontend (required — assets are embedded into the binary)
cd ui && bun run build && cd ..

# Build binary
cargo build --release

# Run
./target/release/maxio --data-dir ./data --port 9000
```

### Docker

```bash
docker run -d \
  -p 9000:9000 \
  -v $(pwd)/data:/data \
  ghcr.io/coollabsio/maxio
```

Or from Docker Hub:

```bash
docker run -d \
  -p 9000:9000 \
  -v $(pwd)/data:/data \
  coollabsio/maxio
```

Configure with environment variables:

```bash
docker run -d \
  -p 9000:9000 \
  -v $(pwd)/data:/data \
  -e MAXIO_ACCESS_KEY=myadmin \
  -e MAXIO_SECRET_KEY=mysecret \
  ghcr.io/coollabsio/maxio
```

Docker Compose:

```yaml
services:
  maxio:
    image: ghcr.io/coollabsio/maxio
    ports:
      - "9000:9000"
    volumes:
      - maxio-data:/data
    environment:
      - MAXIO_ACCESS_KEY=maxioadmin
      - MAXIO_SECRET_KEY=maxioadmin
```

```bash
docker compose up -d
```

Open `http://localhost:9000/ui/` in your browser. Default credentials: `maxioadmin` / `maxioadmin`

## Configuration

| Variable | CLI Flag | Default | Description |
|---|---|---|---|
| `MAXIO_PORT` | `--port` | `9000` | Listen port |
| `MAXIO_ADDRESS` | `--address` | `0.0.0.0` | Bind address |
| `MAXIO_DATA_DIR` | `--data-dir` | `./data` | Storage directory |
| `MAXIO_ACCESS_KEY` | `--access-key` | `maxioadmin` | Access key (aliases: `MINIO_ROOT_USER`, `MINIO_ACCESS_KEY`) |
| `MAXIO_SECRET_KEY` | `--secret-key` | `maxioadmin` | Secret key (aliases: `MINIO_ROOT_PASSWORD`, `MINIO_SECRET_KEY`) |
| `MAXIO_REGION` | `--region` | `us-east-1` | S3 region (aliases: `MINIO_REGION_NAME`, `MINIO_REGION`) |
| `MAXIO_ERASURE_CODING` | `--erasure-coding` | `false` | Enable erasure coding with per-chunk integrity checksums |
| `MAXIO_CHUNK_SIZE` | `--chunk-size` | `10485760` (10MB) | Chunk size in bytes for erasure coding |
| `MAXIO_PARITY_SHARDS` | `--parity-shards` | `0` | Number of parity shards per object (requires `--erasure-coding`, 0 = no parity) |
| `MAXIO_MASTER_KEY` | `--master-key` | _(auto-generated)_ | Base64-encoded 32-byte SSE-S3 master key. If unset, a key is generated and stored under `<data-dir>/.keyring.json`. Provide explicitly to control key rotation |

## Usage

### MinIO Client (mc)

```bash
mc alias set maxio http://localhost:9000 maxioadmin maxioadmin

mc mb maxio/my-bucket
mc cp file.txt maxio/my-bucket/file.txt
mc ls maxio/my-bucket/
mc cat maxio/my-bucket/file.txt
mc rm maxio/my-bucket/file.txt
mc rb maxio/my-bucket
```

### AWS CLI

```bash
export AWS_ACCESS_KEY_ID=maxioadmin
export AWS_SECRET_ACCESS_KEY=maxioadmin

aws --endpoint-url http://localhost:9000 s3 mb s3://my-bucket
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://my-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 ls s3://my-bucket/
aws --endpoint-url http://localhost:9000 s3 rm s3://my-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 rb s3://my-bucket
```

### Server-Side Encryption

```bash
# SSE-S3 (server-managed key) — encrypt a single upload
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://my-bucket/file.txt \
  --sse AES256

# Set bucket default encryption — every subsequent upload is encrypted
aws --endpoint-url http://localhost:9000 s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# SSE-C (customer-supplied key) — caller manages the key
KEY=$(openssl rand 32 | base64)
KEY_MD5=$(echo -n "$KEY" | base64 -d | openssl dgst -md5 -binary | base64)
aws --endpoint-url http://localhost:9000 s3api put-object \
  --bucket my-bucket --key secret.bin --body secret.bin \
  --sse-customer-algorithm AES256 \
  --sse-customer-key "$KEY" \
  --sse-customer-key-md5 "$KEY_MD5"
```

## Roadmap

- ~~Multipart upload~~, ~~presigned URLs~~, ~~CopyObject~~
- ~~CORS~~, ~~Range headers~~
- ~~Versioning~~, lifecycle rules, ~~server-side encryption (SSE-S3, SSE-C)~~
- Multi-user support
- Distributed mode, ~~erasure coding~~, replication

## Contributing

See [CLAUDE.md](CLAUDE.md) for the full development workflow, architecture details, and testing instructions.

## Core Maintainer

| [<img src="https://github.com/andrasbacsai.png" width="120" /><br />Andras Bacsai](https://github.com/andrasbacsai) |
|---|

## License

[Apache-2.0](LICENSE)
