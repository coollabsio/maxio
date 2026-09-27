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

```bash
docker run -d -p 9000:9000 -v $(pwd)/data:/data \
  -e MAXIO_ACCESS_KEY=myadmin -e MAXIO_SECRET_KEY=mysecret \
  ghcr.io/coollabsio/maxio
```

Open `http://localhost:9000/ui/`. Images are on [GHCR](https://ghcr.io/coollabsio/maxio) and Docker Hub (`coollabsio/maxio`).

Build from source:

```bash
cargo build --release
./target/release/maxio --data-dir ./data --port 9000
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
| `MAXIO_ALLOW_INSECURE_DEV` | `false` | Allow default credentials and HTTP console cookies |
| `MAXIO_SECURE_COOKIES` | `true` | Force `Secure` on console session cookies |
| `MAXIO_ERASURE_CODING` | `false` | Enable erasure coding |
| `MAXIO_CHUNK_SIZE` | `10485760` | Erasure coding chunk size in bytes |
| `MAXIO_PARITY_SHARDS` | `0` | Parity shards per object |
| `MAXIO_MASTER_KEY` | _(auto)_ | Base64 32-byte SSE-S3 master key. If unset, stored in `<data-dir>/.maxio-keys.json` — back this file up |
| `MAXIO_MAX_CONSOLE_BODY_BYTES` | `1048576` | Max body size for console JSON routes |

Each variable also has a CLI flag (for example `--port`). Run `maxio --help` for the full list.

## Usage

```bash
mc alias set maxio http://localhost:9000 maxioadmin maxioadmin
mc mb maxio/my-bucket
mc cp file.txt maxio/my-bucket/
```

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
