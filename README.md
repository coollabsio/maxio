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
- **S3 API Coverage** — ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation, ListObjectsV1/V2, PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects (batch)
- **Range Requests** — HTTP 206 Partial Content support via `Range` header on GetObject

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
      - MAXIO_ACCESS_KEY=minioadmin
      - MAXIO_SECRET_KEY=minioadmin
```

```bash
docker compose up -d
```

Open `http://localhost:9000/ui/` in your browser. Default credentials: `minioadmin` / `minioadmin`

## Configuration

| Variable | CLI Flag | Default | Description |
|---|---|---|---|
| `MAXIO_PORT` | `--port` | `9000` | Listen port |
| `MAXIO_ADDRESS` | `--address` | `0.0.0.0` | Bind address |
| `MAXIO_DATA_DIR` | `--data-dir` | `./data` | Storage directory |
| `MAXIO_ACCESS_KEY` | `--access-key` | `minioadmin` | Access key |
| `MAXIO_SECRET_KEY` | `--secret-key` | `minioadmin` | Secret key |
| `MAXIO_REGION` | `--region` | `us-east-1` | S3 region |

## Usage

### MinIO Client (mc)

```bash
mc alias set maxio http://localhost:9000 minioadmin minioadmin

mc mb maxio/my-bucket
mc cp file.txt maxio/my-bucket/file.txt
mc ls maxio/my-bucket/
mc cat maxio/my-bucket/file.txt
mc rm maxio/my-bucket/file.txt
mc rb maxio/my-bucket
```

### AWS CLI

```bash
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

aws --endpoint-url http://localhost:9000 s3 mb s3://my-bucket
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://my-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 ls s3://my-bucket/
aws --endpoint-url http://localhost:9000 s3 rm s3://my-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 rb s3://my-bucket
```

## Roadmap

- Multipart upload, presigned URLs, CopyObject
- CORS, ~~Range headers~~
- Versioning, lifecycle rules
- Multi-user support
- Distributed mode, erasure coding, replication

## Contributing

See [CLAUDE.md](CLAUDE.md) for the full development workflow, architecture details, and testing instructions.

## Core Maintainer

| [<img src="https://github.com/andrasbacsai.png" width="120" /><br />Andras Bacsai](https://github.com/andrasbacsai) |
|---|

## License

[Apache-2.0](LICENSE)
