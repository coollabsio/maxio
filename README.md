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

## Identity and access

The root access key (`MAXIO_ACCESS_KEY` / `MAXIO_SECRET_KEY`) is the administrator. Additional callers are IAM users or standalone service keys. Policies are AWS-style JSON: `Effect`, wildcard actions such as `s3:Get*`, and resource ARNs such as `arn:aws:s3:::bucket` and `arn:aws:s3:::bucket/prefix/*`. An explicit `Deny` wins. Built-in policies are `readonly`, `readwrite`, `writeonly`, and `admin`.

A prefix in the console is a directory. `uploads` and `uploads/` both allow `bucket/uploads/file` and do not allow `bucket/uploads-private` or `bucket/uploadsX`.

Create a user and a key with the AWS CLI (the key secret is printed once):

```bash
aws --endpoint-url http://localhost:9000 iam create-user --user-name alice
aws --endpoint-url http://localhost:9000 iam attach-user-policy \
  --user-name alice --policy-arn arn:aws:iam::000000000000:policy/readonly
aws --endpoint-url http://localhost:9000 iam create-access-key --user-name alice
```

A key policy only narrows what that user's policies already allow. Granting access is a separate step: attach a policy, or use **Grant scope to user** in the console. **Create access key** does not add permissions to the user.

The console at `/ui/users` and `/ui/policies` is available to root and to anyone whose policy allows IAM administration. Other IAM users can sign in and see only the buckets their policy allows.

Access-key secrets in `<data-dir>/iam.json` are sealed with the SSE-S3 master key (`.maxio-keys.json`, or `MAXIO_MASTER_KEY`). Back those two files up together. If `iam.json` has secrets and the master key is missing or is a different key, MaxIO refuses to start instead of serving requests that fail later. A new keyring cannot decrypt the old secrets.

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
