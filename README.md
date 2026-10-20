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
| `MAXIO_MASTER_KEY` | _(auto)_ | Base64 32-byte SSE-S3 master key. Not written into the data directory. See [SSE-S3 master keys](#sse-s3-master-keys) |
| `MAXIO_MASTER_KEY_FILE` | _(none)_ | File containing that key (base64, or 32 raw bytes), kept outside the data directory |
| `MAXIO_ALLOW_MISSING_MASTER_KEY` | `false` | Start even if SSE-S3 objects exist and their master key is missing. Those objects stay unreadable. Pass it on every start until the key is restored |
| `MAXIO_MAX_CONSOLE_BODY_BYTES` | `1048576` | Max body size for console JSON routes |

Each variable also has a CLI flag (for example `--port`). Run `maxio --help` for the full list.

## SSE-S3 master keys

SSE-S3 objects are encrypted with a per-object data key. That data key is wrapped by a 32-byte master key. Losing every copy of the master key makes those objects unrecoverable. MaxIO does not escrow it.

On first start, when `<data-dir>/.maxio-keys.json` does not exist and the data directory has no SSE-S3 objects, MaxIO generates a master key and writes it to that file (mode `0600` on Unix, created atomically and fsynced). Back this file up **outside** the data directory. `<data-dir>/.maxio-key-check.json` stays with the data. It stores a check value per key id and no key material. Do not delete it to "fix" a startup error.

If the key file is missing or the loaded key does not match the check value, and encrypted objects are present, MaxIO refuses to start and does not generate a replacement key. An unreadable or corrupt key file is never overwritten.

```bash
# Generate a key outside the data directory. The shell variable is local to this command.
umask 077
openssl rand -base64 32 > /secure/maxio-master.key

# Use it on every start. It is not copied into the data directory.
export MAXIO_MASTER_KEY_FILE=/secure/maxio-master.key
# equivalent: export MAXIO_MASTER_KEY="$(cat /secure/maxio-master.key)"
./maxio --data-dir /var/lib/maxio --master-key-file /secure/maxio-master.key
```

Set only one of `MAXIO_MASTER_KEY` and `MAXIO_MASTER_KEY_FILE`. The value is standard base64 that decodes to 32 bytes (a trailing newline is fine), or a file of exactly 32 raw bytes. When an external key is set, keys already in `.maxio-keys.json` are still used to read older objects.

### Backup and restore

1. Back up `.maxio-keys.json` (and any external key file) whenever you back up the data directory, including after `maxio keyring rotate`.
2. On the new host, put the key file back at `<data-dir>/.maxio-keys.json` **or** pass the same `--master-key` / `--master-key-file`, then start.
3. Copy `.maxio-key-check.json` with the data directory. It is not a substitute for the key.

`maxio keyring list --data-dir <dir>` prints key ids only. `maxio keyring rotate --data-dir <dir>` adds a new active key and keeps the previous ones so existing objects still decrypt. Restart after rotating. Rotate refuses to create a new keyring when encrypted objects exist and the key file is missing.

If the key file's mode is looser than `0600`, startup logs a warning and continues. Restrict it with `chmod 600`.

`--allow-missing-master-key` starts anyway when the key is absent. Objects encrypted with the missing key stay unreadable, and the flag is required on every later start until the original key is restored. It does not override an unreadable key file or a check value that does not match the key you did load.

## Usage

```bash
# MAXIO_ACCESS_KEY and MAXIO_SECRET_KEY are the values exported in Quick Start.
mc alias set maxio http://localhost:9000 "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
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
