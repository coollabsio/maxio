<div align="center">

# MaxIO

S3-compatible object storage server — single-binary replacement for MinIO.

</div>

Version 1.0.0 is the first release intended for production. Read the [production checklist](docs/PRODUCTION.md) before storing data you need to keep: TLS, your own credentials, and backups of the data directory together with the SSE-S3 key file.

MaxIO is a lightweight S3-compatible object storage server written in Rust. One binary, one data directory, no database. Buckets are directories and objects are files, so a backup is a copy of the data dir.

- Works with `mc`, AWS CLI, and any S3 SDK (AWS Signature V4, presigned URLs, path-style and virtual-hosted-style)
- Built-in web console at `/ui/`
- Multipart upload, versioning, tagging, CORS, range and conditional requests, checksums
- Server-side encryption (SSE-S3, SSE-C) and optional erasure coding

See [COMPATIBILITY.md](COMPATIBILITY.md) for the full list of supported S3 and MinIO features.

- [Supported platforms](docs/PLATFORMS.md)
- [Upgrade and rollback](docs/UPGRADE.md)
- [Production checklist](docs/PRODUCTION.md)
- [Cutting a release](docs/RELEASING.md)

## Quick Start

The web console is at `http://localhost:9000/ui/`.

Sign-in sticks on plain `http://localhost`, `http://127.0.0.1`, and `http://[::1]`. The session cookie is marked `Secure` when the request is HTTPS (`X-Forwarded-Proto: https`) or the host is anything else, so a public HTTP listener does not store a console session. A TLS proxy must forward `X-Forwarded-Proto: https`. To allow the console over plain HTTP on a non-loopback host, set `MAXIO_SECURE_COOKIES=false` (anyone on that network can read the session).

The server refuses to start with the built-in `maxioadmin` / `maxioadmin` keys. Set your own keys, as below. `--allow-insecure-dev` keeps those defaults and also omits `Secure` on every host; use it only on a machine you trust.

### Docker

```bash
# Local credentials for this server. The secret is generated, not a shared default.
export MAXIO_ACCESS_KEY="local-admin"
export MAXIO_SECRET_KEY="$(openssl rand -hex 24)"

# Named volume. The image runs as uid 999, which can write a volume Docker creates.
docker run -d --name maxio -p 9000:9000 -v maxio-data:/data \
  -e MAXIO_ACCESS_KEY -e MAXIO_SECRET_KEY \
  ghcr.io/coollabsio/maxio

printf 'Open http://localhost:9000/ui/ and sign in with %s / %s\n' \
  "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
```

A bind mount of a directory you create (`-v "$(pwd)/data:/data"`) is often root-owned, and the process then fails with `failed to update the on-disk format marker` / `Permission denied`. Either hand the directory to the container user first:

```bash
mkdir -p data
sudo chown 999:999 data
docker run -d --name maxio -p 9000:9000 -v "$(pwd)/data:/data" \
  -e MAXIO_ACCESS_KEY -e MAXIO_SECRET_KEY \
  ghcr.io/coollabsio/maxio
```

or run as your own user so the files stay yours: `--user "$(id -u):$(id -g)"`.

Images are on [GHCR](https://ghcr.io/coollabsio/maxio) and Docker Hub (`coollabsio/maxio`).

### Build from source

Install [Rust](https://rustup.rs) **1.89** or newer (`rust-version` in `Cargo.toml`). This repository, CI, and the container image pin **1.97.1** in `rust-toolchain.toml`. You also need [bun](https://bun.sh) **1.4.2**. `cargo build` runs bun to compile the web console and embed it in the binary.

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
| `MAXIO_DOMAIN` | _(none)_ | Comma-separated base domains for virtual-hosted-style (`<bucket>.<domain>`). Alias: `MINIO_DOMAIN`. Unset keeps every host on path-style |

Each variable also has a CLI flag (for example `--port`, `--domain`). Run `maxio --help` for the full list.

## Virtual-hosted-style addressing

Path-style (`http://s3.example.com/bucket/key`) works with no extra configuration. Many SDKs and tools default to virtual-hosted-style (`http://bucket.s3.example.com/key`). Enable that by naming the base domain:

```bash
maxio --domain s3.example.com --data-dir ./data --port 9000
# or several domains:
# MAXIO_DOMAIN=s3.example.com,s3.example.org
```

A request whose `Host` is `<bucket>.<domain>` (a port is ignored, and the host is matched case-insensitively) is served from that bucket. The bare domain, an IP address, and any other host stay on path-style, so the web console (`/ui/`), `/maxio/api/`, `/maxio/health/*`, and `/minio/health/*` on the service host are unchanged. The bucket names `maxio` and `ui` are reserved. `api` is an ordinary bucket. Bucket names follow the S3 rules (lowercase letters, digits, dots, and hyphens, 3–63 characters). A dotted name such as `my.bucket` is the host `my.bucket.s3.example.com`. `ui.<domain>` is rejected with `InvalidBucketName`, the same as `maxio.<domain>`.

The console UI stays at `/ui`. An unauthenticated browser `GET` or `HEAD` of `/ui` or `/ui/...` is the console when the request has no `Authorization` header, no `x-amz-*` header, no `X-Amz-*` presign query, and no S3 subresource or listing query. Any other request for that path is handled as S3 and fails because `ui` is not a valid bucket name. A working bucket named `ui` is not possible: S3 names are at least 3 characters, and that path is the console. `CreateBucket` returns `400 InvalidBucketName`. A data directory that already contains `buckets/ui` or `buckets/maxio` refuses to start; `maxio check` reports it and does not delete it. The console API is only `/maxio/api/*`. The session cookie uses `Path=/maxio`.

When more than one domain is configured, the longest match wins. `album.s3.example.com` is bucket `album` under `s3.example.com`, and the host `s3.example.com` itself stays the service host.

### DNS

Point the base name and a wildcard at the server:

```text
s3.example.com.      A     203.0.113.10
*.s3.example.com.    A     203.0.113.10
```

For a local process, `--domain localhost` is enough on resolvers that answer `*.localhost` with `127.0.0.1` (common on macOS and systemd-resolved). If `bucket.localhost` does not resolve, add the names you use to `/etc/hosts`, or run a wildcard resolver.

### TLS

Terminate TLS in front of MaxIO. A certificate for `*.s3.example.com` covers a single extra label (`photos.s3.example.com`). Add the apex `s3.example.com` to the same certificate so the console, health checks, and path-style clients can use HTTPS on the base name. A dotted bucket adds another label (`my.bucket.s3.example.com`); list each dotted name you serve on the certificate, or use path-style for those buckets.

### Reverse proxy

Preserve the client `Host` so SigV4 still sees the host that was signed:

```nginx
proxy_set_header Host $http_host;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $http_host;
```

`$http_host` includes a non-default port. Overwrite `X-Forwarded-Host`; do not append a client-supplied value.

If the proxy replaces `Host` with the upstream address, set `X-Forwarded-Host` to the original `Host`. MaxIO uses that value for virtual-host routing and for the signed `host` header only when `Host` itself is not already a configured domain or `<bucket>.<domain>`. A request to the bare domain keeps path-style even if a client sends `X-Forwarded-Host`.

### Clients

```bash
# AWS CLI. Put this in the config file used by AWS_CONFIG_FILE.
# [default]
# region = us-east-1
# s3 =
#     addressing_style = virtual
aws --endpoint-url http://s3.example.com:9000 s3 cp file.txt s3://my-bucket/file.txt

# mc bucket lookup over DNS (virtual-hosted-style)
mc alias set maxio http://s3.example.com:9000 "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY" --api S3v4 --path off
mc cp file.txt maxio/my-bucket/file.txt
```

Path-style clients keep working against the same server: leave `addressing_style` unset (or `path`) and point `mc` at the base URL without `--path off`.

AWS CLI and `mc` send dotted bucket names as path-style even when virtual addressing is selected. MaxIO accepts that, and it also accepts a dotted name as `<dotted-name>.<domain>` when a client addresses it that way.

## SSE-S3 master keys

SSE-S3 objects are encrypted with a per-object data key. That data key is wrapped by a 32-byte master key. Losing every copy of the master key makes those objects unrecoverable. MaxIO does not escrow it.

On first start, when `<data-dir>/.maxio-keys.json` does not exist and the data directory has no SSE-S3 objects and no key check file, MaxIO generates a master key and writes it to that file (mode `0600` on Unix, created atomically and fsynced). Back this file up **outside** the data directory. `<data-dir>/.maxio-key-check.json` stays with the data. It stores a check value per key id, whether that key lives in `.maxio-keys.json` (`on-disk`) or was supplied from outside (`external`), and no key material. Do not delete it to "fix" a startup error.

If the key file is missing, MaxIO refuses to start when encrypted object metadata is present, and also when the key check file records key ids even if every object has been deleted. The error names which of those it found. A loaded key that does not match a check value also refuses to start. An unreadable or corrupt key file is never overwritten.

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

`--allow-missing-master-key` starts anyway when the key is absent. Objects encrypted with the missing key stay unreadable, and the flag is required on every later start until the original key is restored. It does not override an unreadable key file or a check value that does not match the key you did load. The flag writes a new `.maxio-keys.json`. Objects created after that use the new key, and the check file still names the original key ids.

### Recovering both keys

Do not copy the original `.maxio-keys.json` over the new file. That drops the new key, and the next start fails with `data directory requires key ids [...]`.

Merge the backup into the current keyring. Keys already on disk stay, including the new active key. Restart after the merge. Both sets of objects decrypt.

```bash
maxio keyring merge --data-dir /var/lib/maxio --from /backup/.maxio-keys.json
```

If the backup was already copied over the new file, put that new file back the same way (`--from` the saved copy of the new keyring). Without a copy of the new key, objects written after `--allow-missing-master-key` cannot be decrypted. `maxio keyring list` prints ids only.

## Usage

```bash
# MAXIO_ACCESS_KEY and MAXIO_SECRET_KEY are the values exported in Quick Start.
mc alias set maxio http://localhost:9000 "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
mc mb maxio/my-bucket
mc cp file.txt maxio/my-bucket/
```

## Identity and access

The root access key (`MAXIO_ACCESS_KEY` / `MAXIO_SECRET_KEY`) is the administrator. Additional callers are IAM users or standalone service keys. Policies are AWS-style JSON: `Effect`, wildcard actions such as `s3:Get*`, and resource ARNs such as `arn:aws:s3:::bucket` and `arn:aws:s3:::bucket/prefix/*`. An explicit `Deny` wins. Built-in policies are `readonly`, `readwrite`, `writeonly`, and `admin`.

A prefix in the console scope picker is a directory. `uploads` and `uploads/` both allow `bucket/uploads/file` and do not allow `bucket/uploads-private` or `bucket/uploadsX`, because that picker writes `prefix/*`. A policy written with AWS wildcard syntax is stored as given: `prefix*` matches any key that starts with that text, including `uploadsY.txt` and `2026-01.csv`.

Create a user and a key with the AWS CLI (the key secret is printed once):

```bash
aws --endpoint-url http://localhost:9000 iam create-user --user-name alice
aws --endpoint-url http://localhost:9000 iam attach-user-policy \
  --user-name alice --policy-arn arn:aws:iam::000000000000:policy/readonly
aws --endpoint-url http://localhost:9000 iam create-access-key --user-name alice
```

A key policy only narrows what that user's policies already allow. Granting access is a separate step: attach a policy, or use **Grant scope to user** in the console (or `PUT /maxio/api/iam/users/{name}/inline/{policy}`). **Create access key** (`POST /maxio/api/iam/users/{name}/keys`) never adds a policy to the user. The scope is stored on that key only. Omitting `keyOnly` means key-only. Sending `keyOnly: false` is rejected.

The console at `/ui/users` and `/ui/policies` is available to root and to anyone whose policy allows IAM administration. Other IAM users can sign in and see only the buckets their policy allows.

Access-key secrets in `<data-dir>/iam.json` are sealed with the SSE-S3 master key (`.maxio-keys.json`, `MAXIO_MASTER_KEY`, or `MAXIO_MASTER_KEY_FILE`). Back the keyring and `iam.json` up together. If `iam.json` has secrets and the master key is missing or is a different key, MaxIO refuses to start instead of serving requests that fail later. A new keyring cannot decrypt the old secrets. Restore the keyring file, or pass the original key with `--master-key` / `MAXIO_MASTER_KEY` or `--master-key-file` / `MAXIO_MASTER_KEY_FILE`. `maxio keyring merge` keeps those secrets readable: keys already in the data directory stay, including the key that sealed `iam.json`.

## Durability

Object bytes, sidecars, multipart parts, version files, and bucket configuration are published with a temp file, `fsync`, rename, and a directory `fsync`. A crash during a write leaves the previous object in place, or a temp file that is not part of the bucket listing.

On startup MaxIO deletes those temp files, restores or drops stranded erasure-coded publish backups, restores object bytes left in a `.maxio-promote-*` directory, and removes multipart uploads whose metadata never landed. Uploads that have readable metadata are kept so a client can finish them. An hourly sweep aborts uploads that have been idle for 7 days and deletes temp files older than a day (a live upload is younger than that). Promote directories newer than an hour are left for that sweep so it does not race a promotion that is still running; startup does not wait.

### Key and prefix layout

S3 keys are a flat namespace, so `photos/cat.jpg` and `photos/cat.jpg/thumb` can both exist. MaxIO stores the first object's bytes at `photos/cat.jpg/.maxio.object` and keeps the sidecar next to that directory (`photos/cat.jpg.meta.json`). The sidecar is where an SSE-S3 wrapped data key lives.

This layout is one-way. A data directory written by this version is not readable by older MaxIO builds: GET of a promoted key returns `InternalError`, because those builds open the key path as a file and the path is now a directory. Stay on this version, or a newer one, to read those objects. Do not point an older binary at a data directory that already contains promoted keys.

A crash during the promotion parks the bytes in `.maxio-promote-<id>/.maxio.object` and records the key name in that directory. Startup and `maxio check --repair` move the bytes back to the key, or into `<key>/.maxio.object` when that directory already exists. `maxio check` reports the leftover, including `.maxio-promote-target` and `.maxio-promote-ready` files left inside the published directory. It does not delete the sidecar while a promote directory for that key is still there.

Object keys cannot use those internal names as a path segment (`.maxio.object`, `.maxio-promote-*`, `.maxio-tmp-*`, `.maxio-bak-*`, `.maxio-quarantine`, and the other layout names). Matching is ASCII case-insensitive, so `p/.MAXIO.OBJECT` is rejected too. A write returns `400 InvalidArgument`. A read returns `NoSuchKey`. That stops a client from overwriting `p`'s bytes by putting `p/.maxio.object`.

Objects created by a pre-1.0 build may already use those names. MaxIO refuses to start when it finds one, and `maxio check` reports it as `legacy-reserved-key` without modifying the files. Rename or delete the keys with the previous version (`aws s3 mv`), then start this version. See [UPGRADE.md](UPGRADE.md).

Back up the data directory and the SSE-S3 master key. That key is `<data-dir>/.maxio-keys.json` unless you set `MAXIO_MASTER_KEY` or `MAXIO_MASTER_KEY_FILE`, which stay outside the data directory. Losing the key makes SSE-S3 objects unrecoverable.

The server holds an exclusive lock on `<data-dir>/.maxio.lock` until it exits. The lock is released on shutdown and when the process crashes, so a restart is not blocked.

### `maxio check`

Stop the server before `--repair`. A read-only scan can run while the server is up and warns that the result can race with in-flight writes. `--repair` and `keyring merge` refuse to run while the server holds the data-directory lock.

If SSE-S3 uses an external master key, pass it the same way the server does (`--master-key`, `--master-key-file`, `MAXIO_MASTER_KEY`, or `MAXIO_MASTER_KEY_FILE`). A matching key is not a finding. When the check file says the key is external, or when that file was written before it recorded a source, passing no key prints a note and still exits 0. When the check file says the key was on disk and `.maxio-keys.json` is missing, check exits 1: that key cannot be recovered. A wrong key is an error, and `--repair` cannot invent the key.

```bash
maxio check --data-dir ./data
maxio check --data-dir ./data --repair
```

The report lists stale temp files, stranded backups, promote directories and leftover promote marker files, object bytes without a sidecar, sidecars without bytes, plain-object size / etag / checksum mismatches, multipart debris, and erasure-coded chunks that do not match their manifest. Exit status is 1 when anything is still unresolved.

`--repair` fixes the cases that are determined by the bytes already on disk:

- delete temp files and finished publish backups; restore a backup when the live object is missing
- restore object bytes stranded in a `.maxio-promote-*` directory (back to the key, or into `<key>/.maxio.object` if that directory exists) and remove the directory. Remove `.maxio-promote-target` and `.maxio-promote-ready` files left inside a published key directory
- move object bytes that have no sidecar to `<data-dir>/.maxio-quarantine/<bucket>/<path>` and say so in the report. Those bytes are not given a new sidecar: they may be SSE-S3 ciphertext, and serving them as a plain object would return the ciphertext with no encryption headers. Copy a quarantined file back by hand if you know which object it belongs to
- delete a sidecar whose bytes are gone, and delete a multipart upload that has no readable metadata. A sidecar is kept when a promote directory for that key still exists
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
