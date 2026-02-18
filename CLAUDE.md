# MaxIO

S3-compatible object storage server written in Rust. Single-binary replacement for MinIO.

## Naming Convention

Always spell the product name **MaxIO** (capital M, capital I, capital O). Never use "Maxio", "maxio", or "MAXIO" in prose. Lowercase `maxio` is acceptable only for CLI binary names, environment variable prefixes (`MAXIO_`), mc aliases, and code identifiers.

## User Preferences

- Use **bun** (not npm) for the `ui/` frontend

## Build & Run

```bash
# Build frontend (required — assets are embedded into the binary)
cd ui && bun run build && cd ..

# Build binary
cargo build --release
./target/release/maxio --data-dir ./data --port 9000
```

Environment variables: `MAXIO_PORT`, `MAXIO_ADDRESS`, `MAXIO_DATA_DIR`, `MAXIO_ACCESS_KEY`, `MAXIO_SECRET_KEY`, `MAXIO_REGION`

## Production Build

The release binary is fully self-contained — the frontend UI is embedded at compile time via `rust-embed`. No external files needed.

```bash
# 1. Install frontend dependencies
cd ui && bun install

# 2. Build frontend (outputs to ui/dist/, required before cargo build)
bun run build && cd ..

# 3. Build optimized binary
cargo build --release

# Result: single binary at ./target/release/maxio
# Copy it anywhere — no ui/dist/ or other files needed at runtime
```

The binary serves the web console at `/ui/` with proper MIME types, ETags, and cache headers (immutable for hashed assets, no-store for `index.html`).

Defaults: port 9000, access/secret `minioadmin`/`minioadmin`, region `us-east-1`

## Development Workflow

**Test-Driven Development (TDD)**: Before implementing any new function or feature, write a failing test first. Then implement until the test passes.

**After every code change**, re-run the full test suite to catch regressions:

```bash
# 1. Unit + integration tests (always run first, no server needed)
cargo test

# 2. mc integration tests (start server, run tests, stop server)
cargo build && RUST_LOG=info ./target/debug/maxio --data-dir /tmp/maxio-test --port 9876 &
./tests/mc_test.sh 9876 /tmp/maxio-test
kill %1 && rm -rf /tmp/maxio-test

# 3. AWS CLI integration tests (start server, run tests, stop server)
cargo build && RUST_LOG=info ./target/debug/maxio --data-dir /tmp/maxio-test --port 9876 &
./tests/aws_cli_test.sh 9876 /tmp/maxio-test
kill %1 && rm -rf /tmp/maxio-test
```

**Hot-reload dev server** (for manual testing):

```bash
just dev
```

This runs both processes concurrently (Ctrl+C kills both):
- `cargo watch` — rebuilds and restarts the Rust server on changes
- `bun run build --watch` — rebuilds `ui/dist/` on frontend changes

## Architecture

### Module Layout

- `src/main.rs` — entry point, config, server start, graceful shutdown
- `src/config.rs` — CLI args + env vars via clap derive
- `src/server.rs` — Axum router construction, AppState, middleware wiring
- `src/error.rs` — S3Error with XML error response rendering
- `src/auth/` — AWS Signature V4 verification + Axum middleware
- `src/api/` — S3 API handlers (bucket.rs, object.rs, multipart.rs, list.rs, router.rs, console.rs)
- `src/storage/` — Filesystem storage (buckets as dirs, objects as files, JSON sidecar metadata)
- `src/xml/` — S3 XML response types (serde + quick-xml)

### Key Design Decisions

- **Pure filesystem storage**: No database. Buckets are directories, objects are files at their key path, metadata in `.meta.json` sidecars. Backup-friendly — just copy the data dir
- **Storage layout**: `{data_dir}/buckets/{bucket-name}/{key-path}` for data, `{key-path}.meta.json` for metadata, `.bucket.json` for bucket metadata
- **Path-style only**: `/{bucket}/{key}` routing. No virtual-hosted-style yet
- **UNSIGNED-PAYLOAD accepted**: Skips body hashing for PutObject (AWS CLI default)
- **Embedded UI assets**: Frontend is compiled into the binary via `rust-embed`. In debug builds, assets are read from disk (`ui/dist/`) for live reload. In release builds, assets are baked in — single binary, no external files needed
- **Web console**: SPA at `/ui/`, API at `/api/`. Cookie-based auth (HMAC tokens, not SigV4). Presigned URL generation with configurable expiry (1h/6h/24h/7d picker in UI)

### Data Layout

```
{data_dir}/
└── buckets/
    └── my-bucket/
        ├── .bucket.json                    # bucket metadata
        ├── .uploads/                       # in-progress multipart uploads
        │   └── {uploadId}/
        │       ├── .meta.json              # MultipartUploadMeta (key, content_type, initiated)
        │       ├── 1                       # part 1 bytes
        │       └── 1.meta.json             # PartMeta (part_number, etag, size)
        ├── photos/
        │   ├── vacation.jpg                # object data
        │   └── vacation.jpg.meta.json      # object metadata (etag, size, content_type, last_modified)
        └── readme.txt
            └── readme.txt.meta.json
```

### S3 Operations Implemented

| Operation | Method | Path |
|---|---|---|
| ListBuckets | GET | `/` |
| CreateBucket | PUT | `/{bucket}` |
| HeadBucket | HEAD | `/{bucket}` |
| DeleteBucket | DELETE | `/{bucket}` |
| GetBucketLocation | GET | `/{bucket}?location` |
| ListObjectsV2 | GET | `/{bucket}?list-type=2` |
| DeleteObjects | POST | `/{bucket}?delete` |
| PutObject | PUT | `/{bucket}/{key}` |
| GetObject | GET | `/{bucket}/{key}` |
| HeadObject | HEAD | `/{bucket}/{key}` |
| DeleteObject | DELETE | `/{bucket}/{key}` |
| CopyObject | PUT | `/{bucket}/{key}` (with `x-amz-copy-source` header) |
| CreateMultipartUpload | POST | `/{bucket}/{key}?uploads` |
| UploadPart | PUT | `/{bucket}/{key}?partNumber=N&uploadId=X` |
| CompleteMultipartUpload | POST | `/{bucket}/{key}?uploadId=X` |
| AbortMultipartUpload | DELETE | `/{bucket}/{key}?uploadId=X` |
| ListParts | GET | `/{bucket}/{key}?uploadId=X` |
| ListMultipartUploads | GET | `/{bucket}?uploads` |

### Console API (`/api/`)

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/auth/login` | POST | none | Login with accessKey/secretKey, sets session cookie |
| `/api/auth/check` | GET | none | Check if session cookie is valid |
| `/api/auth/logout` | POST | cookie | Clear session cookie |
| `/api/buckets` | GET | cookie | List all buckets |
| `/api/buckets` | POST | cookie | Create bucket (`{ name }`) |
| `/api/buckets/{bucket}` | DELETE | cookie | Delete bucket |
| `/api/buckets/{bucket}/objects` | GET | cookie | List objects (`?prefix=&delimiter=`) |
| `/api/buckets/{bucket}/objects/{key}` | DELETE | cookie | Delete object |
| `/api/buckets/{bucket}/upload/{key}` | PUT | cookie | Upload object |
| `/api/buckets/{bucket}/download/{key}` | GET | cookie | Download object |
| `/api/buckets/{bucket}/presign/{key}` | GET | cookie | Generate presigned URL (`?expires=SECONDS`, default 3600, max 604800) |

### Frontend Error Logging

All `fetch` catch blocks in UI components log errors via `console.error` with context (e.g. `'fetchBuckets failed:'`, `'shareObject failed:'`). Check browser DevTools console for debugging.

### Testing with MinIO Client (mc)

```bash
# Install mc
brew install minio/stable/mc

# Configure alias
mc alias set maxio http://localhost:9000 minioadmin minioadmin

# Bucket operations
mc mb maxio/test-bucket
mc ls maxio/

# Upload / download
echo "hello maxio" > /tmp/test.txt
mc cp /tmp/test.txt maxio/test-bucket/test.txt
mc ls maxio/test-bucket/
mc cat maxio/test-bucket/test.txt
mc cp maxio/test-bucket/test.txt /tmp/downloaded.txt

# Nested keys
mc cp /tmp/test.txt maxio/test-bucket/folder/nested/file.txt
mc ls maxio/test-bucket/folder/

# Cleanup
mc rm maxio/test-bucket/test.txt
mc rm maxio/test-bucket/folder/nested/file.txt
mc rb maxio/test-bucket
```

### Testing with AWS CLI

```bash
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
aws --endpoint-url http://localhost:9000 s3 mb s3://test-bucket
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://test-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 ls s3://test-bucket/
aws --endpoint-url http://localhost:9000 s3 cp s3://test-bucket/file.txt downloaded.txt
aws --endpoint-url http://localhost:9000 s3 rm s3://test-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 rb s3://test-bucket
```

### Running Tests

```bash
# Unit + integration tests (no server needed)
cargo test

# mc integration tests (requires running server)
RUST_LOG=debug cargo watch -x 'run -- --data-dir ./data' &
./tests/mc_test.sh

# AWS CLI integration tests (requires running server)
./tests/aws_cli_test.sh
```

## UI Design System

The web console (`ui/`) follows the Coolify design system. The full specification is in [`ui/DESIGN_SYSTEM.md`](ui/DESIGN_SYSTEM.md). Key points:

- **Stack**: Svelte 5, Vite, Tailwind CSS v4, shadcn-svelte components
- **Theme**: Class-based dark mode (`.dark` on `<html>`), with light/dark CSS variable swap in `ui/src/app.css`
- **Accent colors**: Coollabs purple `#6b16ed` (light) / warning yellow `#fcd452` (dark). Brand purple (`--color-brand`) is always `#6b16ed` regardless of theme
- **Font**: Inter (Google Fonts)
- **Inputs**: Inset box-shadow system (4px colored left bar on focus), no standard borders — see `.input-cool` in `app.css`
- **Buttons**: `border-2`, `h-8`, `rounded-sm`. Variants: `default`, `destructive`, `outline`, `secondary`, `ghost`, `link`, `brand`
- **Border radius**: `0.125rem` (2px) everywhere — set via `--radius` in `@theme inline`
- **Sidebar**: Collapsible 224px → 56px icon-only, uses `--cool-sidebar-*` CSS variables

## Roadmap

- **Phase 2**: ~~Multipart upload~~, ~~presigned URLs~~, ~~CopyObject~~, ~~DeleteObjects batch~~, CORS, Range headers
- **Phase 3**: ~~Web console (SPA at `/ui/`)~~, versioning, lifecycle rules, multi-user, metrics
- **Phase 4**: Distributed mode, erasure coding, replication
