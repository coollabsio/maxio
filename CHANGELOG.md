# Changelog

All notable changes to MaxIO are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- The console bundle no longer contains the release version. The badge shows `GET /maxio/api/version` only after login. Logout writes every received session cookie to the data directory and clears both `Path=/maxio` and `Path=/`, so a pre-upgrade `Path=/` cookie cannot keep the session alive. A request that still carries a revoked cookie is rejected. Each login gets its own session id. A corrupt, unreadable, or deleted revocation file fails closed (sessions issued at or before that process start are revoked). A new data directory writes an empty revocation file and a marker so a later deletion is not treated as a first start. Logout that cannot save the revocation returns 500 and still revokes the session in memory. Failed console logins are limited to 10 per 5 minutes per client IP and access key. `MAXIO_TRUSTED_PROXY` is off by default.
- A checksum or single-part etag that does not match the payload is quarantined by `check --repair` instead of being adopted. `--accept-current-checksums` records the payload checksum or etag. A multipart etag is info (`multipart etag (not verifiable by MD5)`) and is not counted as an issue. An intact current object is kept when only its archived version copy is corrupt; that copy is rebuilt and the corrupt version file is quarantined. An older version is restored only when the current object is missing or corrupt. Copies that cannot be verified and differ are `unverifiable-divergence` and are left unchanged unless `--accept-unverifiable-current` is set. New flat objects store a SHA-256 of the bytes on disk so later checks can verify them.
- Console login clears a legacy `Path=/` session cookie. Failed logins are limited per access key and per client IP, and the limiter keeps a bounded set of hashed keys.
- Unauthenticated `GET`/`HEAD` under `/ui` is the console even when the query string looks like S3. The console favicon is served from `/ui/`. Console HTML and API responses are `Cache-Control: no-store`.
- `/readyz` and `/minio/health/*` are gone. `/maxio/health/live` and `/maxio/health/ready` are the only health URLs. `readyz` is an ordinary bucket.
- A data directory the process cannot write, including the lock file, names uid 999, `chown`, and `--user`.
- `keyring rotate` and `keyring merge` take the data-directory lock before writing, and refuse while a server holds it.
- A pre-release tag is marked prerelease on the GitHub Release.

## [1.0.0]

### Added

- IAM users, scoped access keys, and bucket policies, in the console and over the API. Access-key secrets are sealed in `<data-dir>/iam.json` with the SSE-S3 master key. Back that file up with `.maxio-keys.json`
- Virtual-hosted bucket URLs (`--domain`)
- `maxio check` and `maxio check --repair` for crash leftovers, and `maxio keyring merge` to put a recovered key back into the keyring
- SSE-S3 key safety: MaxIO will not mint a new master key over existing encrypted objects or sealed IAM secrets
- Request limits and a graceful drain on SIGINT and SIGTERM
- On-disk format marker `<data-dir>/.maxio-format`. This release writes version 2. A directory with no marker, or with format 1, is upgraded in place: object bytes and `iam.json` are not rewritten. `serve`, `check --repair`, and `keyring merge` run that upgrade. Read-only `check` does not write the marker
- Format 2 is the key-and-prefix layout. A key that is also a prefix is stored at `<key>/.maxio.object`. A build that only understands format 1 refuses a version 2 directory instead of opening that path as a file. Format 3 and newer is refused by this binary
- React web console with a generated OpenAPI client
- Bucket lifecycle, bucket tags, anonymous read/list, and streaming trailer checksums
- The console API is `/maxio/api/*`, including `GET /maxio/api/version`. That route requires a console session and is what the console badge shows. Unauthenticated callers get 401. There is no `/api` alias. `GET` and `HEAD /maxio/health/live` and `/maxio/health/ready` are unauthenticated and report status only, never the version. The bucket names `maxio` and `ui` are reserved (`ui` is also shorter than an S3 bucket name, so it cannot be a working bucket). An existing `buckets/maxio` or `buckets/ui` directory refuses startup. Buckets named `api`, `version`, and `healthz` are ordinary buckets. An unauthenticated browser `GET` or `HEAD` of `/ui` without an S3 query is the console. The session cookie path is `/maxio`
- Release binaries for Linux (static musl) and macOS, with SHA256 checksums, multi-arch container images, and changelog-backed GitHub Release notes

### Fixed

- Console sign-in on plain localhost, and the content security policy for the Geist font
- Atomic object writes and multipart validation

## [0.4.2] - 2026-05-27

### Changed

- Listen on all interfaces by default
- Document the health check command and the secure-cookie behavior

### Fixed

- Pull-request CI covers formatting, Clippy, the frontend, and the generated API client

## [0.4.0] - 2026-05-26

### Added

- Server-side encryption (SSE-S3 and SSE-C), including with erasure coding
- Anonymous public read and list via a bucket policy
- Buckets created at startup from `MAXIO_DEFAULT_BUCKETS`
- Web console settings for versioning, encryption, and public access

### Changed

- Console uses the Coolify v4.5 layout, Geist, and stricter default credentials
- Bucket name checks are the same on every API

### Fixed

- Deleting an object in a missing bucket returns 404
- Console object keys keep `/` as a path separator

## [0.3.2] - 2026-03-24

### Changed

- Larger buffered reads and writes, and streaming for small objects

## [0.3.1] - 2026-03-24

### Added

- `partNumber` on `GetObject` for one part of a completed multipart object

## [0.3.0] - 2026-03-23

### Added

- Bucket CORS
- Object tagging
- macOS arm64 release builds

## [0.2.1] - 2026-03-06

### Added

- `GET /healthz` and `maxio healthcheck`
- MinIO-compatible root credential environment variables

### Fixed

- Presigned URL signatures and wget/curl downloads

## [0.2.0] - 2026-02-20

### Added

- Checksum verification
- Optional erasure coding

## [0.1.0] - 2026-02-18

### Added

- S3-compatible server: buckets, objects, multipart upload, CopyObject, presigned URLs
- Versioning, range reads, and folder markers
- Web console embedded in the binary
- Container image and a tag-triggered release workflow

[Unreleased]: https://github.com/coollabsio/maxio/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/coollabsio/maxio/compare/v0.4.0...v0.4.2
[0.4.0]: https://github.com/coollabsio/maxio/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/coollabsio/maxio/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/coollabsio/maxio/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/coollabsio/maxio/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/coollabsio/maxio/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/coollabsio/maxio/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/coollabsio/maxio/releases/tag/v0.1.0
