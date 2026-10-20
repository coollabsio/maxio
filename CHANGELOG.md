# Changelog

All notable changes to MaxIO are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `GET /api/version` requires a console session and is what the console badge shows. Unauthenticated callers get 401. `GET` and `HEAD /maxio/health/live` and `/maxio/health/ready` are unauthenticated and report status only, never the version. The bucket name `maxio` is reserved. Buckets named `version` and `healthz` are ordinary buckets
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
