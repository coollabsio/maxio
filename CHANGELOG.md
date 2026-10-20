# Changelog

All notable changes to MaxIO are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- React web console with a generated OpenAPI client
- Bucket lifecycle, bucket tags, anonymous read/list policy, and streaming trailer checksums
- On-disk format marker (`.maxio-format`) and a no-op migration hook for future data upgrades. `serve`, `check`, `check --repair`, and `keyring merge` refuse a newer marker
- Format 2 is reserved for the one-way key-and-prefix layout: a key that is also a prefix is stored at `<key>/.maxio.object`. This binary does not write that layout. A directory marked version 2 is refused, so an older build does not open that path as a file
- Virtual-hosted bucket addressing (`--domain`)
- `maxio check`, `maxio check --repair`, and `maxio keyring merge`
- Graceful connection drain on SIGINT and SIGTERM
- `GET /version` and a version field on `GET /healthz`; the same version is shown in the console
- Release binaries for Linux (static musl) and macOS, with SHA256 checksums, multi-arch container images, and changelog-backed GitHub Release notes
- Upgrade guide, supported platforms, and a production deployment checklist

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
