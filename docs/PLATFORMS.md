# Supported platforms

MaxIO 1.0.0 publishes four release binaries and a multi-arch container image.

| Platform | Artifact | Notes |
|---|---|---|
| Linux x86_64 | `maxio-linux-amd64-<version>.tar.gz` | Static musl binary. No libc install required |
| Linux aarch64 | `maxio-linux-arm64-<version>.tar.gz` | Static musl binary |
| macOS Intel | `maxio-macos-amd64-<version>.tar.gz` | x86_64 |
| macOS Apple Silicon | `maxio-macos-arm64-<version>.tar.gz` | aarch64 |
| Containers | `linux/amd64` and `linux/arm64` | Debian-based image. One manifest covers both architectures |

Container registries:

- `ghcr.io/coollabsio/maxio`
- `docker.io/coollabsio/maxio`

Tags:

| Tag | What it is |
|---|---|
| `1.0.0` | Multi-arch manifest for that version. Pin this in production |
| `latest` | Multi-arch manifest of the newest release |
| `1.0.0-amd64`, `1.0.0-aarch64` | Single-architecture images used to build the manifest |

`SHA256SUMS` is attached to the GitHub Release. Check an archive before you unpack it:

```bash
sha256sum -c SHA256SUMS
tar -xzf maxio-linux-amd64-1.0.0.tar.gz
./maxio --version
```

## Building from source

`Cargo.toml` `rust-version` is **1.89** (the oldest compiler this crate claims to support). CI, the release workflow, and the container image build with the pinned toolchain in `rust-toolchain.toml`, currently **1.97.1**. A source build needs that toolchain (or any newer one) and bun 1.4.4. `cargo build --release` produces a binary for the host (glibc on typical Linux installs, not the musl artifact).

Windows binaries are not published. The SSE-S3 key file is created with mode `0600` on Unix only; on Windows you would have to restrict access yourself.

## What a release does not include

Distributed mode and replication are not part of this release. One MaxIO process owns one data directory.
