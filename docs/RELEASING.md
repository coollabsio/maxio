# Cutting a release

Versions are [semantic versions](https://semver.org/spec/v2.0.0.html). The number in `Cargo.toml` is the release version. `ui/package.json` (`version`) must match it. The console bundle must not contain that string; the badge reads `GET /maxio/api/version` after login. `just dist-version-check` greps `ui/dist`.

`just version-check` fails when they differ. `maxio --version` prints it. A signed-in console session can read `GET /maxio/api/version`, and the console badge uses that. Unauthenticated health checks are `GET /maxio/health/live` and `/maxio/health/ready`; they report status only.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). While a version is in progress, notes live under `## [Unreleased]`.

Before you tag, rename that heading to the version and add the date:

```markdown
## [1.0.0] - 2026-10-20
```

[git-cliff](https://git-cliff.org/) can draft the file from conventional commits (`cliff.toml`):

```bash
git cliff --unreleased
git cliff --tag v1.0.0 --output CHANGELOG.md
```

`just changelog` rewrites `CHANGELOG.md` from the whole history. Read the diff. The seeded sections for 0.1.0 through 0.4.2 were written by hand; a full rewrite replaces them with one line per commit.

`scripts/release-notes.sh 1.0.0` prints the section the GitHub Release will use. If the version heading is missing, it prints `## [Unreleased]` retitled to that version.

## What the workflow publishes

`.github/workflows/release.yml` runs on a tag `vX.Y.Z`, on `workflow_dispatch`, and on pull requests.

| Event | What it does |
|---|---|
| Pull request | Builds the Linux amd64 musl binary and the amd64 image. Does not push or create a release |
| `workflow_dispatch` with **dry run** on (the default) | Builds every binary and both images. Does not push or create a release |
| Tag `vX.Y.Z`, or a dispatch with dry run off | Builds, pushes images, writes the multi-arch manifests, and creates the GitHub Release |

The tag, or the dispatch version input, must equal `Cargo.toml` (`v1.0.0` for version `1.0.0`).

Binaries:

- `maxio-linux-amd64` and `maxio-linux-arm64` — static musl, built on the matching architecture
- `maxio-macos-amd64` and `maxio-macos-arm64`

Each archive is one file named `maxio`. The release also contains `SHA256SUMS`.

Images, pushed to GHCR and Docker Hub:

- `coollabsio/maxio:<version>-amd64` and `coollabsio/maxio:<version>-aarch64`
- `coollabsio/maxio:<version>` and `coollabsio/maxio:latest` (multi-arch)

## First release

1. Merge the release-engineering changes and anything else that belongs in 1.0.0.
2. Move `## [Unreleased]` to `## [1.0.0] - <date>` and commit on `main`. Confirm `Cargo.toml` is `1.0.0`.
3. In the repository settings, add the Docker Hub secrets the workflow already reads:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN` (a write token for `coollabsio/maxio`, not your password)
4. GHCR uses `GITHUB_TOKEN`. The workflow has `packages: write`. After the first push, the package `ghcr.io/coollabsio/maxio` is private until someone sets its visibility to public.
5. Tag the commit and push the tag. Do not create the tag until you intend to publish.

```bash
git checkout main
git pull
git tag v1.0.0
git push origin v1.0.0
```

6. Watch the Release workflow. When it is green, install from `SHA256SUMS`, run `maxio --version`, and follow [UPGRADE.md](UPGRADE.md) if a data directory already exists.

To rehearse without publishing, open **Actions → release → Run workflow** on the commit you care about, enter `v1.0.0`, and leave **dry run** enabled. That builds the matrix and uploads artifacts. It does not push images or open a GitHub Release.

## Smoke test a locally built image

Build each architecture (the arm64 build uses QEMU when the host is amd64):

```bash
docker buildx build --platform linux/amd64 -t maxio:smoke-amd64 --load .
docker buildx build --platform linux/arm64 -t maxio:smoke-arm64 --load .
```

Start one image with the dev credential switch. The smoke test expects that pair; do not use it outside a local test.

```bash
data="$(mktemp -d)"
docker run -d --name maxio-smoke -p 9000:9000 \
  -v "$data:/data" \
  -e MAXIO_ALLOW_INSECURE_DEV=true \
  maxio:smoke-amd64
MAXIO_SMOKE=1 ./tests/aws_cli_test.sh 9000 "$data"
docker rm -f maxio-smoke
rm -rf "$data"
```

`MAXIO_SMOKE=1` checks `/maxio/health/live`, `.maxio-format`, and one `aws` plus `mc` upload. The rest of `tests/aws_cli_test.sh` is the full suite and runs when the variable is unset.
