set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Install UI dependencies and build the UI.
setup:
    cargo --version
    bun --version
    cd ui && bun install --frozen-lockfile
    cd ui && bun run build

# Hot-reload dev: Rust server (cargo watch) + Vite at http://127.0.0.1:5190/ui/
dev:
    bash scripts/dev.sh

test:
    just version-check
    cargo test
    cd ui && bun run test

version-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n1)
    ui_version=$(bun -e 'console.log(require("./ui/package.json").version)')
    test -n "$cargo_version"
    test "$ui_version" = "$cargo_version" || {
        echo "version mismatch: Cargo is $cargo_version, ui/package.json is $ui_version" >&2
        exit 1
    }
    if [ -e ui/src/version.ts ]; then
        echo "ui/src/version.ts must not exist; the console badge reads /maxio/api/version" >&2
        exit 1
    fi

# Fail when a built console asset contains the Cargo version.
dist-version-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n1)
    test -n "$cargo_version"
    if [ ! -d ui/dist ]; then
        echo "ui/dist is missing; build the console before this check" >&2
        exit 1
    fi
    if grep -R -F -n --binary-files=text -e "$cargo_version" ui/dist; then
        echo "ui/dist contains Cargo version $cargo_version; the console must not ship it" >&2
        exit 1
    fi

# Full gate (same as CI).
check:
    just version-check
    cd ui && bun run build
    just dist-version-check
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test
    cd ui && bun run lint
    cd ui && bun run test
    just api-check

# Regenerate the OpenAPI document and the typed UI client.
api:
    SKIP_FRONTEND=1 cargo run -q -- openapi --output ui/src/api/generated/openapi.json
    cd ui && bun run api:generate

# Fail when the committed UI client is out of date with the Rust handlers.
api-check:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(mktemp -d)
    trap 'rm -rf "$out"' EXIT
    SKIP_FRONTEND=1 cargo run -q -- openapi --output "$out/openapi.json"
    (cd ui && bun run scripts/generate-api.ts "$out/openapi.json" "$out")
    diff -ru ui/src/api/generated "$out" || {
        echo "UI API client is stale. Run: just api" >&2
        exit 1
    }

# Ceph s3-tests against a local MaxIO. See docs/s3-compatibility.md.
s3-compat:
    bash tests/s3_compat.sh

# Playwright e2e against a fresh server on port 9876.
e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    data_dir=$(mktemp -d)
    cargo build
    ./target/debug/maxio --data-dir "$data_dir" --address 127.0.0.1 --port 9876 --allow-insecure-dev &
    server_pid=$!
    trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; rm -rf "$data_dir"' EXIT
    for _ in $(seq 1 50); do
        curl -fsS http://127.0.0.1:9876/healthz >/dev/null 2>&1 && break
        sleep 0.2
    done
    cd ui && MAXIO_E2E_URL=http://127.0.0.1:9876 bun x playwright test

# Rewrite CHANGELOG.md from conventional commits (review the diff before committing).
changelog:
    git cliff --output CHANGELOG.md

# Print the Keep a Changelog section for a version (`1.0.0` or `v1.0.0`).
release-notes version:
    bash scripts/release-notes.sh {{version}}

# Release binary with the UI embedded.
build:
    cd ui && bun run build
    cargo build --release --locked
