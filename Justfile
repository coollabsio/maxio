# Start dev environment (Rust server + UI watcher)
dev port='9000':
    #!/usr/bin/env bash
    set -e
    trap 'kill 0' EXIT
    cd ui && bun run build -- --watch &
    RUST_LOG=debug cargo watch -x 'run -- --data-dir ./data --port {{port}}' &
    wait

# Run WARP benchmarks comparing MaxIO vs MinIO
bench duration='30s':
    #!/usr/bin/env bash
    set -e
    echo "Building release binary..."
    cargo build --release
    ./tests/bench.sh --duration={{duration}}

# Run a quick smoke benchmark (10s, small + mixed only)
bench-quick:
    #!/usr/bin/env bash
    set -e
    cargo build --release
    ./tests/bench.sh --duration=10s --scenarios=put-small,get-small,mixed

# Run benchmark on a remote Linux server (cross-compiles + auto-downloads deps)
bench-remote host duration='30s':
    ./tests/bench-remote.sh {{host}} --duration={{duration}}
