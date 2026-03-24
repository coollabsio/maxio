#!/usr/bin/env bash
set -euo pipefail

# Run MaxIO vs MinIO benchmark on a remote server.
# Usage: ./tests/bench-remote.sh user@host [bench.sh options...]
#
# This script:
#   1. Copies bench.sh to the server
#   2. bench.sh auto-downloads maxio, warp, and minio binaries
#   3. Runs benchmarks and streams results back
#   4. Cleans up everything on the server
#
# Prerequisites: SSH access to the server (key-based auth recommended)

red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

if [ $# -lt 1 ] || [ "$1" = "--help" ]; then
    echo "Usage: ./tests/bench-remote.sh user@host [bench.sh options...]"
    echo ""
    echo "Examples:"
    echo "  ./tests/bench-remote.sh root@bench-server"
    echo "  ./tests/bench-remote.sh root@bench-server --duration=60s"
    echo "  ./tests/bench-remote.sh root@bench-server --scenarios=put-small,mixed"
    exit 0
fi

SSH_TARGET="$1"
shift
BENCH_ARGS="$*"
REMOTE_DIR="/tmp/maxio-bench"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Copy bench.sh to server ---
bold "Copying bench.sh to $SSH_TARGET..."
ssh "$SSH_TARGET" "mkdir -p $REMOTE_DIR"
scp -q "$SCRIPT_DIR/bench.sh" "$SSH_TARGET:$REMOTE_DIR/bench.sh"
ssh "$SSH_TARGET" "chmod +x $REMOTE_DIR/bench.sh"
green "  Done"

# --- Run benchmark (maxio, warp, minio are all auto-downloaded) ---
bold "Running benchmark on $SSH_TARGET..."
echo ""
ssh -t "$SSH_TARGET" "cd $REMOTE_DIR && ./bench.sh $BENCH_ARGS"

# --- Cleanup remote ---
ssh "$SSH_TARGET" "rm -rf $REMOTE_DIR" 2>/dev/null || true
