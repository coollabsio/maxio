#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-9000}"
HOST="${HOST:-127.0.0.1}"
DATA_DIR="${DATA_DIR:-./data}"
WEB_PORT="${MAXIO_DEV_WEB_PORT:-5190}"
UI_URL="http://127.0.0.1:$WEB_PORT/ui/"

command -v bun >/dev/null 2>&1 || {
  echo "bun is required for frontend dev." >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || {
  echo "cargo is required for backend dev." >&2
  exit 1
}

cargo watch --version >/dev/null 2>&1 || {
  echo "cargo-watch is required. Install it with: cargo install cargo-watch" >&2
  exit 1
}

frontend_pid=""
backend_pid=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$frontend_pid" ]]; then kill "$frontend_pid" 2>/dev/null || true; fi
  if [[ -n "$backend_pid" ]]; then kill "$backend_pid" 2>/dev/null || true; fi
  wait "$frontend_pid" "$backend_pid" 2>/dev/null || true
  exit "$status"
}

trap cleanup EXIT INT TERM

echo "MaxIO dev mode"
echo "Open: $UI_URL"
if command -v tailscale >/dev/null 2>&1; then
  ts_host="$(tailscale status --json 2>/dev/null | sed -n 's/.*"DNSName": "\([^"]*\)\.".*/\1/p' | head -n1)"
  if [[ -n "$ts_host" ]]; then
    echo "Tailnet: https://$ts_host:$WEB_PORT/ui/ (needs: tailscale serve --bg --https=$WEB_PORT http://127.0.0.1:$WEB_PORT)"
  fi
fi
echo

(
  cd "$ROOT/ui"
  exec env MAXIO_DEV_WEB_PORT="$WEB_PORT" PORT="$PORT" bun run dev
) &
frontend_pid=$!

(
  cd "$ROOT"
  exec env \
    RUST_LOG="${RUST_LOG:-debug}" \
    SKIP_FRONTEND=1 \
    cargo watch \
      -w src \
      -w Cargo.toml \
      -w Cargo.lock \
      -w build.rs \
      -i target \
      -x "run -- --address $HOST --data-dir $DATA_DIR --port $PORT --allow-insecure-dev"
) &
backend_pid=$!

while true; do
  if ! kill -0 "$frontend_pid" 2>/dev/null; then wait "$frontend_pid"; exit $?; fi
  if ! kill -0 "$backend_pid" 2>/dev/null; then wait "$backend_pid"; exit $?; fi
  sleep 1
done
