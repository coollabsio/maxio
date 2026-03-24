#!/usr/bin/env bash
set -euo pipefail

# MaxIO vs MinIO benchmark using WARP (https://github.com/minio/warp)
# Usage: ./tests/bench.sh [options]
#   --duration=30s       Duration per benchmark (default: 30s)
#   --scenarios=all      Comma-separated: put-small,put-med,put-large,get-small,get-med,mixed,multipart
#   --maxio-host=HOST    Use external MaxIO (skip starting server)
#   --minio-host=HOST    Use external MinIO (skip starting server)
#   --maxio-bin=PATH     Path to maxio binary (default: ./maxio or ./target/release/maxio)
#   --help               Show this help

DURATION="30s"
SCENARIOS="all"
MAXIO_HOST=""
MINIO_HOST=""
MAXIO_BIN=""
MAXIO_PORT=9800
MINIO_PORT=9801
ACCESS_KEY="maxioadmin"
SECRET_KEY="maxioadmin"
OUTDIR=$(mktemp -d /tmp/maxio-bench-XXXXXX)
RESULTS_FILE="$OUTDIR/results.md"
MAXIO_DATA="$OUTDIR/maxio-data"
MINIO_DATA="$OUTDIR/minio-data"
BIN_DIR="$HOME/.cache/maxio-bench/bin"
MAXIO_PID=""
MINIO_PID=""

# --- Colors ---
red()    { printf "\033[31m%s\033[0m\n" "$1"; }
green()  { printf "\033[32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }
bold()   { printf "\033[1m%s\033[0m\n" "$1"; }
dim()    { printf "\033[2m%s\033[0m\n" "$1"; }

# --- Argument parsing ---
for arg in "$@"; do
    case "$arg" in
        --duration=*)  DURATION="${arg#*=}" ;;
        --scenarios=*) SCENARIOS="${arg#*=}" ;;
        --maxio-host=*) MAXIO_HOST="${arg#*=}" ;;
        --minio-host=*) MINIO_HOST="${arg#*=}" ;;
        --maxio-bin=*)  MAXIO_BIN="${arg#*=}" ;;
        --help)
            head -12 "$0" | tail -10
            exit 0
            ;;
        *) red "Unknown argument: $arg"; exit 1 ;;
    esac
done

# Resolve scenario list
ALL_SCENARIOS="put-small put-med put-large get-small get-med mixed multipart"
if [ "$SCENARIOS" = "all" ]; then
    SCENARIOS="$ALL_SCENARIOS"
else
    SCENARIOS=$(echo "$SCENARIOS" | tr ',' ' ')
fi

# --- Platform detection ---
detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
    esac
    echo "${os}-${arch}"
}

PLATFORM=$(detect_platform)

# --- Auto-download dependencies ---
# Add cache dir to PATH so previously downloaded binaries are found
export PATH="$BIN_DIR:$BIN_DIR/go/bin:$PATH"

GO_VERSION="1.25.8"

ensure_go() {
    if command -v go &>/dev/null; then return; fi
    mkdir -p "$BIN_DIR"
    bold "Downloading Go $GO_VERSION..."
    local arch url
    case "$PLATFORM" in
        linux-amd64)  arch="amd64" ;;
        linux-arm64)  arch="arm64" ;;
        darwin-amd64) arch="amd64" ;;
        darwin-arm64) arch="arm64" ;;
        *) red "Unsupported platform: $PLATFORM"; exit 1 ;;
    esac
    local os
    case "$PLATFORM" in
        linux-*)  os="linux" ;;
        darwin-*) os="darwin" ;;
    esac
    url="https://go.dev/dl/go${GO_VERSION}.${os}-${arch}.tar.gz"
    curl -fsSL "$url" | tar xz -C "$BIN_DIR" 2>/dev/null
    export PATH="$BIN_DIR/go/bin:$PATH"
    export GOPATH="$BIN_DIR/gopath"
    green "  Go $GO_VERSION downloaded"
}

ensure_warp() {
    if command -v warp &>/dev/null; then return; fi
    ensure_go
    mkdir -p "$BIN_DIR"
    bold "Building warp from source..."
    export GOPATH="${GOPATH:-$BIN_DIR/gopath}"
    export GOBIN="$BIN_DIR"
    go install github.com/minio/warp@latest 2>&1
    chmod +x "$BIN_DIR/warp"
    green "  warp built"
}

ensure_minio() {
    if [ -n "$MINIO_HOST" ]; then return; fi
    if command -v minio &>/dev/null; then return; fi
    mkdir -p "$BIN_DIR"
    bold "Downloading minio..."
    local os arch url
    case "$PLATFORM" in
        linux-amd64)  os="linux";  arch="amd64" ;;
        linux-arm64)  os="linux";  arch="arm64" ;;
        darwin-amd64) os="darwin"; arch="amd64" ;;
        darwin-arm64) os="darwin"; arch="arm64" ;;
        *) red "Unsupported platform: $PLATFORM"; exit 1 ;;
    esac
    url="https://dl.min.io/server/minio/release/${os}-${arch}/minio"
    curl -fsSL -o "$BIN_DIR/minio" "$url"
    chmod +x "$BIN_DIR/minio"
    green "  minio downloaded"
}

# --- Resolve or download maxio binary ---
ensure_maxio() {
    if [ -n "$MAXIO_HOST" ]; then return; fi
    if [ -n "$MAXIO_BIN" ]; then
        if [ ! -f "$MAXIO_BIN" ]; then
            red "MaxIO binary not found: $MAXIO_BIN"
            exit 1
        fi
        return
    fi
    # Check common locations (cache, cwd, cargo target)
    if [ -x "$BIN_DIR/maxio" ]; then
        MAXIO_BIN="$BIN_DIR/maxio"
    elif [ -f ./maxio ]; then
        MAXIO_BIN="./maxio"
    elif [ -f ./target/release/maxio ]; then
        MAXIO_BIN="./target/release/maxio"
    else
        # Download latest release from GitHub
        mkdir -p "$BIN_DIR"
        bold "Downloading maxio..."
        local arch url
        case "$PLATFORM" in
            linux-amd64)  arch="amd64" ;;
            linux-arm64)  arch="arm64" ;;
            darwin-arm64) arch="arm64" ;;
            *) red "No MaxIO release for $PLATFORM. Provide with: --maxio-bin=PATH"; exit 1 ;;
        esac
        local os_name
        case "$PLATFORM" in
            linux-*)  os_name="linux" ;;
            darwin-*) os_name="macos" ;;
        esac
        # Get latest release tag via GitHub API
        local tag
        tag=$(curl -fsSL "https://api.github.com/repos/coollabsio/maxio/releases/latest" \
            | grep '"tag_name"' | cut -d'"' -f4)
        local version="${tag#v}"
        url="https://github.com/coollabsio/maxio/releases/download/${tag}/maxio-${os_name}-${arch}-${version}.tar.gz"
        curl -fsSL "$url" | tar xz -C "$BIN_DIR" 2>/dev/null
        chmod +x "$BIN_DIR/maxio"
        MAXIO_BIN="$BIN_DIR/maxio"
        export PATH="$BIN_DIR:$PATH"
        green "  maxio $version downloaded"
    fi
}

ensure_warp
ensure_minio
ensure_maxio

# --- Cleanup ---
cleanup() {
    echo
    dim "Cleaning up..."
    if [ -n "$MAXIO_PID" ] && kill -0 "$MAXIO_PID" 2>/dev/null; then
        kill "$MAXIO_PID" 2>/dev/null || true
        wait "$MAXIO_PID" 2>/dev/null || true
    fi
    if [ -n "$MINIO_PID" ] && kill -0 "$MINIO_PID" 2>/dev/null; then
        kill "$MINIO_PID" 2>/dev/null || true
        wait "$MINIO_PID" 2>/dev/null || true
    fi
    # Remove raw benchmark data (results.md is printed to stdout)
    rm -rf "$OUTDIR"
}
trap cleanup EXIT

# --- Port check ---
check_port() {
    if command -v lsof &>/dev/null; then
        if lsof -i :"$1" &>/dev/null; then
            red "Port $1 is already in use."
            exit 1
        fi
    elif command -v ss &>/dev/null; then
        if ss -tlnp | grep -q ":$1 " 2>/dev/null; then
            red "Port $1 is already in use."
            exit 1
        fi
    fi
}

# --- Wait for server health ---
wait_for_health() {
    local url="$1" name="$2" max_wait=20
    printf "  Waiting for %s..." "$name"
    for i in $(seq 1 $max_wait); do
        if curl -sf "$url" &>/dev/null; then
            green " ready (${i}s)"
            return 0
        fi
        sleep 1
    done
    red " timeout after ${max_wait}s"
    exit 1
}

# --- Start servers ---
start_maxio() {
    if [ -n "$MAXIO_HOST" ]; then
        yellow "Using external MaxIO: $MAXIO_HOST"
        return
    fi
    check_port "$MAXIO_PORT"
    mkdir -p "$MAXIO_DATA"
    bold "Starting MaxIO on port $MAXIO_PORT..."
    "$MAXIO_BIN" --data-dir "$MAXIO_DATA" --port "$MAXIO_PORT" &>/dev/null &
    MAXIO_PID=$!
    wait_for_health "http://localhost:$MAXIO_PORT/healthz" "MaxIO"
}

start_minio() {
    if [ -n "$MINIO_HOST" ]; then
        yellow "Using external MinIO: $MINIO_HOST"
        return
    fi
    check_port "$MINIO_PORT"
    mkdir -p "$MINIO_DATA"
    bold "Starting MinIO on port $MINIO_PORT..."
    MINIO_ROOT_USER="$ACCESS_KEY" \
    MINIO_ROOT_PASSWORD="$SECRET_KEY" \
    minio server "$MINIO_DATA" --address ":$MINIO_PORT" &>/dev/null &
    MINIO_PID=$!
    wait_for_health "http://localhost:$MINIO_PORT/minio/health/live" "MinIO"
}

# --- Resolve hosts ---
maxio_host() {
    echo "${MAXIO_HOST:-localhost:$MAXIO_PORT}"
}

minio_host() {
    echo "${MINIO_HOST:-localhost:$MINIO_PORT}"
}

# --- Benchmark runner ---
SCENARIO_NUM=0
TOTAL_SCENARIOS=$(echo $SCENARIOS | wc -w | tr -d ' ')

# Arrays for summary table
declare -a SUMMARY_LABELS=()
declare -a SUMMARY_MAXIO=()
declare -a SUMMARY_MINIO=()

# Extract average throughput from warp output (e.g. " * Average: 14.30 MiB/s, 3661.75 obj/s")
# Takes the last "* Average:" line which is the total/combined result
extract_throughput() {
    local avg
    avg=$(echo "$1" | grep '\* Average:' | tail -1 | sed 's/.*\* Average: //')
    echo "${avg:-N/A}"
}

run_bench() {
    local name="$1" label="$2"
    shift 2
    local warp_cmd="$1"
    shift
    SCENARIO_NUM=$((SCENARIO_NUM + 1))

    echo
    bold "============================================================"
    bold "  BENCHMARK $SCENARIO_NUM/$TOTAL_SCENARIOS: $label"
    bold "============================================================"

    local maxio_file="$OUTDIR/maxio-${name}.csv.zst"
    local minio_file="$OUTDIR/minio-${name}.csv.zst"
    local maxio_output minio_output

    # Run against MaxIO
    echo
    green "--- MaxIO ($(maxio_host)) ---"
    maxio_output=$(warp "$warp_cmd" \
        --host "$(maxio_host)" \
        --access-key "$ACCESS_KEY" \
        --secret-key "$SECRET_KEY" \
        --benchdata "$maxio_file" \
        --duration "$DURATION" \
        --bucket "warp-$name" \
        --no-color \
        "$@" 2>&1) || true
    echo "$maxio_output"

    # Run against MinIO
    echo
    green "--- MinIO ($(minio_host)) ---"
    minio_output=$(warp "$warp_cmd" \
        --host "$(minio_host)" \
        --access-key "$ACCESS_KEY" \
        --secret-key "$SECRET_KEY" \
        --benchdata "$minio_file" \
        --duration "$DURATION" \
        --bucket "warp-$name" \
        --no-color \
        "$@" 2>&1) || true
    echo "$minio_output"

    # Compare (MinIO as baseline, MaxIO as "after")
    echo
    yellow "--- Comparison ($label) ---"
    warp cmp "$minio_file" "$maxio_file" --no-color 2>&1 || true

    # Store for summary table
    SUMMARY_LABELS+=("$label")
    SUMMARY_MAXIO+=("$(extract_throughput "$maxio_output")")
    SUMMARY_MINIO+=("$(extract_throughput "$minio_output")")
}

# --- Run selected scenarios ---

start_maxio
start_minio

echo
bold "============================================================"
bold "  MaxIO vs MinIO Benchmark"
bold "  Duration per test: $DURATION"
bold "  Scenarios: $TOTAL_SCENARIOS"
bold "============================================================"

for scenario in $SCENARIOS; do
    case "$scenario" in
        put-small)
            run_bench "put-small" "PUT 4KiB" put \
                --obj.size 4KiB --concurrent 8
            ;;
        put-med)
            run_bench "put-med" "PUT 1MiB" put \
                --obj.size 1MiB --concurrent 8
            ;;
        put-large)
            run_bench "put-large" "PUT 64MiB" put \
                --obj.size 64MiB --concurrent 4
            ;;
        get-small)
            run_bench "get-small" "GET 4KiB" get \
                --obj.size 4KiB --concurrent 8
            ;;
        get-med)
            run_bench "get-med" "GET 1MiB" get \
                --obj.size 1MiB --concurrent 8
            ;;
        mixed)
            run_bench "mixed" "Mixed 1MiB" mixed \
                --obj.size 1MiB --concurrent 8 \
                --get-distrib 45 --put-distrib 30 \
                --stat-distrib 15 --delete-distrib 10
            ;;
        multipart)
            run_bench "multipart" "Multipart 100MiB" multipart \
                --parts 10 --part.size 10MiB --concurrent 4
            ;;
        *)
            yellow "Unknown scenario: $scenario (skipping)"
            ;;
    esac
done

# --- Generate markdown summary table ---
generate_summary() {
    local md="$RESULTS_FILE"
    {
        echo "# MaxIO vs MinIO Benchmark"
        echo ""
        echo "- **Date**: $(date '+%Y-%m-%d %H:%M')"
        echo "- **Duration**: $DURATION per scenario"
        echo "- **MaxIO**: $(maxio_host)"
        echo "- **MinIO**: $(minio_host)"
        echo ""
        echo "| Scenario | MaxIO | MinIO |"
        echo "|----------|-------|-------|"
        for i in "${!SUMMARY_LABELS[@]}"; do
            printf "| %-16s | %s | %s |\n" \
                "${SUMMARY_LABELS[$i]}" \
                "${SUMMARY_MAXIO[$i]}" \
                "${SUMMARY_MINIO[$i]}"
        done
    } > "$md"

    echo
    bold "============================================================"
    bold "  RESULTS"
    bold "============================================================"
    echo
    cat "$md"
}

generate_summary
