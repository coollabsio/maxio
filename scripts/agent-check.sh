#!/usr/bin/env bash
# Agent loop for the single maxio package.
#
# There is no workspace. Changed paths map to targets inside this package:
# the library, the maxio binary, one integration-test binary, and the UI.
# Public API changes have no downstream crates; the in-package dependents
# are the binary and the integration tests, and a src/ change runs those.
#
# Usage:
#   scripts/agent-check.sh [--base REF] [--print-plan]
#
# --print-plan prints five lines and does not run commands:
#   rust=none|bin|integration|scoped|package|full
#   cargo-test=none|all|bin|<comma-separated integration test names>
#   ui=yes|no
#   fingerprint=n/a|miss|hit|fail-open
#   run-tests=yes|no
#
# A fingerprint hit skips cargo test / bun test. check, clippy, and bun lint
# still run. The cache lives in target/agent-check (or MAXIO_AGENT_CHECK_CACHE).
# Keys are versioned (maxio-agent-check-v1). A missing key is a miss. A key
# that is not "vN <64 hex>" fails open and runs the tests. Hash errors fail open.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${MAXIO_AGENT_CHECK_ROOT:-}" ]]; then
  ROOT="${MAXIO_AGENT_CHECK_ROOT}"
fi
cd "$ROOT"

BASE_REF=""
PRINT_PLAN=0

usage() {
  echo "usage: scripts/agent-check.sh [--base REF] [--print-plan]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      BASE_REF="${2:-}"
      if [[ -z "$BASE_REF" ]]; then
        usage
        exit 2
      fi
      shift 2
      ;;
    --print-plan)
      PRINT_PLAN=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$BASE_REF" ]]; then
  if git rev-parse --verify --quiet origin/main >/dev/null; then
    BASE_REF="origin/main"
  elif git rev-parse --verify --quiet main >/dev/null; then
    BASE_REF="main"
  else
    echo "no base ref; pass --base" >&2
    exit 2
  fi
fi

if ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" >/dev/null; then
  echo "base ref not found: ${BASE_REF}" >&2
  exit 2
fi

files=()
while IFS= read -r -d '' path; do
  [[ -z "$path" ]] && continue
  files+=("$path")
done < <(git diff -z --name-only --diff-filter=ACDMRTUXB "$BASE_REF" || true; git ls-files -z --others --exclude-standard || true)

bin_change=0
lib_change=0
manifest_change=0
unknown_change=0
ui_change=0
test_names=()

for path in "${files[@]+"${files[@]}"}"; do
  case "$path" in
    src/main.rs)
      bin_change=1
      ;;
    src/*.rs | src/*/*.rs)
      lib_change=1
      ;;
    tests/*.rs)
      test_names+=("$(basename "$path" .rs)")
      ;;
    Cargo.toml | Cargo.lock | build.rs | rust-toolchain.toml | .cargo/*)
      manifest_change=1
      ;;
    ui/*)
      ui_change=1
      ;;
    *.md | LICENSE* | docs/* | .github/* | .gitignore | .gitattributes | scripts/* | justfile)
      ;;
    *)
      unknown_change=1
      ;;
  esac
done

if [[ ${#test_names[@]} -gt 0 ]]; then
  mapfile -t test_names < <(printf '%s\n' "${test_names[@]}" | sort -u)
fi

rust="none"
cargo_test="none"
ui="no"

if [[ "$unknown_change" -eq 1 ]]; then
  # Not a source path we know. Run the full loop rather than skip work.
  rust="full"
  cargo_test="all"
  ui="yes"
elif [[ "$manifest_change" -eq 1 || "$lib_change" -eq 1 ]]; then
  rust="package"
  cargo_test="all"
  if [[ "$ui_change" -eq 1 ]]; then
    ui="yes"
  fi
elif [[ "$bin_change" -eq 1 && ${#test_names[@]} -gt 0 ]]; then
  rust="scoped"
  cargo_test="bin,$(IFS=','; echo "${test_names[*]}")"
elif [[ "$bin_change" -eq 1 ]]; then
  rust="bin"
  cargo_test="bin"
elif [[ ${#test_names[@]} -gt 0 ]]; then
  rust="integration"
  cargo_test="$(IFS=','; echo "${test_names[*]}")"
fi

if [[ "$ui_change" -eq 1 && "$rust" != "full" ]]; then
  ui="yes"
fi

CACHE_DIR="${MAXIO_AGENT_CHECK_CACHE:-$ROOT/target/agent-check}"
FP_VERSION="v1"
FP_PREIMAGE="maxio-agent-check-v1"

collect_files() {
  local root="$1"
  shift
  if [[ ! -d "$root" ]]; then
    return 0
  fi
  find "$root" "$@" -type f -print | sort
}

closure_for() {
  local kind="$1"
  local names="$2"
  local path
  for path in Cargo.toml Cargo.lock build.rs rust-toolchain.toml; do
    if [[ -f "$path" ]]; then
      printf '%s\n' "$path"
    fi
  done
  case "$kind" in
    rust)
      collect_files src -name '*.rs'
      if [[ "$cargo_test" == "all" ]]; then
        collect_files tests -name '*.rs'
      else
        local name
        IFS=',' read -r -a name_parts <<<"$names"
        for name in "${name_parts[@]}"; do
          if [[ -n "$name" && "$name" != "bin" && -f "tests/${name}.rs" ]]; then
            printf '%s\n' "tests/${name}.rs"
          fi
        done
      fi
      ;;
    ui)
      if [[ -d ui ]]; then
        find ui -type f \
          ! -path 'ui/node_modules/*' \
          ! -path 'ui/dist/*' \
          -print | sort
      fi
      ;;
  esac
}

fingerprint_key() {
  local kind="$1"
  local scope="$2"
  local flags="$3"
  shift 3
  python3 - "$kind" "$scope" "$flags" "$FP_PREIMAGE" "$@" <<'PY'
import hashlib, os, pathlib, subprocess, sys

kind, scope, flags, version, *files = sys.argv[1:]
digest = hashlib.sha256()

def add(text: bytes) -> None:
    digest.update(text)
    digest.update(b"\0")

try:
    toolchain = os.environ.get("MAXIO_AGENT_CHECK_TOOLCHAIN", "")
    if not toolchain:
        toolchain = subprocess.check_output(["rustc", "-vV"], text=True)
        toolchain += subprocess.check_output(["cargo", "--version"], text=True)
        if kind == "ui":
            toolchain += subprocess.check_output(["bun", "--version"], text=True)
    add(version.encode())
    add(kind.encode())
    add(scope.encode())
    add(flags.encode())
    add(toolchain.encode())
    for path in files:
        add(path.encode())
        add(pathlib.Path(path).read_bytes())
except (OSError, subprocess.CalledProcessError) as exc:
    print(f"fingerprint-error: {exc}", file=sys.stderr)
    sys.exit(1)
print(digest.hexdigest())
PY
}

cache_decision() {
  local file="$1"
  local key="$2"
  if [[ ! -e "$file" ]]; then
    printf 'miss'
    return 0
  fi
  local stored
  stored="$(head -n 1 "$file" 2>/dev/null || true)"
  stored="${stored//$'\r'/}"
  if [[ ! "$stored" =~ ^v[0-9]+\ [0-9a-f]{64}$ ]]; then
    printf 'fail-open'
    return 0
  fi
  local ver="${stored%% *}"
  local hex="${stored#* }"
  if [[ "$ver" != "$FP_VERSION" ]]; then
    printf 'miss'
    return 0
  fi
  if [[ "$hex" == "$key" ]]; then
    printf 'hit'
  else
    printf 'miss'
  fi
}

write_cache() {
  local file="$1"
  local key="$2"
  mkdir -p "$(dirname "$file")"
  local tmp
  tmp="$(mktemp "${file}.XXXXXX")"
  printf '%s %s\n' "$FP_VERSION" "$key" >"$tmp"
  mv "$tmp" "$file"
}

resolve_scope() {
  local kind="$1"
  local scope="$2"
  local flags="$3"
  local names="$4"
  local key decision file
  mapfile -t closure < <(closure_for "$kind" "$names")
  if ! key="$(fingerprint_key "$kind" "$scope" "$flags" "${closure[@]+"${closure[@]}"}")"; then
    printf 'fail-open\n'
    return 0
  fi
  file="${CACHE_DIR}/${FP_VERSION}-${scope}"
  decision="$(cache_decision "$file" "$key")"
  printf '%s %s %s\n' "$decision" "$key" "$file"
}

rust_decision="n/a"
ui_decision="n/a"
rust_key=""
rust_cache_file=""
ui_key=""
ui_cache_file=""

if [[ "$cargo_test" != "none" ]]; then
  case "$rust" in
    bin) rust_scope="bin-tests" ;;
    integration | scoped) rust_scope="tests-${cargo_test//,/-}" ;;
    *) rust_scope="pkg-tests" ;;
  esac
  rust_flags="cargo check/clippy/test -p maxio --all-features ${cargo_test}"
  read -r rust_decision rust_key rust_cache_file < <(resolve_scope rust "$rust_scope" "$rust_flags" "$cargo_test")
fi

if [[ "$ui" == "yes" ]]; then
  read -r ui_decision ui_key ui_cache_file < <(resolve_scope ui "ui-tests" "bun run lint && bun run test" "")
fi

fingerprint="n/a"
run_tests="no"
if [[ "$rust_decision" == "fail-open" || "$ui_decision" == "fail-open" ]]; then
  fingerprint="fail-open"
  run_tests="yes"
elif [[ "$rust_decision" == "miss" || "$ui_decision" == "miss" ]]; then
  fingerprint="miss"
  run_tests="yes"
elif [[ "$rust_decision" == "hit" || "$ui_decision" == "hit" ]]; then
  fingerprint="hit"
  run_tests="no"
fi

if [[ "$PRINT_PLAN" -eq 1 ]]; then
  printf 'rust=%s\n' "$rust"
  printf 'cargo-test=%s\n' "$cargo_test"
  printf 'ui=%s\n' "$ui"
  printf 'fingerprint=%s\n' "$fingerprint"
  printf 'run-tests=%s\n' "$run_tests"
  exit 0
fi

echo "agent-check rust=${rust} cargo-test=${cargo_test} ui=${ui} fingerprint=${fingerprint} run-tests=${run_tests} base=${BASE_REF}" >&2

run_cargo_targets() {
  local decision="$1"
  local key="$2"
  local cache_file="$3"
  shift 3
  local -a target_args=("$@")
  cargo check -p maxio --all-features "${target_args[@]}"
  cargo clippy -p maxio --all-features "${target_args[@]}" -- -D warnings
  if [[ "$decision" == "hit" ]]; then
    echo "skip cargo test (fingerprint hit)" >&2
    return 0
  fi
  cargo test -p maxio --all-features "${target_args[@]}"
  if [[ -n "$key" && -n "$cache_file" ]]; then
    write_cache "$cache_file" "$key"
  fi
}

case "$rust" in
  none) ;;
  bin)
    run_cargo_targets "$rust_decision" "$rust_key" "$rust_cache_file" --bin maxio
    ;;
  integration | scoped)
    args=()
    names="$cargo_test"
    if [[ "$rust" == "scoped" ]]; then
      args+=(--bin maxio)
      names="${cargo_test#bin,}"
    fi
    IFS=',' read -r -a parts <<<"$names"
    for name in "${parts[@]}"; do
      args+=(--test "$name")
    done
    run_cargo_targets "$rust_decision" "$rust_key" "$rust_cache_file" "${args[@]}"
    ;;
  package | full)
    run_cargo_targets "$rust_decision" "$rust_key" "$rust_cache_file" --all-targets
    ;;
  *)
    echo "internal error: rust=${rust}" >&2
    exit 2
    ;;
esac

if [[ "$ui" == "yes" ]]; then
  (cd ui && bun run lint)
  if [[ "$ui_decision" == "hit" ]]; then
    echo "skip bun test (fingerprint hit)" >&2
  else
    (cd ui && bun run test)
    if [[ -n "$ui_key" && -n "$ui_cache_file" ]]; then
      write_cache "$ui_cache_file" "$ui_key"
    fi
  fi
fi
