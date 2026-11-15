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
# --print-plan prints three lines and does not run commands:
#   rust=none|bin|integration|scoped|package|full
#   cargo-test=none|all|bin|<comma-separated integration test names>
#   ui=yes|no
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
done < <(git diff -z --name-only --diff-filter=ACDMRTUXB "$BASE_REF" && git ls-files -z --others --exclude-standard)

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

if [[ "$PRINT_PLAN" -eq 1 ]]; then
  printf 'rust=%s\n' "$rust"
  printf 'cargo-test=%s\n' "$cargo_test"
  printf 'ui=%s\n' "$ui"
  exit 0
fi

echo "agent-check rust=${rust} cargo-test=${cargo_test} ui=${ui} base=${BASE_REF}" >&2

run_cargo_targets() {
  local -a target_args=("$@")
  cargo check -p maxio --all-features "${target_args[@]}"
  cargo clippy -p maxio --all-features "${target_args[@]}" -- -D warnings
  cargo test -p maxio --all-features "${target_args[@]}"
}

case "$rust" in
  none) ;;
  bin)
    run_cargo_targets --bin maxio
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
    run_cargo_targets "${args[@]}"
    ;;
  package | full)
    run_cargo_targets --all-targets
    ;;
  *)
    echo "internal error: rust=${rust}" >&2
    exit 2
    ;;
esac

if [[ "$ui" == "yes" ]]; then
  (cd ui && bun run lint)
  (cd ui && bun run test)
fi
