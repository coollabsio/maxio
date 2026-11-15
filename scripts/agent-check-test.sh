#!/usr/bin/env bash
# Exercises path-to-target planning for scripts/agent-check.sh.
set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/agent-check.sh"
if [[ ! -f "$SCRIPT" ]]; then
  echo "missing $SCRIPT" >&2
  exit 1
fi

failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

new_repo() {
  local dir
  dir="$(mktemp -d)"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email "agent-check@example.com"
  git -C "$dir" config user.name "agent-check"
  mkdir -p "$dir/src/storage" "$dir/tests" "$dir/ui/src" "$dir/docs" "$dir/.github/workflows"
  printf 'fn main() {}\n' >"$dir/src/main.rs"
  printf 'pub fn lib() {}\n' >"$dir/src/lib.rs"
  printf 'pub fn store() {}\n' >"$dir/src/storage/mod.rs"
  printf 'fn limits() {}\n' >"$dir/tests/limits.rs"
  printf 'fn integration() {}\n' >"$dir/tests/integration.rs"
  printf 'export {}\n' >"$dir/ui/src/App.tsx"
  printf '# docs\n' >"$dir/README.md"
  printf '# workflow\n' >"$dir/.github/workflows/ci.yml"
  printf 'fn build() {}\n' >"$dir/build.rs"
  git -C "$dir" add .
  git -C "$dir" commit -q -m init
  printf '%s' "$dir"
}

expect_plan() {
  local name="$1"
  local dir="$2"
  local expected="$3"
  local actual
  local err
  err="$(mktemp)"
  if ! actual="$(MAXIO_AGENT_CHECK_ROOT="$dir" "$SCRIPT" --base HEAD --print-plan 2>"$err")"; then
    fail "$name: print-plan exited $?"
    cat "$err" >&2 || true
    return
  fi
  if [[ "$actual" != "$expected" ]]; then
    fail "$name: plan mismatch"
    echo "stderr:" >&2
    cat "$err" >&2 || true
    echo "expected:" >&2
    printf '%s\n' "$expected" >&2
    echo "actual:" >&2
    printf '%s\n' "$actual" >&2
  else
    echo "ok $name"
  fi
}

# Clean tree.
dir="$(new_repo)"
expect_plan clean "$dir" $'rust=none\ncargo-test=none\nui=no'

# Library module.
dir="$(new_repo)"
printf '\npub fn extra() {}\n' >>"$dir/src/storage/mod.rs"
expect_plan lib "$dir" $'rust=package\ncargo-test=all\nui=no'

# Binary only.
dir="$(new_repo)"
printf '\nfn bin_only() {}\n' >>"$dir/src/main.rs"
expect_plan bin "$dir" $'rust=bin\ncargo-test=bin\nui=no'

# One integration test.
dir="$(new_repo)"
printf '\nfn extra() {}\n' >>"$dir/tests/limits.rs"
expect_plan one-test "$dir" $'rust=integration\ncargo-test=limits\nui=no'

# Two integration tests, sorted.
dir="$(new_repo)"
printf '\nfn extra() {}\n' >>"$dir/tests/integration.rs"
printf '\nfn extra() {}\n' >>"$dir/tests/limits.rs"
expect_plan two-tests "$dir" $'rust=integration\ncargo-test=integration,limits\nui=no'

# UI only.
dir="$(new_repo)"
printf '\nexport const n = 1;\n' >>"$dir/ui/src/App.tsx"
expect_plan ui "$dir" $'rust=none\ncargo-test=none\nui=yes'

# Docs only.
dir="$(new_repo)"
printf '\nmore\n' >>"$dir/README.md"
expect_plan docs "$dir" $'rust=none\ncargo-test=none\nui=no'

# The agent script and justfile are not crate inputs.
dir="$(new_repo)"
mkdir -p "$dir/scripts"
printf 'echo hi\n' >"$dir/scripts/tool.sh"
printf 'check:\n' >"$dir/justfile"
expect_plan tooling "$dir" $'rust=none\ncargo-test=none\nui=no'

# Library plus UI.
dir="$(new_repo)"
printf '\npub fn extra() {}\n' >>"$dir/src/lib.rs"
printf '\nexport const n = 1;\n' >>"$dir/ui/src/App.tsx"
expect_plan lib-ui "$dir" $'rust=package\ncargo-test=all\nui=yes'

# Manifest.
dir="$(new_repo)"
printf '\n// touch\n' >>"$dir/build.rs"
expect_plan manifest "$dir" $'rust=package\ncargo-test=all\nui=no'

# Unknown path fails open to the full loop, including the UI.
dir="$(new_repo)"
printf 'FROM scratch\n' >"$dir/Dockerfile"
git -C "$dir" add Dockerfile
expect_plan unknown "$dir" $'rust=full\ncargo-test=all\nui=yes'

# Untracked library file.
dir="$(new_repo)"
printf 'pub fn fresh() {}\n' >"$dir/src/fresh.rs"
expect_plan untracked "$dir" $'rust=package\ncargo-test=all\nui=no'

# Binary plus one integration test.
dir="$(new_repo)"
printf '\nfn bin_only() {}\n' >>"$dir/src/main.rs"
printf '\nfn extra() {}\n' >>"$dir/tests/limits.rs"
expect_plan scoped "$dir" $'rust=scoped\ncargo-test=bin,limits\nui=no'

# Shim cargo and bun and confirm the commands for a lib change and a UI-only change.
assert_log() {
  local name="$1"
  local log="$2"
  local expected="$3"
  local actual
  actual="$(cat "$log")"
  if [[ "$actual" != "$expected" ]]; then
    fail "$name: command log mismatch"
    echo "expected:" >&2
    printf '%s\n' "$expected" >&2
    echo "actual:" >&2
    printf '%s\n' "$actual" >&2
  else
    echo "ok $name"
  fi
}

make_shims() {
  local shim_dir="$1"
  mkdir -p "$shim_dir"
  cat >"$shim_dir/cargo" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${AGENT_CHECK_LOG:?}"
exit 0
EOF
  cat >"$shim_dir/bun" <<'EOF'
#!/bin/sh
printf '%s\n' "bun $*" >>"${AGENT_CHECK_LOG:?}"
exit 0
EOF
  chmod +x "$shim_dir/cargo" "$shim_dir/bun"
}

run_with_shims() {
  local dir="$1"
  local log
  log="$(mktemp)"
  local shims
  shims="$(mktemp -d)"
  make_shims "$shims"
  PATH="$shims:$PATH" AGENT_CHECK_LOG="$log" MAXIO_AGENT_CHECK_ROOT="$dir" \
    "$SCRIPT" --base HEAD
  printf '%s' "$log"
}

dir="$(new_repo)"
printf '\npub fn extra() {}\n' >>"$dir/src/lib.rs"
log="$(run_with_shims "$dir")"
assert_log run-lib "$log" $'check -p maxio --all-features --all-targets\nclippy -p maxio --all-features --all-targets -- -D warnings\ntest -p maxio --all-features --all-targets'

dir="$(new_repo)"
printf '\nexport const n = 1;\n' >>"$dir/ui/src/App.tsx"
log="$(run_with_shims "$dir")"
assert_log run-ui "$log" $'bun run lint\nbun run test'

dir="$(new_repo)"
printf '\nfn extra() {}\n' >>"$dir/tests/limits.rs"
log="$(run_with_shims "$dir")"
assert_log run-test "$log" $'check -p maxio --all-features --test limits\nclippy -p maxio --all-features --test limits -- -D warnings\ntest -p maxio --all-features --test limits'

dir="$(new_repo)"
printf '\nfn bin_only() {}\n' >>"$dir/src/main.rs"
printf '\nfn extra() {}\n' >>"$dir/tests/limits.rs"
log="$(run_with_shims "$dir")"
assert_log run-scoped "$log" $'check -p maxio --all-features --bin maxio --test limits\nclippy -p maxio --all-features --bin maxio --test limits -- -D warnings\ntest -p maxio --all-features --bin maxio --test limits'

if [[ "$failures" -ne 0 ]]; then
  echo "$failures failed" >&2
  exit 1
fi
echo "all agent-check tests passed"
