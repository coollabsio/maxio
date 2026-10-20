#!/usr/bin/env bash
# Run Ceph's s3-tests (boto3) against a local MaxIO.
#
# MinIO Mint is not used: it is a Docker harness that launches MinIO itself,
# and this environment (and a typical CI runner without the Mint image) cannot
# run it reliably. s3-tests is the suite other S3-compatible servers use.
#
# Usage:
#   ./tests/s3_compat.sh                 # build (if needed), start MaxIO, run
#   MAXIO_BIN=./target/debug/maxio ./tests/s3_compat.sh
#
# Exit status is 0 when every failure is in tests/s3_compat_expected_failures.txt.
# A new failure fails the run. Tests for features MaxIO does not implement are
# deselected (marker expression below, plus tests/s3_compat_skip_names.txt)
# and are not counted as failures. See docs/s3-compatibility.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${MAXIO_PORT:-9876}"
DATA_DIR="${MAXIO_DATA_DIR:-$(mktemp -d)}"
BIN="${MAXIO_BIN:-$ROOT/target/debug/maxio}"
S3TESTS_SHA="${S3TESTS_SHA:-5b3987116eca0b4b8fa57d6b10f3db57bab196b6}"
CACHE="${S3_COMPAT_CACHE:-${TMPDIR:-/tmp}/maxio-s3-tests}"
CONF="$(mktemp)"
RESULTS="${S3_COMPAT_RESULTS:-$ROOT/target/s3-compat-results.xml}"
SKIP_NAMES="$ROOT/tests/s3_compat_skip_names.txt"
EXPECTED="$ROOT/tests/s3_compat_expected_failures.txt"

# Features MaxIO intentionally does not implement. These markers come from
# s3-tests' pytest.ini. Keeping them here (not as silent passes) is the skip list.
SKIP_MARKERS="object_lock or storage_class or lifecycle_transition or cloud_transition or cloud_restore or s3website or s3website_routing_rules or s3website_redirect_location or auth_aws2 or fails_on_aws or iam_account or iam_user or iam_role or iam_tenant or iam_cross_account or user_policy or session_policy or group_policy or role_policy or webidentity_test or test_of_sts or s3select or sns or s3control or object_ownership or bucket_logging or bucket_logging_cleanup or appendobject or abac_test or group or fails_with_subdomain"

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$CONF"
    if [[ "${MAXIO_DATA_DIR:-}" == "" ]]; then
        rm -rf "$DATA_DIR"
    fi
}
trap cleanup EXIT

if [[ ! -x "$BIN" ]]; then
    echo "building $BIN"
    (cd "$ROOT" && SKIP_FRONTEND=1 cargo build --bin maxio)
fi

mkdir -p "$DATA_DIR" "$(dirname "$RESULTS")"
"$BIN" --data-dir "$DATA_DIR" --address 127.0.0.1 --port "$PORT" --allow-insecure-dev \
    >"${DATA_DIR}/maxio.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null

if [[ ! -d "$CACHE/.git" ]]; then
    mkdir -p "$CACHE"
    git -C "$CACHE" init -q
    git -C "$CACHE" remote add origin https://github.com/ceph/s3-tests.git
fi
git -C "$CACHE" fetch --depth 1 --quiet origin "$S3TESTS_SHA"
git -C "$CACHE" checkout --quiet --force FETCH_HEAD

if [[ ! -x "$CACHE/.venv/bin/pytest" ]]; then
    python3 -m venv "$CACHE/.venv"
    "$CACHE/.venv/bin/pip" install -q -r "$CACHE/requirements.txt" pytest-timeout
fi

# Documented dev credentials. Not a production secret.
cat >"$CONF" <<EOF
[DEFAULT]
host = 127.0.0.1
port = ${PORT}
is_secure = False
ssl_verify = False

[fixtures]
bucket prefix = maxio-{random}-

[s3 main]
display_name = MaxIO Tester
user_id = maxio-main
email = tester@example.com
api_name = default
access_key = maxioadmin
secret_key = maxioadmin
lc_debug_interval = 1

[s3 alt]
display_name = MaxIO Alt
email = alt@example.com
user_id = maxio-alt
access_key = maxioadmin
secret_key = maxioadmin

[s3 tenant]
display_name = MaxIO Tenant
user_id = maxio-tenant
access_key = maxioadmin
secret_key = maxioadmin
email = tenant@example.com
tenant = testx

[iam]
email = iam@example.com
user_id = maxio-iam
access_key = maxioadmin
secret_key = maxioadmin
display_name = MaxIO IAM

[iam root]
access_key = maxioadmin
secret_key = maxioadmin
account_id = 000000000000
user_id = maxio-iam-root
email = iam-root@example.com

[iam alt root]
access_key = maxioadmin
secret_key = maxioadmin
account_id = 000000000001
user_id = maxio-iam-alt
email = iam-alt@example.com
EOF

# pytest --deselect treats the node id as a prefix, so test_100_continue would
# also drop test_100_continue_error_retry. Match the full node id instead.
cat >"$CACHE/conftest.py" <<'EOF'
import os

def pytest_collection_modifyitems(config, items):
    path = os.environ.get("S3_COMPAT_SKIP", "")
    exact = set()
    if path and os.path.isfile(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#"):
                exact.add(line)
    if not exact:
        return
    kept, dropped = [], []
    for item in items:
        node = item.nodeid.replace("\\", "/")
        if any(node.endswith(nid) for nid in exact):
            dropped.append(item)
        else:
            kept.append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = kept
EOF

set +e
S3TEST_CONF="$CONF" \
    S3_COMPAT_SKIP="$SKIP_NAMES" \
    PYTHONPATH="$CACHE" \
    AWS_DEFAULT_REGION=us-east-1 \
    AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
    AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    "$CACHE/.venv/bin/pytest" -q --timeout=120 --tb=line -p no:cacheprovider \
    --junitxml="$RESULTS" \
    -m "not (${SKIP_MARKERS})" \
    "$CACHE/s3tests/functional/test_s3.py" \
    "$CACHE/s3tests/functional/test_headers.py"
PYTEST_EXIT=$?
set -e

python3 - "$RESULTS" "$EXPECTED" <<'PY'
import sys
import xml.etree.ElementTree as ET

results, expected_path = sys.argv[1], sys.argv[2]
tree = ET.parse(results)
failed = []
passed = 0
for tc in tree.iter("testcase"):
    name = tc.get("classname", "") + "::" + tc.get("name", "")
    # junit classname is the module; pytest node id uses the file path.
    node = tc.get("file", "")
    if not node:
        # pytest junit: classname s3tests.functional.test_s3
        cls = tc.get("classname", "")
        node = cls.replace(".", "/") + ".py"
    node_id = f"{node}::{tc.get('name')}"
    if any(child.tag in ("failure", "error") for child in tc):
        failed.append(node_id)
    else:
        passed += 1

expected = []
try:
    for line in open(expected_path):
        line = line.strip()
        if line and not line.startswith("#"):
            expected.append(line)
except FileNotFoundError:
    expected = []

unexpected = sorted(set(failed) - set(expected))
fixed = sorted(set(expected) - set(failed))
print(f"s3-tests: {passed} passed, {len(failed)} failed, {passed + len(failed)} run")
if fixed:
    print(f"{len(fixed)} expected failure(s) now pass; update {expected_path}")
    for name in fixed:
        print(f"  now passing: {name}")
if unexpected:
    print(f"{len(unexpected)} unexpected failure(s):")
    for name in unexpected:
        print(f"  {name}")
    sys.exit(1)
if not failed:
    print("no failures")
sys.exit(0)
PY
