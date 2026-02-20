#!/usr/bin/env bash
set -euo pipefail

# Integration tests using AWS CLI against a running maxio server.
# Usage: ./tests/aws_cli_test.sh [port] [data_dir]
# Expects maxio to be running on localhost:${PORT:-9000}

PORT="${1:-9000}"
DATA_DIR="$(cd "${2:-./data}" && pwd)"
BUCKET="test-bucket-$$"
ENDPOINT="http://localhost:$PORT"
TMPDIR=$(mktemp -d)
PASS=0
FAIL=0

export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_DEFAULT_REGION=us-east-1

AWS="aws --endpoint-url $ENDPOINT"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }

assert() {
    local name="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        green "PASS: $name"
        PASS=$((PASS + 1))
    else
        red "FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    local name="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        red "FAIL: $name (expected failure but succeeded)"
        FAIL=$((FAIL + 1))
    else
        green "PASS: $name"
        PASS=$((PASS + 1))
    fi
}

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        green "PASS: $name"
        PASS=$((PASS + 1))
    else
        red "FAIL: $name (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_file_exists() {
    local name="$1" path="$2"
    if [ -e "$path" ]; then
        green "PASS: $name"
        PASS=$((PASS + 1))
    else
        red "FAIL: $name (file not found: $path)"
        FAIL=$((FAIL + 1))
    fi
}

assert_file_not_exists() {
    local name="$1" path="$2"
    if [ ! -e "$path" ]; then
        green "PASS: $name"
        PASS=$((PASS + 1))
    else
        red "FAIL: $name (file should not exist: $path)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Maxio AWS CLI integration tests ==="
echo "Server: localhost:$PORT"
echo "Data dir: $DATA_DIR"
echo ""

# --- Bucket operations ---
assert "create bucket" $AWS s3 mb "s3://$BUCKET"
assert_file_exists "bucket dir exists on disk" "$DATA_DIR/buckets/$BUCKET"
assert_file_exists "bucket meta exists on disk" "$DATA_DIR/buckets/$BUCKET/.bucket.json"

# List buckets
OUTPUT=$($AWS s3 ls 2>&1)
assert_eq "list buckets contains our bucket" "true" "$(echo "$OUTPUT" | grep -q "$BUCKET" && echo true || echo false)"

# Head bucket
assert "head bucket" $AWS s3api head-bucket --bucket "$BUCKET"

# --- Object operations ---
echo "hello maxio" > "$TMPDIR/test.txt"

assert "upload object" $AWS s3 cp "$TMPDIR/test.txt" "s3://$BUCKET/test.txt"
assert_file_exists "object file exists on disk" "$DATA_DIR/buckets/$BUCKET/test.txt"
assert_file_exists "object meta exists on disk" "$DATA_DIR/buckets/$BUCKET/test.txt.meta.json"
assert_eq "on-disk content matches" "hello maxio" "$(cat "$DATA_DIR/buckets/$BUCKET/test.txt")"

# List objects
OUTPUT=$($AWS s3 ls "s3://$BUCKET/" 2>&1)
assert_eq "list objects contains test.txt" "true" "$(echo "$OUTPUT" | grep -q "test.txt" && echo true || echo false)"

# Download and verify
assert "download object" $AWS s3 cp "s3://$BUCKET/test.txt" "$TMPDIR/downloaded.txt"
assert_eq "content matches" "hello maxio" "$(cat "$TMPDIR/downloaded.txt")"

# Head object
OUTPUT=$($AWS s3api head-object --bucket "$BUCKET" --key "test.txt" 2>&1)
assert_eq "head object has etag" "true" "$(echo "$OUTPUT" | grep -q "ETag" && echo true || echo false)"
assert_eq "head object has content-length" "true" "$(echo "$OUTPUT" | grep -q "ContentLength" && echo true || echo false)"

# --- Nested keys ---
assert "upload nested object" $AWS s3 cp "$TMPDIR/test.txt" "s3://$BUCKET/folder/nested/file.txt"
assert_file_exists "nested object exists on disk" "$DATA_DIR/buckets/$BUCKET/folder/nested/file.txt"
assert_file_exists "nested meta exists on disk" "$DATA_DIR/buckets/$BUCKET/folder/nested/file.txt.meta.json"

OUTPUT=$($AWS s3 ls "s3://$BUCKET/folder/" 2>&1)
assert_eq "list nested prefix" "true" "$(echo "$OUTPUT" | grep -q "nested" && echo true || echo false)"

assert "download nested object" $AWS s3 cp "s3://$BUCKET/folder/nested/file.txt" "$TMPDIR/nested.txt"
assert_eq "nested content matches" "hello maxio" "$(cat "$TMPDIR/nested.txt")"

# --- Multipart upload (large file) ---
dd if=/dev/urandom of="$TMPDIR/big.bin" bs=1M count=15 status=none
assert "upload large object (multipart)" $AWS s3 cp "$TMPDIR/big.bin" "s3://$BUCKET/big.bin"
assert "download large object" $AWS s3 cp "s3://$BUCKET/big.bin" "$TMPDIR/big.download.bin"
assert_eq "large object size matches" "$(wc -c < "$TMPDIR/big.bin" | tr -d ' ')" "$(wc -c < "$TMPDIR/big.download.bin" | tr -d ' ')"
OUTPUT=$($AWS s3api head-object --bucket "$BUCKET" --key "big.bin" 2>&1)
assert_eq "multipart etag suffix present" "true" "$(echo "$OUTPUT" | grep -Eq '\"ETag\": \".*-[0-9]+.*\"' && echo true || echo false)"

# --- Multipart upload (explicit API lifecycle) ---
dd if=/dev/urandom of="$TMPDIR/mpart1.bin" bs=1M count=5 status=none
echo "tail-part" > "$TMPDIR/mpart2.bin"
UPLOAD_ID=$($AWS s3api create-multipart-upload --bucket "$BUCKET" --key "manual-multipart.bin" --query UploadId --output text 2>/dev/null || true)
assert_eq "create multipart upload id" "true" "$([ -n "$UPLOAD_ID" ] && [ "$UPLOAD_ID" != "None" ] && echo true || echo false)"

ETAG1=$($AWS s3api upload-part --bucket "$BUCKET" --key "manual-multipart.bin" --part-number 1 --body "$TMPDIR/mpart1.bin" --upload-id "$UPLOAD_ID" --query ETag --output text 2>/dev/null || true)
ETAG2=$($AWS s3api upload-part --bucket "$BUCKET" --key "manual-multipart.bin" --part-number 2 --body "$TMPDIR/mpart2.bin" --upload-id "$UPLOAD_ID" --query ETag --output text 2>/dev/null || true)
assert_eq "upload multipart part 1 etag" "true" "$([ -n "$ETAG1" ] && [ "$ETAG1" != "None" ] && echo true || echo false)"
assert_eq "upload multipart part 2 etag" "true" "$([ -n "$ETAG2" ] && [ "$ETAG2" != "None" ] && echo true || echo false)"

OUTPUT=$($AWS s3api list-parts --bucket "$BUCKET" --key "manual-multipart.bin" --upload-id "$UPLOAD_ID" 2>&1)
assert_eq "list-parts contains part 1" "true" "$(echo "$OUTPUT" | grep -q '"PartNumber": 1' && echo true || echo false)"
assert_eq "list-parts contains part 2" "true" "$(echo "$OUTPUT" | grep -q '"PartNumber": 2' && echo true || echo false)"

COMPLETE_JSON="$TMPDIR/complete.json"
cat > "$COMPLETE_JSON" <<EOF
{
  "Parts": [
    {"ETag": $ETAG1, "PartNumber": 1},
    {"ETag": $ETAG2, "PartNumber": 2}
  ]
}
EOF
assert "complete multipart upload" $AWS s3api complete-multipart-upload --bucket "$BUCKET" --key "manual-multipart.bin" --upload-id "$UPLOAD_ID" --multipart-upload "file://$COMPLETE_JSON"
assert "download completed multipart" $AWS s3 cp "s3://$BUCKET/manual-multipart.bin" "$TMPDIR/manual-multipart.download.bin"
assert_eq "completed multipart merged size" "$(($(wc -c < "$TMPDIR/mpart1.bin") + $(wc -c < "$TMPDIR/mpart2.bin")))" "$(wc -c < "$TMPDIR/manual-multipart.download.bin" | tr -d ' ')"

ABORT_ID=$($AWS s3api create-multipart-upload --bucket "$BUCKET" --key "abort-multipart.bin" --query UploadId --output text 2>/dev/null || true)
assert_eq "create abortable multipart upload id" "true" "$([ -n "$ABORT_ID" ] && [ "$ABORT_ID" != "None" ] && echo true || echo false)"
assert "abort multipart upload" $AWS s3api abort-multipart-upload --bucket "$BUCKET" --key "abort-multipart.bin" --upload-id "$ABORT_ID"
assert_fail "list-parts after abort should fail" $AWS s3api list-parts --bucket "$BUCKET" --key "abort-multipart.bin" --upload-id "$ABORT_ID"

# --- Copy object ---
assert "copy object same bucket" $AWS s3 cp "s3://$BUCKET/test.txt" "s3://$BUCKET/test-copy.txt"
assert "download copied object" $AWS s3 cp "s3://$BUCKET/test-copy.txt" "$TMPDIR/copy.txt"
assert_eq "copied content matches" "hello maxio" "$(cat "$TMPDIR/copy.txt")"
assert_file_exists "copied object on disk" "$DATA_DIR/buckets/$BUCKET/test-copy.txt"

# Copy object via s3api
OUTPUT=$($AWS s3api copy-object --bucket "$BUCKET" --key "api-copy.txt" --copy-source "$BUCKET/test.txt" 2>&1)
assert_eq "copy-object has ETag" "true" "$(echo "$OUTPUT" | grep -q "ETag" && echo true || echo false)"
assert "download api-copied object" $AWS s3 cp "s3://$BUCKET/api-copy.txt" "$TMPDIR/api-copy.txt"
assert_eq "api-copied content matches" "hello maxio" "$(cat "$TMPDIR/api-copy.txt")"

# --- Overwrite object ---
echo "updated content" > "$TMPDIR/updated.txt"
assert "overwrite object" $AWS s3 cp "$TMPDIR/updated.txt" "s3://$BUCKET/test.txt"
assert "download overwritten" $AWS s3 cp "s3://$BUCKET/test.txt" "$TMPDIR/overwritten.txt"
assert_eq "overwritten content" "updated content" "$(cat "$TMPDIR/overwritten.txt")"
assert_eq "on-disk overwritten content" "updated content" "$(cat "$DATA_DIR/buckets/$BUCKET/test.txt")"

# --- Range request tests ---
echo "abcdefghijklmnopqrstuvwxyz" > "$TMPDIR/alphabet.txt"
assert "upload range-test file" $AWS s3 cp "$TMPDIR/alphabet.txt" "s3://$BUCKET/alphabet.txt"

assert "get-object with range bytes=0-4" \
    $AWS s3api get-object --bucket "$BUCKET" --key "alphabet.txt" \
    --range "bytes=0-4" "$TMPDIR/range_out.txt"
assert_eq "range first 5 bytes" "abcde" "$(cat "$TMPDIR/range_out.txt")"

assert "get-object with range bytes=-3" \
    $AWS s3api get-object --bucket "$BUCKET" --key "alphabet.txt" \
    --range "bytes=-3" "$TMPDIR/range_suffix.txt"
assert_eq "range suffix 3 bytes" "yz" "$(cat "$TMPDIR/range_suffix.txt" | tr -d '\n')"

assert "get-object with open-end range bytes=23-" \
    $AWS s3api get-object --bucket "$BUCKET" --key "alphabet.txt" \
    --range "bytes=23-" "$TMPDIR/range_open.txt"
assert_eq "range open-end" "xyz" "$(cat "$TMPDIR/range_open.txt" | tr -d '\n')"

assert_fail "get-object with invalid range bytes=9999-" \
    $AWS s3api get-object --bucket "$BUCKET" --key "alphabet.txt" \
    --range "bytes=9999-" "$TMPDIR/range_invalid.txt"

assert "delete range-test file" $AWS s3 rm "s3://$BUCKET/alphabet.txt"

# --- Folder operations ---
assert "create folder via put-object" $AWS s3api put-object --bucket "$BUCKET" --key "empty-folder/" --content-length 0
assert_file_exists "folder marker exists on disk" "$DATA_DIR/buckets/$BUCKET/empty-folder/.folder"
assert_file_exists "folder marker meta exists on disk" "$DATA_DIR/buckets/$BUCKET/empty-folder/.folder.meta.json"

OUTPUT=$($AWS s3 ls "s3://$BUCKET/" 2>&1)
assert_eq "list shows folder prefix" "true" "$(echo "$OUTPUT" | grep -q "empty-folder/" && echo true || echo false)"

OUTPUT=$($AWS s3api head-object --bucket "$BUCKET" --key "empty-folder/" 2>&1)
assert_eq "head folder marker has zero size" "true" "$(echo "$OUTPUT" | grep -q '"ContentLength": 0' && echo true || echo false)"

assert "delete folder marker" $AWS s3api delete-object --bucket "$BUCKET" --key "empty-folder/"
assert_fail "head deleted folder marker" $AWS s3api head-object --bucket "$BUCKET" --key "empty-folder/"

# --- Checksum tests ---
echo "checksum test data" > "$TMPDIR/checksum.txt"

# PutObject with CRC32 checksum via s3api
CRC32_VALUE=$(python3 -c "
import binascii, base64
data = open('$TMPDIR/checksum.txt', 'rb').read()
crc = binascii.crc32(data) & 0xffffffff
print(base64.b64encode(crc.to_bytes(4, 'big')).decode())
")
OUTPUT=$($AWS s3api put-object --bucket "$BUCKET" --key "checksum.txt" \
    --body "$TMPDIR/checksum.txt" \
    --checksum-algorithm CRC32 \
    --checksum-crc32 "$CRC32_VALUE" 2>&1)
assert_eq "put-object with CRC32 checksum accepted" "true" "$(echo "$OUTPUT" | grep -q "ChecksumCRC32" && echo true || echo false)"

# HeadObject should return the checksum
OUTPUT=$($AWS s3api head-object --bucket "$BUCKET" --key "checksum.txt" --checksum-mode ENABLED 2>&1)
assert_eq "head-object returns CRC32 checksum" "true" "$(echo "$OUTPUT" | grep -q "ChecksumCRC32" && echo true || echo false)"

# PutObject with wrong checksum should fail
assert_fail "put-object with wrong CRC32 rejects" \
    $AWS s3api put-object --bucket "$BUCKET" --key "bad-checksum.txt" \
    --body "$TMPDIR/checksum.txt" \
    --checksum-algorithm CRC32 \
    --checksum-crc32 "AAAAAAAA"

# PutObject with SHA256 checksum
SHA256_VALUE=$(python3 -c "
import hashlib, base64
data = open('$TMPDIR/checksum.txt', 'rb').read()
print(base64.b64encode(hashlib.sha256(data).digest()).decode())
")
OUTPUT=$($AWS s3api put-object --bucket "$BUCKET" --key "checksum-sha256.txt" \
    --body "$TMPDIR/checksum.txt" \
    --checksum-algorithm SHA256 \
    --checksum-sha256 "$SHA256_VALUE" 2>&1)
assert_eq "put-object with SHA256 checksum accepted" "true" "$(echo "$OUTPUT" | grep -q "ChecksumSHA256" && echo true || echo false)"

# Cleanup checksum test objects
assert "delete checksum object" $AWS s3 rm "s3://$BUCKET/checksum.txt"
assert "delete sha256 checksum object" $AWS s3 rm "s3://$BUCKET/checksum-sha256.txt"

# --- Delete operations ---
assert "delete object" $AWS s3 rm "s3://$BUCKET/test.txt"
assert_file_not_exists "deleted object gone from disk" "$DATA_DIR/buckets/$BUCKET/test.txt"
assert_file_not_exists "deleted meta gone from disk" "$DATA_DIR/buckets/$BUCKET/test.txt.meta.json"
assert_fail "get deleted object" $AWS s3 cp "s3://$BUCKET/test.txt" "$TMPDIR/should-not-exist.txt"

assert "delete copied object" $AWS s3 rm "s3://$BUCKET/test-copy.txt"
assert "delete api-copied object" $AWS s3 rm "s3://$BUCKET/api-copy.txt"
assert "delete nested object" $AWS s3 rm "s3://$BUCKET/folder/nested/file.txt"
assert_file_not_exists "deleted nested object gone from disk" "$DATA_DIR/buckets/$BUCKET/folder/nested/file.txt"
assert "delete large object" $AWS s3 rm "s3://$BUCKET/big.bin"
assert "delete manual multipart object" $AWS s3 rm "s3://$BUCKET/manual-multipart.bin"

# --- Erasure coding corruption detection ---
echo "hello erasure" > "$TMPDIR/ec-test.txt"
assert "upload ec test object" $AWS s3 cp "$TMPDIR/ec-test.txt" "s3://$BUCKET/ec-test.txt"

EC_DIR="$DATA_DIR/buckets/$BUCKET/ec-test.txt.ec"
if [ -d "$EC_DIR" ]; then
    assert_file_exists "ec chunk dir exists" "$EC_DIR"
    assert_file_exists "ec manifest exists" "$EC_DIR/manifest.json"

    # Verify download works before corruption
    assert "download ec object before corruption" $AWS s3 cp "s3://$BUCKET/ec-test.txt" "$TMPDIR/ec-before.txt"
    assert_eq "ec content before corruption" "hello erasure" "$(cat "$TMPDIR/ec-before.txt")"

    # Corrupt the first chunk
    printf "CORRUPTED" > "$EC_DIR/000000"

    # Download should fail due to checksum mismatch
    assert_fail "download ec object after corruption fails" $AWS s3 cp "s3://$BUCKET/ec-test.txt" "$TMPDIR/ec-after.txt"

    green "INFO: erasure coding corruption tests ran (server has EC enabled)"
else
    green "INFO: erasure coding corruption tests skipped (server has EC disabled)"
fi
assert "delete ec test object" $AWS s3 rm "s3://$BUCKET/ec-test.txt"

# Delete bucket
assert "delete empty bucket" $AWS s3 rb "s3://$BUCKET"
assert_file_not_exists "bucket dir gone from disk" "$DATA_DIR/buckets/$BUCKET"
assert_fail "head deleted bucket" $AWS s3api head-bucket --bucket "$BUCKET"

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
