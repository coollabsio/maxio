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

export AWS_ACCESS_KEY_ID=maxioadmin
export AWS_SECRET_ACCESS_KEY=maxioadmin
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

# --- UploadPartCopy ---
# Prepare a source object large enough to serve as multipart copy parts (5 MiB + 1 KiB)
dd if=/dev/urandom of="$TMPDIR/upc-source.bin" bs=1M count=5 status=none
dd if=/dev/urandom of="$TMPDIR/upc-tail.bin" bs=1024 count=1 status=none
cat "$TMPDIR/upc-source.bin" "$TMPDIR/upc-tail.bin" > "$TMPDIR/upc-full.bin"
assert "upload upc source object" $AWS s3 cp "$TMPDIR/upc-full.bin" "s3://$BUCKET/upc-source.bin"

UPC_SIZE=$(wc -c < "$TMPDIR/upc-full.bin" | tr -d ' ')
UPC_PART1_END=$((5 * 1024 * 1024 - 1))
UPC_PART2_START=$((5 * 1024 * 1024))
UPC_PART2_END=$((UPC_SIZE - 1))

UPC_UPLOAD_ID=$($AWS s3api create-multipart-upload --bucket "$BUCKET" --key "upc-dest.bin" --query UploadId --output text 2>/dev/null || true)
assert_eq "upc create multipart upload id" "true" "$([ -n "$UPC_UPLOAD_ID" ] && [ "$UPC_UPLOAD_ID" != "None" ] && echo true || echo false)"

UPC_ETAG1=$($AWS s3api upload-part-copy \
  --bucket "$BUCKET" --key "upc-dest.bin" \
  --upload-id "$UPC_UPLOAD_ID" --part-number 1 \
  --copy-source "$BUCKET/upc-source.bin" \
  --copy-source-range "bytes=0-$UPC_PART1_END" \
  --query CopyPartResult.ETag --output text 2>/dev/null || true)
assert_eq "upc part 1 etag present" "true" "$([ -n "$UPC_ETAG1" ] && [ "$UPC_ETAG1" != "None" ] && echo true || echo false)"

UPC_ETAG2=$($AWS s3api upload-part-copy \
  --bucket "$BUCKET" --key "upc-dest.bin" \
  --upload-id "$UPC_UPLOAD_ID" --part-number 2 \
  --copy-source "$BUCKET/upc-source.bin" \
  --copy-source-range "bytes=$UPC_PART2_START-$UPC_PART2_END" \
  --query CopyPartResult.ETag --output text 2>/dev/null || true)
assert_eq "upc part 2 etag present" "true" "$([ -n "$UPC_ETAG2" ] && [ "$UPC_ETAG2" != "None" ] && echo true || echo false)"

UPC_COMPLETE_JSON="$TMPDIR/upc-complete.json"
cat > "$UPC_COMPLETE_JSON" <<EOF
{
  "Parts": [
    {"ETag": $UPC_ETAG1, "PartNumber": 1},
    {"ETag": $UPC_ETAG2, "PartNumber": 2}
  ]
}
EOF
assert "upc complete multipart upload" $AWS s3api complete-multipart-upload \
  --bucket "$BUCKET" --key "upc-dest.bin" \
  --upload-id "$UPC_UPLOAD_ID" \
  --multipart-upload "file://$UPC_COMPLETE_JSON"

assert "upc download result" $AWS s3 cp "s3://$BUCKET/upc-dest.bin" "$TMPDIR/upc-download.bin"
assert_eq "upc result size matches source" "$UPC_SIZE" "$(wc -c < "$TMPDIR/upc-download.bin" | tr -d ' ')"
assert_eq "upc result content matches source" "$(md5sum "$TMPDIR/upc-full.bin" | cut -d' ' -f1)" "$(md5sum "$TMPDIR/upc-download.bin" | cut -d' ' -f1)"

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

# --- Conditional request headers ---
echo "conditional test" > "$TMPDIR/cond.txt"
assert "upload conditional test object" $AWS s3 cp "$TMPDIR/cond.txt" "s3://$BUCKET/cond.txt"

# Capture ETag (strip surrounding quotes from JSON output)
COND_ETAG=$($AWS s3api head-object --bucket "$BUCKET" --key "cond.txt" --query ETag --output text 2>/dev/null)

# If-Match: matching ETag → 200
assert "get-object if-match correct etag" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-match "$COND_ETAG" "$TMPDIR/cond-out.txt"

# If-Match: wrong ETag → 412 Precondition Failed
assert_fail "get-object if-match wrong etag returns 412" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-match '"wrongetag000000000000000000000000"' "$TMPDIR/cond-out.txt"

# If-None-Match: matching ETag → 304 (AWS CLI treats this as a failure/error exit)
assert_fail "get-object if-none-match matching etag returns 304" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-none-match "$COND_ETAG" "$TMPDIR/cond-out.txt"

# If-None-Match: non-matching ETag → 200
assert "get-object if-none-match different etag succeeds" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-none-match '"wrongetag000000000000000000000000"' "$TMPDIR/cond-out.txt"

# If-Modified-Since: far future date → 304 (object was not modified since then)
assert_fail "get-object if-modified-since future returns 304" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-modified-since "Mon, 01 Jan 2099 00:00:00 GMT" "$TMPDIR/cond-out.txt"

# If-Modified-Since: past date → 200 (object was modified after that date)
assert "get-object if-modified-since past succeeds" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-modified-since "Mon, 01 Jan 2000 00:00:00 GMT" "$TMPDIR/cond-out.txt"

# If-Unmodified-Since: far future date → 200 (object has not been modified since)
assert "get-object if-unmodified-since future succeeds" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-unmodified-since "Mon, 01 Jan 2099 00:00:00 GMT" "$TMPDIR/cond-out.txt"

# If-Unmodified-Since: past date → 412 (object was modified after threshold)
assert_fail "get-object if-unmodified-since past returns 412" \
    $AWS s3api get-object --bucket "$BUCKET" --key "cond.txt" \
    --if-unmodified-since "Mon, 01 Jan 2000 00:00:00 GMT" "$TMPDIR/cond-out.txt"

# Same conditions on HeadObject
assert "head-object if-match correct etag" \
    $AWS s3api head-object --bucket "$BUCKET" --key "cond.txt" \
    --if-match "$COND_ETAG"

assert_fail "head-object if-match wrong etag returns 412" \
    $AWS s3api head-object --bucket "$BUCKET" --key "cond.txt" \
    --if-match '"wrongetag000000000000000000000000"'

assert_fail "head-object if-none-match matching etag returns 304" \
    $AWS s3api head-object --bucket "$BUCKET" --key "cond.txt" \
    --if-none-match "$COND_ETAG"

assert "delete conditional test object" $AWS s3 rm "s3://$BUCKET/cond.txt"

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

# --- Reject rb on non-empty bucket ---
NON_EMPTY_BUCKET="nonempty-$$"
assert "create non-empty test bucket" $AWS s3api create-bucket --bucket "$NON_EMPTY_BUCKET"
echo "stay" > "$TMPDIR/stay.txt"
assert "put object into non-empty bucket" $AWS s3 cp "$TMPDIR/stay.txt" "s3://$NON_EMPTY_BUCKET/stay.txt"
assert_fail "rb on non-empty bucket rejected" \
    $AWS s3api delete-bucket --bucket "$NON_EMPTY_BUCKET"
assert "head-bucket still succeeds after failed rb" \
    $AWS s3api head-bucket --bucket "$NON_EMPTY_BUCKET"
$AWS s3 rm "s3://$NON_EMPTY_BUCKET/stay.txt" > /dev/null
assert "rb succeeds after emptying" $AWS s3api delete-bucket --bucket "$NON_EMPTY_BUCKET"

# --- CORS tests ---
CORS_BUCKET="cors-test-$$"
assert "create cors test bucket" $AWS s3api create-bucket --bucket "$CORS_BUCKET"

# GetBucketCors on bucket with no CORS config should return an error
assert_fail "get-bucket-cors on unconfigured bucket fails" \
    $AWS s3api get-bucket-cors --bucket "$CORS_BUCKET"

# PutBucketCors
cat > "$TMPDIR/cors.json" <<'EOF'
{
  "CORSRules": [
    {
      "AllowedOrigins": ["*"],
      "AllowedMethods": ["GET", "PUT"],
      "AllowedHeaders": ["*"],
      "MaxAgeSeconds": 3600
    }
  ]
}
EOF
assert "put-bucket-cors" \
    $AWS s3api put-bucket-cors --bucket "$CORS_BUCKET" --cors-configuration file://"$TMPDIR/cors.json"

# GetBucketCors — should succeed now
assert "get-bucket-cors succeeds after put" \
    $AWS s3api get-bucket-cors --bucket "$CORS_BUCKET"

# Verify content via curl preflight
PREFLIGHT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: GET" \
    "$ENDPOINT/$CORS_BUCKET/test-object.txt")
if [ "$PREFLIGHT_STATUS" = "200" ]; then
    green "PASS: CORS preflight returns 200"
    PASS=$((PASS + 1))
else
    red "FAIL: CORS preflight returned $PREFLIGHT_STATUS (expected 200)"
    FAIL=$((FAIL + 1))
fi

# Preflight without CORS config should return 403
NOCORS_BUCKET="no-cors-$$"
assert "create no-cors bucket" $AWS s3api create-bucket --bucket "$NOCORS_BUCKET"
NOCORS_PREFLIGHT=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS \
    -H "Origin: http://example.com" \
    -H "Access-Control-Request-Method: GET" \
    "$ENDPOINT/$NOCORS_BUCKET/test.txt")
if [ "$NOCORS_PREFLIGHT" = "403" ]; then
    green "PASS: CORS preflight without config returns 403"
    PASS=$((PASS + 1))
else
    red "FAIL: CORS preflight without config returned $NOCORS_PREFLIGHT (expected 403)"
    FAIL=$((FAIL + 1))
fi

# DeleteBucketCors
assert "delete-bucket-cors" \
    $AWS s3api delete-bucket-cors --bucket "$CORS_BUCKET"

# GetBucketCors after delete should fail again
assert_fail "get-bucket-cors fails after delete" \
    $AWS s3api get-bucket-cors --bucket "$CORS_BUCKET"

# Cleanup CORS test buckets
assert "delete cors test bucket" $AWS s3api delete-bucket --bucket "$CORS_BUCKET"
assert "delete no-cors test bucket" $AWS s3api delete-bucket --bucket "$NOCORS_BUCKET"

# --- Server-Side Encryption (SSE) ---
echo ""
echo "--- SSE tests ---"
ENC_BUCKET="enc-$$"
assert "create SSE bucket" $AWS s3api create-bucket --bucket "$ENC_BUCKET"

# SSE-S3 (AES256)
echo "hello sse-s3" > "$TMPDIR/sse-s3.txt"
SSE_S3_OUT=$($AWS s3api put-object --bucket "$ENC_BUCKET" --key sse-s3.txt \
    --body "$TMPDIR/sse-s3.txt" --server-side-encryption AES256 2>&1)
assert_eq "SSE-S3 PUT echoes ServerSideEncryption=AES256" \
    "AES256" "$(echo "$SSE_S3_OUT" | grep -o '"ServerSideEncryption": "[^"]*"' | cut -d'"' -f4)"

# Verify on-disk content != plaintext
DISK_BYTES=$(head -c 12 "$DATA_DIR/buckets/$ENC_BUCKET/sse-s3.txt" 2>/dev/null | od -An -tx1 | tr -d ' \n')
PLAIN_HEX=$(head -c 12 "$TMPDIR/sse-s3.txt" 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$DISK_BYTES" != "$PLAIN_HEX" ] && [ -n "$DISK_BYTES" ]; then
    green "PASS: SSE-S3 on-disk is ciphertext (not plaintext)"
    PASS=$((PASS + 1))
else
    red "FAIL: SSE-S3 on-disk matches plaintext (disk=$DISK_BYTES plain=$PLAIN_HEX)"
    FAIL=$((FAIL + 1))
fi

# Metadata sidecar carries encryption block
if grep -q '"mode": "sse_s3"' "$DATA_DIR/buckets/$ENC_BUCKET/sse-s3.txt.meta.json" 2>/dev/null; then
    green "PASS: SSE-S3 meta.json has mode=sse_s3"
    PASS=$((PASS + 1))
else
    red "FAIL: SSE-S3 meta.json missing mode=sse_s3"
    FAIL=$((FAIL + 1))
fi

# HEAD echoes the header
HEAD_OUT=$($AWS s3api head-object --bucket "$ENC_BUCKET" --key sse-s3.txt 2>&1)
assert_eq "SSE-S3 HEAD echoes ServerSideEncryption=AES256" \
    "AES256" "$(echo "$HEAD_OUT" | grep -o '"ServerSideEncryption": "[^"]*"' | cut -d'"' -f4)"

# GET roundtrip
$AWS s3api get-object --bucket "$ENC_BUCKET" --key sse-s3.txt "$TMPDIR/sse-s3-out.txt" > /dev/null
if cmp -s "$TMPDIR/sse-s3.txt" "$TMPDIR/sse-s3-out.txt"; then
    green "PASS: SSE-S3 GET roundtrip matches"
    PASS=$((PASS + 1))
else
    red "FAIL: SSE-S3 GET roundtrip differs"
    FAIL=$((FAIL + 1))
fi

# Range GET across ciphertext frame boundary is only meaningful > 64K — do a
# small range check that still exercises FrameDecryptor range translation.
RANGE_OUT=$($AWS s3api get-object --bucket "$ENC_BUCKET" --key sse-s3.txt \
    --range "bytes=0-4" "$TMPDIR/sse-s3-range.txt" 2>&1 || true)
assert_eq "SSE-S3 range GET returns first 5 bytes" "hello" "$(cat "$TMPDIR/sse-s3-range.txt")"

# SSE-C (customer-supplied key)
SSEC_KEY_B64=$(openssl rand 32 | base64)
SSEC_KEY_MD5=$(echo -n "$SSEC_KEY_B64" | base64 -d | openssl dgst -md5 -binary | base64)
echo "hello sse-c" > "$TMPDIR/sse-c.txt"
SSE_C_OUT=$($AWS s3api put-object --bucket "$ENC_BUCKET" --key sse-c.txt \
    --body "$TMPDIR/sse-c.txt" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$SSEC_KEY_B64" \
    --sse-customer-key-md5 "$SSEC_KEY_MD5" 2>&1)
assert_eq "SSE-C PUT echoes SSECustomerAlgorithm=AES256" \
    "AES256" "$(echo "$SSE_C_OUT" | grep -o '"SSECustomerAlgorithm": "[^"]*"' | cut -d'"' -f4)"

# GET without key must fail
assert_fail "SSE-C GET without customer key fails" \
    $AWS s3api get-object --bucket "$ENC_BUCKET" --key sse-c.txt "$TMPDIR/sse-c-nokey.txt"

# GET with wrong key must fail
WRONG_KEY=$(openssl rand 32 | base64)
WRONG_MD5=$(echo -n "$WRONG_KEY" | base64 -d | openssl dgst -md5 -binary | base64)
assert_fail "SSE-C GET with wrong key fails" \
    $AWS s3api get-object --bucket "$ENC_BUCKET" --key sse-c.txt \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$WRONG_KEY" \
    --sse-customer-key-md5 "$WRONG_MD5" \
    "$TMPDIR/sse-c-wrong.txt"

# GET with correct key succeeds
$AWS s3api get-object --bucket "$ENC_BUCKET" --key sse-c.txt \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$SSEC_KEY_B64" \
    --sse-customer-key-md5 "$SSEC_KEY_MD5" \
    "$TMPDIR/sse-c-out.txt" > /dev/null
if cmp -s "$TMPDIR/sse-c.txt" "$TMPDIR/sse-c-out.txt"; then
    green "PASS: SSE-C GET with correct key matches"
    PASS=$((PASS + 1))
else
    red "FAIL: SSE-C GET with correct key differs"
    FAIL=$((FAIL + 1))
fi

# Bucket default encryption → unencrypted-request PUT gets encrypted anyway
DEFAULT_BUCKET="enc-default-$$"
assert "create default-encryption bucket" $AWS s3api create-bucket --bucket "$DEFAULT_BUCKET"
assert "put-bucket-encryption AES256" $AWS s3api put-bucket-encryption \
    --bucket "$DEFAULT_BUCKET" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# get-bucket-encryption roundtrip
GET_ENC_OUT=$($AWS s3api get-bucket-encryption --bucket "$DEFAULT_BUCKET" 2>&1)
assert_eq "get-bucket-encryption returns AES256" \
    "AES256" "$(echo "$GET_ENC_OUT" | grep -o '"SSEAlgorithm": "[^"]*"' | cut -d'"' -f4)"

# Plain PUT (no SSE headers) should be encrypted via bucket default
echo "inherit default" > "$TMPDIR/default.txt"
DEF_PUT_OUT=$($AWS s3api put-object --bucket "$DEFAULT_BUCKET" --key default.txt \
    --body "$TMPDIR/default.txt" 2>&1)
assert_eq "bucket-default PUT echoes ServerSideEncryption=AES256" \
    "AES256" "$(echo "$DEF_PUT_OUT" | grep -o '"ServerSideEncryption": "[^"]*"' | cut -d'"' -f4)"
if grep -q '"mode": "sse_s3"' "$DATA_DIR/buckets/$DEFAULT_BUCKET/default.txt.meta.json" 2>/dev/null; then
    green "PASS: bucket-default meta.json has mode=sse_s3"
    PASS=$((PASS + 1))
else
    red "FAIL: bucket-default meta.json missing mode=sse_s3"
    FAIL=$((FAIL + 1))
fi

# delete-bucket-encryption
assert "delete-bucket-encryption" \
    $AWS s3api delete-bucket-encryption --bucket "$DEFAULT_BUCKET"
assert_fail "get-bucket-encryption fails after delete" \
    $AWS s3api get-bucket-encryption --bucket "$DEFAULT_BUCKET"

# SSE-KMS is rejected (feature removed — AES256 only)
echo "hello sse-kms" > "$TMPDIR/sse-kms.txt"
KMS_OUT=$($AWS s3api put-object --bucket "$ENC_BUCKET" --key sse-kms.txt \
    --body "$TMPDIR/sse-kms.txt" --server-side-encryption aws:kms 2>&1 || true)
if echo "$KMS_OUT" | grep -q "InvalidEncryptionAlgorithm"; then
    green "PASS: PUT with --server-side-encryption aws:kms rejected"
    PASS=$((PASS + 1))
else
    red "FAIL: expected InvalidEncryptionAlgorithm for aws:kms, got: $KMS_OUT"
    FAIL=$((FAIL + 1))
fi

# SSE multipart upload (> 5 MiB part so it exercises complete-multipart encryption path)
MP_BUCKET="enc-mp-$$"
assert "create MP SSE bucket" $AWS s3api create-bucket --bucket "$MP_BUCKET"
dd if=/dev/urandom of="$TMPDIR/mp.bin" bs=1M count=6 2>/dev/null
assert "multipart PUT with SSE-S3 (uses cp for simplicity)" \
    $AWS s3 cp "$TMPDIR/mp.bin" "s3://$MP_BUCKET/mp.bin" --sse AES256
$AWS s3 cp "s3://$MP_BUCKET/mp.bin" "$TMPDIR/mp-out.bin" > /dev/null
if cmp -s "$TMPDIR/mp.bin" "$TMPDIR/mp-out.bin"; then
    green "PASS: SSE-S3 multipart roundtrip matches"
    PASS=$((PASS + 1))
else
    red "FAIL: SSE-S3 multipart roundtrip differs"
    FAIL=$((FAIL + 1))
fi

# Invalid SSE algorithm must be rejected (InvalidEncryptionAlgorithm)
BAD_ALGO_OUT=$($AWS s3api put-object --bucket "$ENC_BUCKET" --key bad-algo.txt \
    --body "$TMPDIR/sse-s3.txt" --server-side-encryption AES512 2>&1 || true)
if echo "$BAD_ALGO_OUT" | grep -q "InvalidEncryptionAlgorithm"; then
    green "PASS: PUT with bogus server-side-encryption algorithm rejected"
    PASS=$((PASS + 1))
else
    red "FAIL: bogus SSE algorithm not rejected — got: $BAD_ALGO_OUT"
    FAIL=$((FAIL + 1))
fi

# Cleanup SSE objects + buckets
$AWS s3 rm "s3://$ENC_BUCKET/sse-s3.txt" > /dev/null || true
$AWS s3 rm "s3://$ENC_BUCKET/sse-c.txt" > /dev/null || true
$AWS s3 rm "s3://$ENC_BUCKET/sse-kms.txt" > /dev/null || true
$AWS s3 rm "s3://$DEFAULT_BUCKET/default.txt" > /dev/null || true
$AWS s3 rm "s3://$MP_BUCKET/mp.bin" > /dev/null || true
assert "delete SSE bucket" $AWS s3api delete-bucket --bucket "$ENC_BUCKET"
assert "delete default-encryption bucket" $AWS s3api delete-bucket --bucket "$DEFAULT_BUCKET"
assert "delete MP SSE bucket" $AWS s3api delete-bucket --bucket "$MP_BUCKET"

# --- EC + SSE composition ---
echo ""
echo "--- EC + SSE composition tests ---"
EC_SSE_BUCKET="ec-sse-$$"
assert "create ec+sse bucket" $AWS s3api create-bucket --bucket "$EC_SSE_BUCKET"

# Probe: plaintext PUT; presence of .ec/ directory indicates server has EC on.
echo "probe" > "$TMPDIR/ec-sse-probe.txt"
$AWS s3 cp "$TMPDIR/ec-sse-probe.txt" "s3://$EC_SSE_BUCKET/probe.txt" > /dev/null
EC_SSE_PROBE_DIR="$DATA_DIR/buckets/$EC_SSE_BUCKET/probe.txt.ec"
$AWS s3 rm "s3://$EC_SSE_BUCKET/probe.txt" > /dev/null 2>&1 || true

if [ -d "$EC_SSE_PROBE_DIR" ]; then
    # 1. Small object — EC + SSE-S3 round-trip
    echo "hello ec+sse-s3" > "$TMPDIR/ec-sse-s3.txt"
    $AWS s3api put-object --bucket "$EC_SSE_BUCKET" --key small.txt \
        --body "$TMPDIR/ec-sse-s3.txt" --server-side-encryption AES256 > /dev/null
    assert_file_exists "EC+SSE small chunks dir" "$DATA_DIR/buckets/$EC_SSE_BUCKET/small.txt.ec"
    assert_file_exists "EC+SSE small manifest" "$DATA_DIR/buckets/$EC_SSE_BUCKET/small.txt.ec/manifest.json"
    if grep -q '"mode": "sse_s3"' "$DATA_DIR/buckets/$EC_SSE_BUCKET/small.txt.meta.json" 2>/dev/null; then
        green "PASS: EC+SSE small meta has mode=sse_s3"; PASS=$((PASS+1))
    else
        red "FAIL: EC+SSE small meta missing mode=sse_s3"; FAIL=$((FAIL+1))
    fi
    DISK_HEX=$(head -c 12 "$DATA_DIR/buckets/$EC_SSE_BUCKET/small.txt.ec/000000" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    PLAIN_HEX=$(head -c 12 "$TMPDIR/ec-sse-s3.txt" | od -An -tx1 | tr -d ' \n')
    if [ "$DISK_HEX" != "$PLAIN_HEX" ] && [ -n "$DISK_HEX" ]; then
        green "PASS: EC+SSE chunk contents are ciphertext"; PASS=$((PASS+1))
    else
        red "FAIL: EC+SSE chunk 000000 appears to be plaintext (disk=$DISK_HEX plain=$PLAIN_HEX)"; FAIL=$((FAIL+1))
    fi
    $AWS s3api get-object --bucket "$EC_SSE_BUCKET" --key small.txt "$TMPDIR/ec-sse-s3-out.txt" > /dev/null
    if cmp -s "$TMPDIR/ec-sse-s3.txt" "$TMPDIR/ec-sse-s3-out.txt"; then
        green "PASS: EC+SSE-S3 small round-trip"; PASS=$((PASS+1))
    else
        red "FAIL: EC+SSE-S3 small round-trip differs"; FAIL=$((FAIL+1))
    fi

    # 2. Large object — EC + SSE-S3 multi-chunk multi-frame round-trip (8 MiB)
    dd if=/dev/urandom of="$TMPDIR/ec-sse-big.bin" bs=1M count=8 status=none
    assert "EC+SSE-S3 large PUT" $AWS s3 cp "$TMPDIR/ec-sse-big.bin" \
        "s3://$EC_SSE_BUCKET/big.bin" --sse AES256
    assert "EC+SSE-S3 large GET" $AWS s3 cp "s3://$EC_SSE_BUCKET/big.bin" "$TMPDIR/ec-sse-big.out"
    assert_eq "EC+SSE-S3 large md5 matches" \
        "$(md5sum "$TMPDIR/ec-sse-big.bin" | cut -d' ' -f1)" \
        "$(md5sum "$TMPDIR/ec-sse-big.out" | cut -d' ' -f1)"

    # 3. Range read across chunk + frame boundaries
    RNG_START=1000000; RNG_END=1009999
    $AWS s3api get-object --bucket "$EC_SSE_BUCKET" --key big.bin \
        --range "bytes=${RNG_START}-${RNG_END}" "$TMPDIR/ec-sse-range.out" > /dev/null
    dd if="$TMPDIR/ec-sse-big.bin" of="$TMPDIR/ec-sse-range.expect" \
        bs=1 skip=$RNG_START count=10000 status=none
    if cmp -s "$TMPDIR/ec-sse-range.out" "$TMPDIR/ec-sse-range.expect"; then
        green "PASS: EC+SSE-S3 range read"; PASS=$((PASS+1))
    else
        red "FAIL: EC+SSE-S3 range read differs"; FAIL=$((FAIL+1))
    fi

    # 4. SSE-C + EC round-trip
    EC_SSEC_KEY=$(openssl rand 32 | base64)
    EC_SSEC_MD5=$(echo -n "$EC_SSEC_KEY" | base64 -d | openssl dgst -md5 -binary | base64)
    echo "hello ec+sse-c" > "$TMPDIR/ec-sse-c.txt"
    $AWS s3api put-object --bucket "$EC_SSE_BUCKET" --key ssec.txt \
        --body "$TMPDIR/ec-sse-c.txt" \
        --sse-customer-algorithm AES256 \
        --sse-customer-key "$EC_SSEC_KEY" --sse-customer-key-md5 "$EC_SSEC_MD5" > /dev/null
    $AWS s3api get-object --bucket "$EC_SSE_BUCKET" --key ssec.txt \
        --sse-customer-algorithm AES256 \
        --sse-customer-key "$EC_SSEC_KEY" --sse-customer-key-md5 "$EC_SSEC_MD5" \
        "$TMPDIR/ec-sse-c.out" > /dev/null
    if cmp -s "$TMPDIR/ec-sse-c.txt" "$TMPDIR/ec-sse-c.out"; then
        green "PASS: EC+SSE-C round-trip"; PASS=$((PASS+1))
    else
        red "FAIL: EC+SSE-C round-trip differs"; FAIL=$((FAIL+1))
    fi
    assert_fail "EC+SSE-C GET without key fails" \
        $AWS s3api get-object --bucket "$EC_SSE_BUCKET" --key ssec.txt "$TMPDIR/ec-sse-c-nokey"

    # 5. Bucket-default encryption + EC
    $AWS s3api put-bucket-encryption --bucket "$EC_SSE_BUCKET" \
        --server-side-encryption-configuration \
        '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' > /dev/null
    echo "default ec+sse" > "$TMPDIR/ec-default.txt"
    DEF_OUT=$($AWS s3api put-object --bucket "$EC_SSE_BUCKET" --key default.txt \
        --body "$TMPDIR/ec-default.txt" 2>&1)
    assert_eq "EC+bucket-default PUT echoes AES256" "AES256" \
        "$(echo "$DEF_OUT" | grep -o '"ServerSideEncryption": "[^"]*"' | cut -d'"' -f4)"
    $AWS s3api get-object --bucket "$EC_SSE_BUCKET" --key default.txt "$TMPDIR/ec-default.out" > /dev/null
    if cmp -s "$TMPDIR/ec-default.txt" "$TMPDIR/ec-default.out"; then
        green "PASS: EC+bucket-default round-trip"; PASS=$((PASS+1))
    else
        red "FAIL: EC+bucket-default round-trip differs"; FAIL=$((FAIL+1))
    fi
    $AWS s3api delete-bucket-encryption --bucket "$EC_SSE_BUCKET" > /dev/null

    # 6. Corruption + RS recovery under encryption (only if parity present)
    MANIFEST_JSON="$DATA_DIR/buckets/$EC_SSE_BUCKET/big.bin.ec/manifest.json"
    PARITY_COUNT=$(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(m.get('parity_shards') or 0)" "$MANIFEST_JSON" 2>/dev/null || echo 0)
    if [ "$PARITY_COUNT" -gt 0 ]; then
        CHUNK0="$DATA_DIR/buckets/$EC_SSE_BUCKET/big.bin.ec/000000"
        SZ=$(stat -f%z "$CHUNK0" 2>/dev/null || stat -c%s "$CHUNK0")
        dd if=/dev/zero of="$CHUNK0" bs=1 count=$SZ conv=notrunc status=none
        assert "EC+SSE GET recovers from one zeroed chunk via RS" \
            $AWS s3 cp "s3://$EC_SSE_BUCKET/big.bin" "$TMPDIR/ec-sse-recover.out"
        assert_eq "EC+SSE recovered content md5 matches original" \
            "$(md5sum "$TMPDIR/ec-sse-big.bin" | cut -d' ' -f1)" \
            "$(md5sum "$TMPDIR/ec-sse-recover.out" | cut -d' ' -f1)"

        # 7. Bit-flip one ciphertext byte AND patch manifest SHA — AEAD must
        #    still reject even when chunk integrity check is bypassed.
        python3 - "$MANIFEST_JSON" "$DATA_DIR/buckets/$EC_SSE_BUCKET/big.bin.ec/000001" <<'PY'
import json, sys, hashlib
mf, chunk = sys.argv[1], sys.argv[2]
with open(chunk, "rb") as f: data = bytearray(f.read())
data[10] ^= 0xFF
with open(chunk, "wb") as f: f.write(data)
m = json.load(open(mf))
m["chunks"][1]["sha256"] = hashlib.sha256(data).hexdigest()
json.dump(m, open(mf, "w"))
PY
        assert_fail "EC+SSE GET rejects AEAD-tampered chunk (even with matching SHA)" \
            $AWS s3 cp "s3://$EC_SSE_BUCKET/big.bin" "$TMPDIR/ec-sse-tampered.out"
    else
        green "INFO: skipping EC+SSE RS-recovery tests (server has parity_shards=0)"
    fi

    # Cleanup
    $AWS s3 rm "s3://$EC_SSE_BUCKET/small.txt" > /dev/null 2>&1 || true
    $AWS s3 rm "s3://$EC_SSE_BUCKET/big.bin"   > /dev/null 2>&1 || true
    $AWS s3api delete-object --bucket "$EC_SSE_BUCKET" --key ssec.txt \
        --sse-customer-algorithm AES256 \
        --sse-customer-key "$EC_SSEC_KEY" --sse-customer-key-md5 "$EC_SSEC_MD5" \
        > /dev/null 2>&1 || true
    $AWS s3 rm "s3://$EC_SSE_BUCKET/default.txt" > /dev/null 2>&1 || true

    green "INFO: EC + SSE composition tests ran (server has EC enabled)"
else
    green "INFO: EC + SSE composition tests skipped (server has EC disabled)"
fi
assert "delete ec+sse bucket" $AWS s3api delete-bucket --bucket "$EC_SSE_BUCKET"

# --- Encryption transition: plaintext → enable → disable ---
echo ""
echo "--- Encryption transition tests ---"
TRANS_BUCKET="enc-trans-$$"
assert "create transition bucket (no encryption)" \
    $AWS s3api create-bucket --bucket "$TRANS_BUCKET"

# 1. Plaintext PUT before encryption is configured
echo "plaintext-before" > "$TMPDIR/before.txt"
assert "PUT file-A (plaintext, no bucket encryption)" \
    $AWS s3api put-object --bucket "$TRANS_BUCKET" --key before.txt \
    --body "$TMPDIR/before.txt"
assert_eq "before.txt stored as plaintext on disk" \
    "plaintext-before" "$(cat "$DATA_DIR/buckets/$TRANS_BUCKET/before.txt")"
if grep -q '"mode"' "$DATA_DIR/buckets/$TRANS_BUCKET/before.txt.meta.json" 2>/dev/null; then
    red "FAIL: before.txt meta.json unexpectedly has encryption mode"
    FAIL=$((FAIL + 1))
else
    green "PASS: before.txt meta.json has no encryption mode"
    PASS=$((PASS + 1))
fi

# 2. Enable bucket default encryption (AES256 / SSE-S3)
assert "enable bucket default encryption" $AWS s3api put-bucket-encryption \
    --bucket "$TRANS_BUCKET" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# 3. Upload file-B (inherits bucket default → encrypted)
echo "encrypted-after" > "$TMPDIR/after.txt"
AFTER_PUT_OUT=$($AWS s3api put-object --bucket "$TRANS_BUCKET" --key after.txt \
    --body "$TMPDIR/after.txt" 2>&1)
assert_eq "after.txt PUT echoes ServerSideEncryption=AES256" \
    "AES256" "$(echo "$AFTER_PUT_OUT" | grep -o '"ServerSideEncryption": "[^"]*"' | cut -d'"' -f4)"
if grep -q '"mode": "sse_s3"' "$DATA_DIR/buckets/$TRANS_BUCKET/after.txt.meta.json" 2>/dev/null; then
    green "PASS: after.txt meta.json has mode=sse_s3"
    PASS=$((PASS + 1))
else
    red "FAIL: after.txt meta.json missing mode=sse_s3"
    FAIL=$((FAIL + 1))
fi

# 4. Both files readable while encryption enabled
$AWS s3api get-object --bucket "$TRANS_BUCKET" --key before.txt \
    "$TMPDIR/before-enc-on.txt" > /dev/null
assert_eq "before.txt readable (encryption enabled)" \
    "plaintext-before" "$(cat "$TMPDIR/before-enc-on.txt")"
$AWS s3api get-object --bucket "$TRANS_BUCKET" --key after.txt \
    "$TMPDIR/after-enc-on.txt" > /dev/null
assert_eq "after.txt readable (encryption enabled)" \
    "encrypted-after" "$(cat "$TMPDIR/after-enc-on.txt")"

# 5. Disable bucket default encryption
assert "disable bucket default encryption" \
    $AWS s3api delete-bucket-encryption --bucket "$TRANS_BUCKET"
assert_fail "get-bucket-encryption fails after disable" \
    $AWS s3api get-bucket-encryption --bucket "$TRANS_BUCKET"

# 6. Both files STILL readable after disable
$AWS s3api get-object --bucket "$TRANS_BUCKET" --key before.txt \
    "$TMPDIR/before-enc-off.txt" > /dev/null
assert_eq "before.txt readable (encryption disabled)" \
    "plaintext-before" "$(cat "$TMPDIR/before-enc-off.txt")"
$AWS s3api get-object --bucket "$TRANS_BUCKET" --key after.txt \
    "$TMPDIR/after-enc-off.txt" > /dev/null
assert_eq "after.txt readable (encryption disabled)" \
    "encrypted-after" "$(cat "$TMPDIR/after-enc-off.txt")"

# Cleanup
$AWS s3 rm "s3://$TRANS_BUCKET/before.txt" > /dev/null || true
$AWS s3 rm "s3://$TRANS_BUCKET/after.txt" > /dev/null || true
assert "delete transition bucket" $AWS s3api delete-bucket --bucket "$TRANS_BUCKET"

# --- Keyring rotation (CLI) ---
echo ""
echo "--- Keyring rotate CLI tests ---"

# Locate the maxio binary (script runs against a pre-started server, so the
# binary path isn't passed in — try both debug and release).
MAXIO_BIN=""
for candidate in ./target/debug/maxio ./target/release/maxio; do
    if [ -x "$candidate" ]; then
        MAXIO_BIN="$candidate"
        break
    fi
done

if [ -z "$MAXIO_BIN" ]; then
    red "SKIP: keyring rotate tests (./target/debug/maxio and ./target/release/maxio not found)"
else
    KEYRING_FILE="$DATA_DIR/.maxio-keys.json"

    # Bucket + object before rotation (running server's active key wraps the DEK).
    ROT_BUCKET="rotate-$$"
    assert "create rotate bucket" $AWS s3api create-bucket --bucket "$ROT_BUCKET"
    echo "before rotation" > "$TMPDIR/pre.txt"
    PRE_OUT=$($AWS s3api put-object --bucket "$ROT_BUCKET" --key pre.txt \
        --body "$TMPDIR/pre.txt" --server-side-encryption AES256 2>&1)
    assert_eq "pre-rotation PUT got AES256" \
        "AES256" "$(echo "$PRE_OUT" | grep -o '"ServerSideEncryption": "[^"]*"' | cut -d'"' -f4)"

    PRE_KEY_ID=$(grep -o '"key_id": "[^"]*"' \
        "$DATA_DIR/buckets/$ROT_BUCKET/pre.txt.meta.json" | cut -d'"' -f4)
    if [ -n "$PRE_KEY_ID" ]; then
        green "PASS: pre.txt meta.json records key_id=$PRE_KEY_ID"
        PASS=$((PASS + 1))
    else
        red "FAIL: pre.txt meta.json missing key_id"
        FAIL=$((FAIL + 1))
    fi

    # `keyring list` before rotate shows one active key.
    LIST_BEFORE=$("$MAXIO_BIN" keyring list --data-dir "$DATA_DIR" 2>&1)
    YES_COUNT_BEFORE=$(echo "$LIST_BEFORE" | awk 'NR>1 && $3=="yes"{n++} END{print n+0}')
    assert_eq "pre-rotate: exactly 1 active key" "1" "$YES_COUNT_BEFORE"

    # Run the rotate CLI.
    ROTATE_OUT=$("$MAXIO_BIN" keyring rotate --data-dir "$DATA_DIR" 2>&1)
    if echo "$ROTATE_OUT" | grep -q "keyring rotated"; then
        green "PASS: rotate CLI output contains 'keyring rotated'"
        PASS=$((PASS + 1))
    else
        red "FAIL: rotate CLI output missing 'keyring rotated' — got: $ROTATE_OUT"
        FAIL=$((FAIL + 1))
    fi

    NEW_KEY_ID=$(echo "$ROTATE_OUT" | grep "new active key id:" | awk '{print $NF}')
    if [ -n "$NEW_KEY_ID" ] && [ "$NEW_KEY_ID" != "$PRE_KEY_ID" ]; then
        green "PASS: rotate produced a new distinct key_id $NEW_KEY_ID"
        PASS=$((PASS + 1))
    else
        red "FAIL: rotate key_id=$NEW_KEY_ID vs pre=$PRE_KEY_ID"
        FAIL=$((FAIL + 1))
    fi

    # File perms 0600 (Unix only).
    if [ "$(uname)" != "MINGW"* ] && [ "$(uname)" != "CYGWIN"* ]; then
        PERMS=$(stat -f '%Lp' "$KEYRING_FILE" 2>/dev/null || stat -c '%a' "$KEYRING_FILE")
        assert_eq "keyring file perms are 600 after rotate" "600" "$PERMS"
    fi

    # `keyring list` after: still exactly 1 active, total count is 2.
    LIST_AFTER=$("$MAXIO_BIN" keyring list --data-dir "$DATA_DIR" 2>&1)
    YES_COUNT_AFTER=$(echo "$LIST_AFTER" | awk 'NR>1 && $3=="yes"{n++} END{print n+0}')
    NO_COUNT_AFTER=$(echo "$LIST_AFTER" | awk 'NR>1 && $3=="no"{n++} END{print n+0}')
    assert_eq "post-rotate: exactly 1 active key" "1" "$YES_COUNT_AFTER"
    assert_eq "post-rotate: previous key demoted (1 inactive)" "1" "$NO_COUNT_AFTER"

    # Old object remains decryptable via the live server (its in-memory ring
    # still has the old active key). This verifies that writing a new key to
    # disk does NOT break the currently-running server's reads.
    $AWS s3api get-object --bucket "$ROT_BUCKET" --key pre.txt \
        "$TMPDIR/pre-out.txt" > /dev/null
    if cmp -s "$TMPDIR/pre.txt" "$TMPDIR/pre-out.txt"; then
        green "PASS: pre-rotation object still readable from live server after rotate"
        PASS=$((PASS + 1))
    else
        red "FAIL: pre-rotation object corrupted after rotate"
        FAIL=$((FAIL + 1))
    fi

    # Second rotate → 3 keys total, 1 active.
    "$MAXIO_BIN" keyring rotate --data-dir "$DATA_DIR" > /dev/null
    LIST_FINAL=$("$MAXIO_BIN" keyring list --data-dir "$DATA_DIR" 2>&1)
    TOTAL_FINAL=$(echo "$LIST_FINAL" | awk 'NR>1' | wc -l | tr -d ' ')
    assert_eq "second rotate: 3 keys total" "3" "$TOTAL_FINAL"

    # NOTE: verifying decryption AFTER a full restart (so the new key becomes
    # the in-memory active key while the old keys remain for unwrap) is covered
    # by the Rust integration test `test_keyring_rotate_preserves_old_objects`.
    # This shell test cannot restart the caller-owned server process.

    $AWS s3 rm "s3://$ROT_BUCKET/pre.txt" > /dev/null || true
    assert "delete rotate bucket" $AWS s3api delete-bucket --bucket "$ROT_BUCKET"
fi

# --- Object tagging ---
echo ""
echo "--- Object tagging tests ---"
TAG_BUCKET="tag-$$"
assert "create tag bucket" $AWS s3api create-bucket --bucket "$TAG_BUCKET"
echo "tagged" > "$TMPDIR/tag.txt"
assert "put object for tagging" $AWS s3api put-object \
    --bucket "$TAG_BUCKET" --key tag.txt --body "$TMPDIR/tag.txt"

# put-object-tagging
assert "put-object-tagging 2 tags" $AWS s3api put-object-tagging \
    --bucket "$TAG_BUCKET" --key tag.txt \
    --tagging 'TagSet=[{Key=env,Value=prod},{Key=app,Value=maxio}]'

# get-object-tagging roundtrip
TAG_GET=$($AWS s3api get-object-tagging --bucket "$TAG_BUCKET" --key tag.txt 2>&1)
assert_eq "get-object-tagging sees env=prod" "prod" \
    "$(echo "$TAG_GET" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(next((t["Value"] for t in d.get("TagSet",[]) if t["Key"]=="env"), ""))' 2>/dev/null)"
assert_eq "get-object-tagging sees app=maxio" "maxio" \
    "$(echo "$TAG_GET" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(next((t["Value"] for t in d.get("TagSet",[]) if t["Key"]=="app"), ""))' 2>/dev/null)"

# Storage sidecar carries tags
if grep -q '"tags"' "$DATA_DIR/buckets/$TAG_BUCKET/tag.txt.meta.json"; then
    green "PASS: tag.txt.meta.json records tags"
    PASS=$((PASS + 1))
else
    red "FAIL: tag.txt.meta.json missing tags"
    FAIL=$((FAIL + 1))
fi

# delete-object-tagging → empty tag set
assert "delete-object-tagging" $AWS s3api delete-object-tagging \
    --bucket "$TAG_BUCKET" --key tag.txt
TAG_AFTER=$($AWS s3api get-object-tagging --bucket "$TAG_BUCKET" --key tag.txt 2>&1)
TAG_AFTER_COUNT=$(echo "$TAG_AFTER" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("TagSet",[])))' 2>/dev/null)
assert_eq "get-object-tagging empty after delete" "0" "$TAG_AFTER_COUNT"

# NOTE: `put-object --tagging 'env=prod&...'` (x-amz-tagging header on PUT) is
# not yet implemented in MaxIO — only the separate PutObjectTagging API works.
# When that header lands, add an assertion here that verifies tags are set by
# PUT+header in one request.

$AWS s3 rm "s3://$TAG_BUCKET/tag.txt" > /dev/null || true
assert "delete tag bucket" $AWS s3api delete-bucket --bucket "$TAG_BUCKET"

# --- Batch DeleteObjects ---
echo ""
echo "--- Batch DeleteObjects tests ---"
BATCH_BUCKET="batch-$$"
assert "create batch bucket" $AWS s3api create-bucket --bucket "$BATCH_BUCKET"
echo "a" > "$TMPDIR/a.txt"
echo "b" > "$TMPDIR/b.txt"
echo "c" > "$TMPDIR/c.txt"
$AWS s3 cp "$TMPDIR/a.txt" "s3://$BATCH_BUCKET/a.txt" > /dev/null
$AWS s3 cp "$TMPDIR/b.txt" "s3://$BATCH_BUCKET/b.txt" > /dev/null
$AWS s3 cp "$TMPDIR/c.txt" "s3://$BATCH_BUCKET/c.txt" > /dev/null

DEL_OUT=$($AWS s3api delete-objects --bucket "$BATCH_BUCKET" \
    --delete 'Objects=[{Key=a.txt},{Key=b.txt},{Key=c.txt}]' 2>&1)
DEL_COUNT=$(echo "$DEL_OUT" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("Deleted",[])))' 2>/dev/null)
assert_eq "delete-objects removed 3" "3" "$DEL_COUNT"
assert_file_not_exists "a.txt gone" "$DATA_DIR/buckets/$BATCH_BUCKET/a.txt"
assert_file_not_exists "b.txt gone" "$DATA_DIR/buckets/$BATCH_BUCKET/b.txt"
assert_file_not_exists "c.txt gone" "$DATA_DIR/buckets/$BATCH_BUCKET/c.txt"
assert_file_not_exists "a.txt.meta.json gone" "$DATA_DIR/buckets/$BATCH_BUCKET/a.txt.meta.json"

# Batch delete with one missing key — still returns 200; S3 treats missing as deleted.
echo "x" > "$TMPDIR/x.txt"
$AWS s3 cp "$TMPDIR/x.txt" "s3://$BATCH_BUCKET/x.txt" > /dev/null
DEL_MIX=$($AWS s3api delete-objects --bucket "$BATCH_BUCKET" \
    --delete 'Objects=[{Key=x.txt},{Key=does-not-exist.txt}]' 2>&1)
DEL_MIX_COUNT=$(echo "$DEL_MIX" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d.get("Deleted",[])))' 2>/dev/null)
if [ "$DEL_MIX_COUNT" -ge 1 ]; then
    green "PASS: delete-objects handles mixed existing + missing keys"
    PASS=$((PASS + 1))
else
    red "FAIL: delete-objects mixed gave Deleted=$DEL_MIX_COUNT"
    FAIL=$((FAIL + 1))
fi

assert "delete batch bucket" $AWS s3api delete-bucket --bucket "$BATCH_BUCKET"

# --- Versioning ---
echo ""
echo "--- Versioning tests ---"
VER_BUCKET="ver-$$"
assert "create version bucket" $AWS s3api create-bucket --bucket "$VER_BUCKET"
assert "put-bucket-versioning Enabled" $AWS s3api put-bucket-versioning \
    --bucket "$VER_BUCKET" --versioning-configuration 'Status=Enabled'

VER_STATUS=$($AWS s3api get-bucket-versioning --bucket "$VER_BUCKET" 2>&1)
assert_eq "get-bucket-versioning returns Enabled" "Enabled" \
    "$(echo "$VER_STATUS" | grep -o '"Status": "[^"]*"' | cut -d'"' -f4)"

# Three PUTs of same key → three versions
echo "v1" > "$TMPDIR/v1.txt"
echo "v2" > "$TMPDIR/v2.txt"
echo "v3" > "$TMPDIR/v3.txt"
V1_VID=$($AWS s3api put-object --bucket "$VER_BUCKET" --key obj --body "$TMPDIR/v1.txt" 2>&1 | grep -o '"VersionId": "[^"]*"' | cut -d'"' -f4)
V2_VID=$($AWS s3api put-object --bucket "$VER_BUCKET" --key obj --body "$TMPDIR/v2.txt" 2>&1 | grep -o '"VersionId": "[^"]*"' | cut -d'"' -f4)
V3_VID=$($AWS s3api put-object --bucket "$VER_BUCKET" --key obj --body "$TMPDIR/v3.txt" 2>&1 | grep -o '"VersionId": "[^"]*"' | cut -d'"' -f4)
if [ -n "$V1_VID" ] && [ -n "$V2_VID" ] && [ -n "$V3_VID" ] \
    && [ "$V1_VID" != "$V2_VID" ] && [ "$V2_VID" != "$V3_VID" ]; then
    green "PASS: three distinct VersionIds returned"
    PASS=$((PASS + 1))
else
    red "FAIL: VersionIds v1=$V1_VID v2=$V2_VID v3=$V3_VID"
    FAIL=$((FAIL + 1))
fi

# list-object-versions shows all 3
VER_LIST=$($AWS s3api list-object-versions --bucket "$VER_BUCKET" 2>&1)
VER_LIST_COUNT=$(echo "$VER_LIST" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("Versions",[])))' 2>/dev/null)
assert_eq "list-object-versions returns 3 versions" "3" "$VER_LIST_COUNT"

# get-object --version-id returns historical content
$AWS s3api get-object --bucket "$VER_BUCKET" --key obj --version-id "$V1_VID" \
    "$TMPDIR/v1-out.txt" > /dev/null 2>&1
if [ "$(cat "$TMPDIR/v1-out.txt" 2>/dev/null)" = "v1" ]; then
    green "PASS: get-object --version-id retrieves old v1 content"
    PASS=$((PASS + 1))
else
    red "FAIL: get-object --version-id returned $(cat "$TMPDIR/v1-out.txt" 2>/dev/null)"
    FAIL=$((FAIL + 1))
fi

# delete-object (no version-id) creates a delete marker
DEL_MARKER=$($AWS s3api delete-object --bucket "$VER_BUCKET" --key obj 2>&1)
assert_eq "delete-object returns DeleteMarker=true" "true" \
    "$(echo "$DEL_MARKER" | grep -o '"DeleteMarker": [a-z]*' | awk '{print $2}')"

VER_LIST_AFTER=$($AWS s3api list-object-versions --bucket "$VER_BUCKET" 2>&1)
DM_COUNT=$(echo "$VER_LIST_AFTER" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("DeleteMarkers",[])))' 2>/dev/null)
assert_eq "list-object-versions shows 1 DeleteMarker" "1" "$DM_COUNT"

# delete-object --version-id hard-deletes a specific version
assert "delete-object --version-id hard-delete v1" $AWS s3api delete-object \
    --bucket "$VER_BUCKET" --key obj --version-id "$V1_VID"
VER_LIST_FINAL=$($AWS s3api list-object-versions --bucket "$VER_BUCKET" 2>&1)
VER_FINAL_COUNT=$(echo "$VER_LIST_FINAL" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("Versions",[])))' 2>/dev/null)
assert_eq "post hard-delete: 2 versions remain" "2" "$VER_FINAL_COUNT"

# Suspend versioning
assert "put-bucket-versioning Suspended" $AWS s3api put-bucket-versioning \
    --bucket "$VER_BUCKET" --versioning-configuration 'Status=Suspended'

# Cleanup all remaining versions
for vid in $(echo "$VER_LIST_FINAL" | python3 -c 'import sys,json; [print(v["VersionId"]) for v in json.load(sys.stdin).get("Versions",[])+json.load(open("/dev/stdin")).get("DeleteMarkers",[])]' 2>/dev/null || echo ""); do
    $AWS s3api delete-object --bucket "$VER_BUCKET" --key obj --version-id "$vid" > /dev/null 2>&1 || true
done
# Fallback — delete everything
$AWS s3 rm "s3://$VER_BUCKET" --recursive > /dev/null 2>&1 || true
# remove any lingering version files on disk (versioning tests leave .versions/ dirs)
rm -rf "$DATA_DIR/buckets/$VER_BUCKET"
$AWS s3api delete-bucket --bucket "$VER_BUCKET" > /dev/null 2>&1 || true

# --- ListObjectsV1 pagination ---
echo ""
echo "--- ListObjectsV1 pagination tests ---"
PAG_BUCKET="pag-$$"
assert "create pagination bucket" $AWS s3api create-bucket --bucket "$PAG_BUCKET"
for i in 0 1 2 3 4 5 6; do
    echo "obj$i" > "$TMPDIR/obj$i.txt"
    $AWS s3 cp "$TMPDIR/obj$i.txt" "s3://$PAG_BUCKET/obj$i" > /dev/null
done

PAGE1=$($AWS s3api list-objects --bucket "$PAG_BUCKET" --max-keys 3 2>&1)
PAGE1_COUNT=$(echo "$PAGE1" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("Contents",[])))' 2>/dev/null)
assert_eq "list-objects v1 page 1 returns 3" "3" "$PAGE1_COUNT"
PAGE1_TRUNC=$(echo "$PAGE1" | grep -o '"IsTruncated": [a-z]*' | awk '{print $2}')
assert_eq "list-objects v1 page 1 IsTruncated=true" "true" "$PAGE1_TRUNC"
NEXT_MARKER=$(echo "$PAGE1" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("NextMarker") or d["Contents"][-1]["Key"])' 2>/dev/null)

PAGE2=$($AWS s3api list-objects --bucket "$PAG_BUCKET" --max-keys 3 --marker "$NEXT_MARKER" 2>&1)
PAGE2_COUNT=$(echo "$PAGE2" | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("Contents",[])))' 2>/dev/null)
assert_eq "list-objects v1 page 2 returns 3" "3" "$PAGE2_COUNT"

$AWS s3 rm "s3://$PAG_BUCKET" --recursive > /dev/null
assert "delete pagination bucket" $AWS s3api delete-bucket --bucket "$PAG_BUCKET"

# --- GetBucketLocation ---
echo ""
echo "--- GetBucketLocation test ---"
LOC_BUCKET="loc-$$"
assert "create loc bucket" $AWS s3api create-bucket --bucket "$LOC_BUCKET"
LOC=$($AWS s3api get-bucket-location --bucket "$LOC_BUCKET" 2>&1)
# LocationConstraint is "us-east-1" or null-equivalent
LOC_VAL=$(echo "$LOC" | grep -o '"LocationConstraint": "[^"]*"' | cut -d'"' -f4)
if [ "$LOC_VAL" = "us-east-1" ] || [ -z "$LOC_VAL" ]; then
    green "PASS: get-bucket-location returned '$LOC_VAL'"
    PASS=$((PASS + 1))
else
    red "FAIL: get-bucket-location returned '$LOC_VAL'"
    FAIL=$((FAIL + 1))
fi
assert "delete loc bucket" $AWS s3api delete-bucket --bucket "$LOC_BUCKET"

# --- Cross-bucket CopyObject ---
echo ""
echo "--- Cross-bucket CopyObject test ---"
SRC_BUCKET="src-$$"
DST_BUCKET="dst-$$"
assert "create src bucket" $AWS s3api create-bucket --bucket "$SRC_BUCKET"
assert "create dst bucket" $AWS s3api create-bucket --bucket "$DST_BUCKET"
echo "cross-bucket content" > "$TMPDIR/xcopy.txt"
$AWS s3 cp "$TMPDIR/xcopy.txt" "s3://$SRC_BUCKET/src-key" > /dev/null
assert "cross-bucket copy-object" $AWS s3api copy-object \
    --bucket "$DST_BUCKET" --key dst-key \
    --copy-source "$SRC_BUCKET/src-key"
$AWS s3api get-object --bucket "$DST_BUCKET" --key dst-key "$TMPDIR/xcopy-out.txt" > /dev/null
if cmp -s "$TMPDIR/xcopy.txt" "$TMPDIR/xcopy-out.txt"; then
    green "PASS: cross-bucket copy preserves content"
    PASS=$((PASS + 1))
else
    red "FAIL: cross-bucket copy differs"
    FAIL=$((FAIL + 1))
fi
$AWS s3 rm "s3://$SRC_BUCKET/src-key" > /dev/null
$AWS s3 rm "s3://$DST_BUCKET/dst-key" > /dev/null
assert "delete src bucket" $AWS s3api delete-bucket --bucket "$SRC_BUCKET"
assert "delete dst bucket" $AWS s3api delete-bucket --bucket "$DST_BUCKET"

# --- CopyObject with SSE-C source ---
echo ""
echo "--- CopyObject with SSE-C source test ---"
SSEC_SRC="ssec-src-$$"
SSEC_DST="ssec-dst-$$"
assert "create ssec-src" $AWS s3api create-bucket --bucket "$SSEC_SRC"
assert "create ssec-dst" $AWS s3api create-bucket --bucket "$SSEC_DST"

SSEC_KEY=$(openssl rand 32 | base64)
SSEC_MD5=$(echo -n "$SSEC_KEY" | base64 -d | openssl dgst -md5 -binary | base64)
echo "ssec copy payload" > "$TMPDIR/ssec-src.txt"
$AWS s3api put-object --bucket "$SSEC_SRC" --key srcobj --body "$TMPDIR/ssec-src.txt" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$SSEC_KEY" \
    --sse-customer-key-md5 "$SSEC_MD5" > /dev/null

# Copy without providing source key → must fail
assert_fail "copy without copy-source SSE-C key fails" \
    $AWS s3api copy-object --bucket "$SSEC_DST" --key dstobj \
    --copy-source "$SSEC_SRC/srcobj"

# Copy WITH source key → destination becomes plaintext (no dst SSE specified)
assert "copy with copy-source SSE-C key succeeds" \
    $AWS s3api copy-object --bucket "$SSEC_DST" --key dstobj \
    --copy-source "$SSEC_SRC/srcobj" \
    --copy-source-sse-customer-algorithm AES256 \
    --copy-source-sse-customer-key "$SSEC_KEY" \
    --copy-source-sse-customer-key-md5 "$SSEC_MD5"

# Destination is plaintext → plain GET works
$AWS s3api get-object --bucket "$SSEC_DST" --key dstobj "$TMPDIR/ssec-dst.txt" > /dev/null 2>&1
if cmp -s "$TMPDIR/ssec-src.txt" "$TMPDIR/ssec-dst.txt"; then
    green "PASS: copy-source SSE-C roundtrip content match"
    PASS=$((PASS + 1))
else
    red "FAIL: copy-source SSE-C roundtrip content differs"
    FAIL=$((FAIL + 1))
fi

$AWS s3 rm "s3://$SSEC_DST/dstobj" > /dev/null 2>&1 || true
# Force-remove SSE-C source (regular s3 rm doesn't need the key, only GET does)
$AWS s3 rm "s3://$SSEC_SRC/srcobj" > /dev/null 2>&1 || true
assert "delete ssec-src bucket" $AWS s3api delete-bucket --bucket "$SSEC_SRC"
assert "delete ssec-dst bucket" $AWS s3api delete-bucket --bucket "$SSEC_DST"

# --- CopyObject SSE-C source → SSE-S3 destination (reencryption) ---
echo ""
echo "--- CopyObject reencryption (SSE-C → SSE-S3) test ---"
REENC_SRC="reenc-src-$$"
REENC_DST="reenc-dst-$$"
assert "create reenc-src" $AWS s3api create-bucket --bucket "$REENC_SRC"
assert "create reenc-dst" $AWS s3api create-bucket --bucket "$REENC_DST"

REENC_KEY=$(openssl rand 32 | base64)
REENC_MD5=$(echo -n "$REENC_KEY" | base64 -d | openssl dgst -md5 -binary | base64)
echo "reencryption payload" > "$TMPDIR/reenc-src.txt"
$AWS s3api put-object --bucket "$REENC_SRC" --key srcobj --body "$TMPDIR/reenc-src.txt" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$REENC_KEY" \
    --sse-customer-key-md5 "$REENC_MD5" > /dev/null

# Copy SSE-C source → SSE-S3 destination: server decrypts source with customer
# key, re-encrypts under SSE-S3 master key.
REENC_OUT=$($AWS s3api copy-object --bucket "$REENC_DST" --key dstobj \
    --copy-source "$REENC_SRC/srcobj" \
    --copy-source-sse-customer-algorithm AES256 \
    --copy-source-sse-customer-key "$REENC_KEY" \
    --copy-source-sse-customer-key-md5 "$REENC_MD5" \
    --server-side-encryption AES256 2>&1)
assert_eq "reencryption copy response shows SSE=AES256" \
    "AES256" "$(echo "$REENC_OUT" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("ServerSideEncryption",""))')"

# GET destination with no customer key (SSE-S3 is server-managed)
REENC_HEAD=$($AWS s3api head-object --bucket "$REENC_DST" --key dstobj 2>&1)
assert_eq "reencrypted dst HEAD shows SSE=AES256" \
    "AES256" "$(echo "$REENC_HEAD" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("ServerSideEncryption",""))')"

$AWS s3api get-object --bucket "$REENC_DST" --key dstobj "$TMPDIR/reenc-dst.txt" > /dev/null
if cmp -s "$TMPDIR/reenc-src.txt" "$TMPDIR/reenc-dst.txt"; then
    green "PASS: reencryption (SSE-C→SSE-S3) content matches"
    PASS=$((PASS + 1))
else
    red "FAIL: reencryption (SSE-C→SSE-S3) content differs"
    FAIL=$((FAIL + 1))
fi

$AWS s3 rm "s3://$REENC_DST/dstobj" > /dev/null 2>&1 || true
$AWS s3 rm "s3://$REENC_SRC/srcobj" > /dev/null 2>&1 || true
assert "delete reenc-src bucket" $AWS s3api delete-bucket --bucket "$REENC_SRC"
assert "delete reenc-dst bucket" $AWS s3api delete-bucket --bucket "$REENC_DST"

# --- SSE-C + Range read ---
echo ""
echo "--- SSE-C + Range read test ---"
SSEC_RANGE_BUCKET="ssec-range-$$"
assert "create ssec-range bucket" $AWS s3api create-bucket --bucket "$SSEC_RANGE_BUCKET"

RANGE_KEY=$(openssl rand 32 | base64)
RANGE_MD5=$(echo -n "$RANGE_KEY" | base64 -d | openssl dgst -md5 -binary | base64)

# 1 MiB random payload — exceeds the 65,536-byte frame size so the range read
# crosses at least one encryption-frame boundary.
dd if=/dev/urandom of="$TMPDIR/ssec-range.bin" bs=1024 count=1024 2>/dev/null
$AWS s3api put-object --bucket "$SSEC_RANGE_BUCKET" --key big.bin \
    --body "$TMPDIR/ssec-range.bin" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$RANGE_KEY" \
    --sse-customer-key-md5 "$RANGE_MD5" > /dev/null

# Range read with correct customer key → bytes must match local slice
$AWS s3api get-object --bucket "$SSEC_RANGE_BUCKET" --key big.bin \
    --range "bytes=70000-130000" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$RANGE_KEY" \
    --sse-customer-key-md5 "$RANGE_MD5" \
    "$TMPDIR/ssec-range-out.bin" > /dev/null
dd if="$TMPDIR/ssec-range.bin" of="$TMPDIR/ssec-range-expected.bin" \
    bs=1 skip=70000 count=60001 2>/dev/null
if cmp -s "$TMPDIR/ssec-range-out.bin" "$TMPDIR/ssec-range-expected.bin"; then
    green "PASS: SSE-C range read across frame boundary matches"
    PASS=$((PASS + 1))
else
    red "FAIL: SSE-C range read across frame boundary differs"
    FAIL=$((FAIL + 1))
fi

# Range read without customer key must fail
assert_fail "SSE-C range GET without customer key fails" \
    $AWS s3api get-object --bucket "$SSEC_RANGE_BUCKET" --key big.bin \
    --range "bytes=0-99" "$TMPDIR/ssec-range-nokey.bin"

$AWS s3 rm "s3://$SSEC_RANGE_BUCKET/big.bin" > /dev/null 2>&1 || true
assert "delete ssec-range bucket" $AWS s3api delete-bucket --bucket "$SSEC_RANGE_BUCKET"

# --- Presigned URLs ---
echo ""
echo "--- Presigned URL tests ---"
PRE_BUCKET="presign-$$"
assert "create presign bucket" $AWS s3api create-bucket --bucket "$PRE_BUCKET"
echo "presigned content" > "$TMPDIR/presign.txt"
$AWS s3 cp "$TMPDIR/presign.txt" "s3://$PRE_BUCKET/obj" > /dev/null

PRESIGN_URL=$($AWS s3 presign "s3://$PRE_BUCKET/obj" --expires-in 3600 2>&1)
if echo "$PRESIGN_URL" | grep -q "X-Amz-Signature"; then
    green "PASS: s3 presign returns signed URL"
    PASS=$((PASS + 1))
else
    red "FAIL: s3 presign output missing signature: $PRESIGN_URL"
    FAIL=$((FAIL + 1))
fi

# Curl the presigned URL without any AWS creds → should succeed
(unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; curl -s "$PRESIGN_URL" -o "$TMPDIR/presign-out.txt")
if cmp -s "$TMPDIR/presign.txt" "$TMPDIR/presign-out.txt"; then
    green "PASS: presigned URL GET works without credentials"
    PASS=$((PASS + 1))
else
    red "FAIL: presigned URL GET content mismatch"
    FAIL=$((FAIL + 1))
fi

# Expired presigned URL → 403
EXPIRED_URL=$($AWS s3 presign "s3://$PRE_BUCKET/obj" --expires-in 1 2>&1)
sleep 2
EXPIRED_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$EXPIRED_URL")
if [ "$EXPIRED_STATUS" = "403" ]; then
    green "PASS: expired presigned URL returns 403"
    PASS=$((PASS + 1))
else
    red "FAIL: expired presigned URL returned $EXPIRED_STATUS (expected 403)"
    FAIL=$((FAIL + 1))
fi

$AWS s3 rm "s3://$PRE_BUCKET/obj" > /dev/null
assert "delete presign bucket" $AWS s3api delete-bucket --bucket "$PRE_BUCKET"

# --- SSE-C edge cases ---
echo ""
echo "--- SSE-C edge case tests ---"
SSEC_EDGE_BUCKET="ssec-edge-$$"
assert "create ssec-edge bucket" $AWS s3api create-bucket --bucket "$SSEC_EDGE_BUCKET"
echo "edge" > "$TMPDIR/edge.txt"

# 31-byte key → must fail (32 required)
SHORT_KEY=$(openssl rand 31 | base64)
SHORT_MD5=$(echo -n "$SHORT_KEY" | base64 -d | openssl dgst -md5 -binary | base64)
assert_fail "PUT with 31-byte SSE-C key rejected" \
    $AWS s3api put-object --bucket "$SSEC_EDGE_BUCKET" --key short.txt \
    --body "$TMPDIR/edge.txt" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$SHORT_KEY" \
    --sse-customer-key-md5 "$SHORT_MD5"

# Correct key but wrong MD5 → must fail
GOOD_KEY=$(openssl rand 32 | base64)
assert_fail "PUT with wrong SSE-C MD5 rejected" \
    $AWS s3api put-object --bucket "$SSEC_EDGE_BUCKET" --key badmd5.txt \
    --body "$TMPDIR/edge.txt" \
    --sse-customer-algorithm AES256 \
    --sse-customer-key "$GOOD_KEY" \
    --sse-customer-key-md5 "AAAAAAAAAAAAAAAAAAAAAA=="

assert "delete ssec-edge bucket" $AWS s3api delete-bucket --bucket "$SSEC_EDGE_BUCKET"

# --- Object key edge cases ---
echo ""
echo "--- Object key edge case tests ---"
KEY_BUCKET="keys-$$"
assert "create keys bucket" $AWS s3api create-bucket --bucket "$KEY_BUCKET"
echo "edge" > "$TMPDIR/edge.txt"

# NOTE: MaxIO's filesystem backend stores the key as an on-disk path, so
# key length is ultimately bounded by the OS filesystem limits:
#   - Per-component: NAME_MAX (255 bytes on ext4/APFS) — minus `.meta.json`
#     suffix (10 bytes) for the sidecar, so ≤ 245 bytes per single-component key
#   - Total path:    PATH_MAX (1024 bytes on APFS) including `{data_dir}/buckets/{bucket}/`
#
# The S3 spec allows 1024-byte UTF-8 keys; MaxIO enforces that upper bound in
# `validate_key`, but actually storing a 1024-byte key requires a short
# data_dir and a short bucket name on systems with PATH_MAX = 1024. We test
# the MaxIO-enforced contract (1025 rejection) and a comfortably-safe key.

# 240-byte single-component key (room for `.meta.json` suffix under NAME_MAX)
MAX_KEY_SINGLE=$(python3 -c 'print("a"*240)')
assert "PUT with 240-byte single-component key" $AWS s3api put-object \
    --bucket "$KEY_BUCKET" --key "$MAX_KEY_SINGLE" --body "$TMPDIR/edge.txt"
assert "GET with 240-byte single-component key" $AWS s3api get-object \
    --bucket "$KEY_BUCKET" --key "$MAX_KEY_SINGLE" "$TMPDIR/maxkey-out.txt"

# 1025-byte key — rejected by MaxIO's validate_key (>1024) regardless of FS
OVER_KEY=$(python3 -c 'k="/".join(["a"*200]*5 + ["a"*25]); print(k[:1025])')
assert_fail "PUT with 1025-byte key rejected" \
    $AWS s3api put-object --bucket "$KEY_BUCKET" --key "$OVER_KEY" --body "$TMPDIR/edge.txt"

# Unicode + space key
UNICODE_KEY="日本語 file.txt"
assert "PUT unicode+space key" $AWS s3api put-object \
    --bucket "$KEY_BUCKET" --key "$UNICODE_KEY" --body "$TMPDIR/edge.txt"
$AWS s3api get-object --bucket "$KEY_BUCKET" --key "$UNICODE_KEY" "$TMPDIR/unicode-out.txt" > /dev/null
if cmp -s "$TMPDIR/edge.txt" "$TMPDIR/unicode-out.txt"; then
    green "PASS: unicode+space key roundtrip"
    PASS=$((PASS + 1))
else
    red "FAIL: unicode+space key roundtrip mismatch"
    FAIL=$((FAIL + 1))
fi

$AWS s3 rm "s3://$KEY_BUCKET" --recursive > /dev/null 2>&1 || true
assert "delete keys bucket" $AWS s3api delete-bucket --bucket "$KEY_BUCKET"

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
