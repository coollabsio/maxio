# S3 compatibility suite

MaxIO is measured with [Ceph s3-tests](https://github.com/ceph/s3-tests) (`s3tests_boto3` functional tests, boto3). MinIO [Mint](https://github.com/minio/mint) was not used: it is a Docker harness that starts MinIO itself, and it does not run reliably without that image.

Run it locally:

```bash
just s3-compat
# or: bash tests/s3_compat.sh
```

The script builds MaxIO if needed, starts it on `127.0.0.1:9876` with the documented development credentials (`--allow-insecure-dev`), and runs `test_s3.py` and `test_headers.py` at s3-tests commit `5b3987116eca0b4b8fa57d6b10f3db57bab196b6`. CI runs the same script weekly and on `workflow_dispatch` (`.github/workflows/s3-compat.yml`). A failure that is not listed in `tests/s3_compat_expected_failures.txt` fails the job.

## Result

Scored tests are the ones that exercise behavior MaxIO claims to support. Tests for features MaxIO does not implement are deselected (below) and are not counted as failures.

| | Scored tests | Passed | Failed | Pass rate |
|---|---:|---:|---:|---:|
| Baseline (before these fixes) | 391 | 316 | 75 | 81% |
| After the fixes | 391 | 354 | 37 | 91% |

The full marker-filtered run, before name-based skips, was 316/613 (52%) at baseline and 354/613 (58%) after the fixes. Another 273 tests are removed by the marker expression (IAM, object lock, storage classes, and the rest of the list below). The scored numbers above also drop tests that have no marker but still require an unsupported feature (POST uploads, canned ACLs, SSE-KMS, and so on).

## Skip list

### Marker expression

`tests/s3_compat.sh` passes `-m 'not (...)'` for:

| Marker | Why it is skipped |
|---|---|
| `iam_*`, `user_policy`, `session_policy`, `group_policy`, `role_policy`, `webidentity_test`, `test_of_sts`, `abac_test`, `group` | No IAM or STS. One root access key only |
| `object_lock` | Object Lock, retention, and legal hold are not implemented |
| `storage_class`, `lifecycle_transition`, `cloud_transition`, `cloud_restore` | One storage class. Transitions are rejected |
| `s3website`, `s3website_routing_rules`, `s3website_redirect_location` | No website hosting |
| `fails_with_subdomain` | No virtual-hosted bucket URLs |
| `auth_aws2` | No Signature V2 |
| `s3select`, `sns`, `s3control` | Select, SNS, and S3 Control are not implemented |
| `bucket_logging`, `bucket_logging_cleanup` | No bucket logging |
| `object_ownership` | No ownership controls |
| `appendobject` | Ceph append extension |
| `fails_on_aws` | These tests fail against AWS itself (RGW-specific or stricter than S3) |

### Name list

`tests/s3_compat_skip_names.txt` deselects individual tests that are not marked but still depend on something MaxIO does not implement:

| Area | Why |
|---|---|
| Browser POST uploads (`test_post_object_*`) | POST policy is not implemented |
| Canned ACLs, grants, and anonymous ACL access | GET returns owner `FULL_CONTROL`; PUT accepts `private` only. Anonymous read/list is the bucket policy, not an ACL |
| SSE-KMS | Rejected with `InvalidEncryptionAlgorithmError` |
| Bucket policies other than anonymous read/list | Any other policy is `NotImplemented` |
| Public access block | Not implemented |
| Object Lock tests without the `object_lock` marker | Same as the marker: retention and legal hold are not implemented |
| `test_100_continue` | The second half requires a `public-read-write` ACL |
| `test_bucket_get_location` | The suite sends Ceph's zonegroup name (`default`) as `LocationConstraint`. MaxIO is an AWS region (`us-east-1`) and returns an empty constraint, which is what AWS does for us-east-1 |
| `test_get_object_torrent` | Torrent subresource is not implemented |
| Tests that need a second account (`*_not_owned*`, `*_nonowner*`, `test_access_bucket_private*`) | Alt and tenant credentials in the suite are the same root key, so cross-account checks do not apply |
| CORS cases that call `_setup_bucket_acl(public-read)` | CORS itself is implemented; these cases never get past the ACL call |
| Owner display name compared to the s3-tests config (`MaxIO Tester`) | MaxIO reports owner id `maxio` for every object. The suite's display name is not an account MaxIO knows about |

## Fixes in this pass

These were wrong for clients that already work against AWS, and each has a regression test in `tests/integration.rs` (and, where the AWS CLI can see it, `tests/aws_cli_test.sh`):

- A key that is also a prefix of another key (`foo/bar` and `foo/bar/baz`) can both be stored. The prefix object's bytes live at `{key}/.maxio.object` so the directory can hold children. The layout is one-way: an older MaxIO build returns `InternalError` on GET of a promoted key, because it opens that path as a file.
- In `us-east-1`, creating a bucket you already own returns 200. Other regions still return `BucketAlreadyOwnedByYou`.
- `CopyObject` onto the same key without a metadata, tagging, or encryption change returns `InvalidRequest`.
- `CompleteMultipartUpload` with an empty body returns `MalformedXML`. Repeating a successful complete returns the same result, so a client retry does not see `NoSuchUpload`.
- `partNumber=1` on a non-multipart object returns the object. A part number past the end of a non-multipart object returns `416 InvalidPartNumber` (AWS). A part past the end of a completed multipart object stays `400 InvalidPart`, which is what s3-tests checks.
- The `x-amz-request-id` header matches `<RequestId>` in the error XML.
- A missing key's 404 carries `x-amz-delete-marker: false`.
- SSE-C requires the key MD5. HEAD/GET of an SSE-C object without the customer key returns 400. Sending both SSE-C and SSE-S3, or a customer key without the algorithm, returns 400. `x-amz-server-side-encryption` on GET/HEAD returns 400.
- `If-None-Match` on PUT accepts a specific ETag as well as `*`. `If-Match: *` matches any current object.
- Too many tags, or a tag that is too long, returns `InvalidTag`.
- `GetBucketLifecycleConfiguration` echoes the form the client stored: a legacy top-level `<Prefix>` stays a `<Prefix>` (what s3-tests and older boto send), and `<Filter><Prefix>` stays a Filter (AWS CLI, Terraform, `mc ilm`). PUT and HEAD include `x-amz-expiration` when a rule matches.
- A malformed lifecycle transition date is 400. A well-formed transition is still `NotImplemented`.
- `ListBuckets` honors `max-buckets`, `continuation-token`, and `prefix`.
- `GetBucketLocation` for `us-east-1` is an empty `<LocationConstraint>`.
- `ListObjectVersions` includes `<Owner>`.
- HTTP header values are read as ISO-8859-1 for signing and user metadata, so a non-ASCII metadata byte is not dropped before the signature check.

## Known gaps

These 37 tests still fail and are listed in `tests/s3_compat_expected_failures.txt`. They are the ones most likely to matter to a client next:

- **Multipart checksums and `GetObjectAttributes`.** Complete and attributes responses do not yet surface `ChecksumAlgorithm` / `ChecksumSHA256` or `PartsCount` the way the suite expects. Trailer checksums on ordinary PUT already work (see `tests/aws_cli_test.sh`).
- **`UploadPartCopy` between SSE-S3 and SSE-C** on an 8 MiB object. The copy response is missing `x-amz-server-side-encryption`.
- **`partNumber` on an SSE-C multipart object**, and one SSE-C multipart chunk-size rejection (`test_encryption_sse_c_multipart_invalid_chunks_2`, `test_multipart_sse_c_get_part`).
- **Lifecycle expiry header arithmetic** for the suite's "days equals the header delta" check is sensitive to how the date is rounded. The header is present; three of the suite's checks now pass, and `test_delete_marker_expiration` still depends on the hourly lifecycle sweep rather than the suite's one-second debug interval.
- **Suspended-versioning delete markers** (`test_delete_marker_suspended`).
- **`ListObjects` V1 with a newline prefix.** boto3 turns that into `encoding-type=url` but does not decode `Prefix` on the V1 response, so it expects a raw newline. The body follows S3 and returns `%0A`. ListObjects V2, which boto does decode, passes.
- **Non-ASCII user metadata** (`test_object_set_get_unicode_metadata`). The signature still does not match boto's canonical request for a latin-1 `é` in `x-amz-meta-*`. ASCII metadata works.
- **A few header-auth edge cases** in `test_headers.py` (empty `Authorization`, both `Date` and `x-amz-date`, missing `Content-Length` on a signed PUT). These return `AccessDenied` or succeed where the suite wants a 400.
- **Copy of a suspended-versioning object** (`test_versioning_obj_suspended_copy`) and **resending the first multipart part so it finishes last** (`test_multipart_resend_first_finishes_last`).
- **Unreadable object keys** (`test_object_read_unreadable`) return 404 rather than 400.
