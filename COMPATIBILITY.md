# MinIO / S3 Compatibility

This file tracks which S3 and MinIO features MaxIO supports. Update it when you add or change a feature.

Measured against Ceph's s3-tests: [docs/s3-compatibility.md](docs/s3-compatibility.md) (`just s3-compat`).

Status: ✅ supported · 🟡 partial · ❌ not supported

## Buckets

| Operation | Status | Notes |
|---|---|---|
| ListBuckets | ✅ | |
| CreateBucket | ✅ | |
| HeadBucket | ✅ | |
| DeleteBucket | ✅ | |
| GetBucketLocation | ✅ | |
| Get/PutBucketVersioning | ✅ | Reports `Suspended` |
| Get/Put/DeleteBucketCors | ✅ | |
| Get/Put/DeleteBucketEncryption | ✅ | SSE-S3 only as bucket default |
| Get/Put/DeleteBucketPolicy, GetBucketPolicyStatus | 🟡 | Only anonymous read (`s3:GetObject`) and list (`s3:ListBucket`) policies, as set by `mc anonymous set download`. Other policies get `NotImplemented` |
| Get/Put/DeleteBucketLifecycle | 🟡 | Expiration (`Days` / `Date`, `ExpiredObjectDeleteMarker`), `NoncurrentVersionExpiration` (`NoncurrentDays`, `NewerNoncurrentVersions`) and `AbortIncompleteMultipartUpload`; filters by prefix, tags and object size (`And`, legacy `<Prefix>`). `Transition` / `NoncurrentVersionTransition` return `NotImplemented`; unknown elements (including MinIO's `DelMarkerExpiration` / `AllVersionsExpiration` / `ExpiredObjectAllVersions`) return `MalformedXML`. GET/PUT always answer `x-amz-transition-default-minimum-object-size: all_storage_classes_128K` (the request header is ignored). Applied by the hourly background sweep, so actions run up to one hour after they become due. In versioning-suspended buckets expiration deletes the current object like `DeleteObject` does (no null delete marker) |
| Get/Put/DeleteBucketTagging | ✅ | |
| Bucket notifications | ❌ | |
| Bucket replication | ❌ | On roadmap |
| Object Lock / retention / legal hold | ❌ | GET object-lock returns `ObjectLockConfigurationNotFoundError`; object retention / legal hold return `InvalidRequest` |
| Bucket ACLs | 🟡 | GET returns owner `FULL_CONTROL`; PUT accepts `private` only |
| Website, replication, ownership controls, public access block | ❌ | GET returns the S3 "not found" error, DELETE is a no-op |
| Logging, notifications, request payment, accelerate | 🟡 | GET returns the empty default; PUT is not implemented |
| Unknown bucket / object subresources | ✅ | `501 NotImplemented`, never the default action |

## Listing

| Operation | Status | Notes |
|---|---|---|
| ListObjects (V1) | ✅ | `prefix`, `marker`, `max-keys`, `delimiter`, `encoding-type` |
| ListObjectsV2 | ✅ | `max-keys` counts keys and CommonPrefixes; `encoding-type`, `fetch-owner` |
| ListObjectVersions | ✅ | `prefix`, `delimiter`, `key-marker`, `version-id-marker`, `max-keys` |
| ListMultipartUploads | 🟡 | No prefix / marker pagination |

## Objects

| Operation | Status | Notes |
|---|---|---|
| PutObject | ✅ | Conditional writes (`If-None-Match: *`, `If-Match`), `x-amz-tagging`, `Content-MD5` |
| GetObject | ✅ | `versionId` (also with Range / `partNumber`), `response-*` overrides, `x-amz-delete-marker` |
| HeadObject | ✅ | |
| DeleteObject | ✅ | Includes `versionId` |
| DeleteObjects (batch) | ✅ | Per-key `VersionId`, `Quiet`, `Content-MD5` |
| CopyObject | ✅ | `x-amz-metadata-directive`, `x-amz-tagging-directive`, `?versionId=` source, `x-amz-copy-source-if-*` |
| Get/Put/DeleteObjectTagging | ✅ | |
| Range requests | ✅ | HTTP 206 |
| Conditional requests | ✅ | `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` |
| Checksums | ✅ | CRC32, CRC32C, SHA-1, SHA-256, CRC64NVME (header or trailer) |
| User metadata (`x-amz-meta-*`) | ✅ | Plus Cache-Control, Content-Disposition, Content-Encoding, Content-Language, Expires |
| Object ACLs | 🟡 | GET returns owner `FULL_CONTROL`; PUT accepts `private` only |
| GetObjectAttributes | ✅ | ETag, Checksum, ObjectSize, StorageClass |
| SelectObjectContent | ❌ | |
| RestoreObject | ❌ | |

## Multipart Upload

| Operation | Status | Notes |
|---|---|---|
| CreateMultipartUpload | ✅ | |
| UploadPart | ✅ | |
| UploadPartCopy | ✅ | |
| CompleteMultipartUpload | ✅ | Conditional writes |
| AbortMultipartUpload | ✅ | |
| ListParts | ✅ | |

## Authentication

| Feature | Status | Notes |
|---|---|---|
| AWS Signature V4 (header) | ✅ | |
| Presigned URLs (SigV4 query) | ✅ | |
| `UNSIGNED-PAYLOAD` | ✅ | |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | ✅ | Streamed, chunk signatures verified |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | ✅ | Trailer signature and checksum verified |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | ✅ | Trailer checksum verified (AWS CLI v2 / SDK default over HTTPS) |
| POST policy (browser form upload) | ❌ | |
| AWS Signature V2 | ❌ | |
| Multiple users / IAM policies | 🟡 | IAM users, scoped access keys, and AWS-style allow/deny policies. The root key remains `MAXIO_ACCESS_KEY`. No groups |
| STS | ❌ | |

## Encryption

| Feature | Status | Notes |
|---|---|---|
| SSE-S3 | ✅ | Local keyring or external master key. Startup refuses a missing or wrong key when encrypted objects exist |
| SSE-C | ✅ | |
| SSE-KMS | ❌ | Rejected with `InvalidEncryptionAlgorithm` |

## Addressing

| Feature | Status | Notes |
|---|---|---|
| Path-style (`/{bucket}/{key}`) | ✅ | Always available |
| Virtual-hosted-style (`{bucket}.host/key`) | ✅ | `--domain` / `MAXIO_DOMAIN` (alias `MINIO_DOMAIN`). See README |

## MinIO-Specific

| Feature | Status | Notes |
|---|---|---|
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` env vars | ✅ | Aliases for `MAXIO_ACCESS_KEY` / `MAXIO_SECRET_KEY` |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` env vars | ✅ | |
| `MINIO_REGION_NAME` / `MINIO_REGION` env vars | ✅ | |
| `MINIO_DEFAULT_BUCKETS` env var | ✅ | |
| `mc` client | ✅ | `mb`, `rb`, `cp`, `ls`, `cat`, `rm`, `stat`, `tag`, `anonymous set download`, `ls/rm --versions` |
| Health checks `/minio/health/live`, `/ready`, `/cluster`, `/cluster/read` | ✅ | Same status as `/maxio/health/live` and `/maxio/health/ready`. Cluster follows single-node readiness. `?maintenance=true` on `/cluster` is 412. Body is status only, no version |
| Erasure coding | 🟡 | Single node only, different on-disk format |
| MinIO on-disk data format | ❌ | Cannot read an existing MinIO data dir |
| MinIO Admin API (`mc admin`) | ❌ | |
| Distributed mode | ❌ | On roadmap |
| Prometheus metrics | ❌ | On roadmap |
