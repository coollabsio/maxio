# MinIO / S3 Compatibility

This file tracks which S3 and MinIO features MaxIO supports. Update it when you add or change a feature.

Status: ✅ supported · 🟡 partial · ❌ not supported

## Buckets

| Operation | Status | Notes |
|---|---|---|
| ListBuckets | ✅ | |
| CreateBucket | ✅ | |
| HeadBucket | ✅ | |
| DeleteBucket | ✅ | |
| GetBucketLocation | ✅ | |
| Get/PutBucketVersioning | ✅ | |
| Get/Put/DeleteBucketCors | ✅ | |
| Get/Put/DeleteBucketEncryption | ✅ | SSE-S3 only as bucket default |
| Get/Put/DeleteBucketPolicy | ❌ | |
| Get/Put/DeleteBucketLifecycle | ❌ | On roadmap |
| Get/Put/DeleteBucketTagging | ❌ | |
| Bucket notifications | ❌ | |
| Bucket replication | ❌ | On roadmap |
| Object Lock / retention / legal hold | ❌ | |
| Bucket ACLs | ❌ | |

## Listing

| Operation | Status | Notes |
|---|---|---|
| ListObjects (V1) | ✅ | `prefix`, `marker`, `max-keys`, `delimiter` |
| ListObjectsV2 | ✅ | |
| ListObjectVersions | ✅ | |
| ListMultipartUploads | ✅ | |

## Objects

| Operation | Status | Notes |
|---|---|---|
| PutObject | ✅ | |
| GetObject | ✅ | Includes `versionId` |
| HeadObject | ✅ | |
| DeleteObject | ✅ | Includes `versionId` |
| DeleteObjects (batch) | ✅ | |
| CopyObject | ✅ | `x-amz-metadata-directive` |
| Get/Put/DeleteObjectTagging | ✅ | |
| Range requests | ✅ | HTTP 206 |
| Conditional requests | ✅ | `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` |
| Checksums | ✅ | CRC32, CRC32C, SHA-1, SHA-256 |
| User metadata (`x-amz-meta-*`) | ❌ | Not stored |
| Object ACLs | ❌ | |
| GetObjectAttributes | ❌ | |
| SelectObjectContent | ❌ | |
| RestoreObject | ❌ | |

## Multipart Upload

| Operation | Status | Notes |
|---|---|---|
| CreateMultipartUpload | ✅ | |
| UploadPart | ✅ | |
| UploadPartCopy | ✅ | |
| CompleteMultipartUpload | ✅ | |
| AbortMultipartUpload | ✅ | |
| ListParts | ✅ | |

## Authentication

| Feature | Status | Notes |
|---|---|---|
| AWS Signature V4 (header) | ✅ | |
| Presigned URLs (SigV4 query) | ✅ | |
| `UNSIGNED-PAYLOAD` | ✅ | |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | ✅ | |
| AWS Signature V2 | ❌ | |
| Multiple users / IAM policies | ❌ | Single root access key only |
| STS | ❌ | |

## Encryption

| Feature | Status | Notes |
|---|---|---|
| SSE-S3 | ✅ | Local keyring, rotatable master key |
| SSE-C | ✅ | |
| SSE-KMS | ❌ | Rejected with `InvalidEncryptionAlgorithm` |

## Addressing

| Feature | Status | Notes |
|---|---|---|
| Path-style (`/{bucket}/{key}`) | ✅ | |
| Virtual-hosted-style (`{bucket}.host`) | ❌ | |

## MinIO-Specific

| Feature | Status | Notes |
|---|---|---|
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` env vars | ✅ | Aliases for `MAXIO_ACCESS_KEY` / `MAXIO_SECRET_KEY` |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` env vars | ✅ | |
| `MINIO_REGION_NAME` / `MINIO_REGION` env vars | ✅ | |
| `MINIO_DEFAULT_BUCKETS` env var | ✅ | |
| `mc` client (basic commands) | ✅ | `mb`, `rb`, `cp`, `ls`, `cat`, `rm` |
| Erasure coding | 🟡 | Single node only, different on-disk format |
| MinIO on-disk data format | ❌ | Cannot read an existing MinIO data dir |
| MinIO Admin API (`mc admin`) | ❌ | |
| Distributed mode | ❌ | On roadmap |
| Prometheus metrics | ❌ | On roadmap |
