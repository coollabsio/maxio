# Production checklist

Use this before the first real deployment, and again when you move a data directory to a new host.

## Identity and network

- [ ] Set `MAXIO_ACCESS_KEY` and `MAXIO_SECRET_KEY` yourself. MaxIO refuses to start with the built-in `maxioadmin` / `maxioadmin` pair. Do not pass `--allow-insecure-dev` or `MAXIO_ALLOW_INSECURE_DEV` on a shared machine.
- [ ] Generate the secret on the host and store it in your secret manager. Do not commit it.

```bash
export MAXIO_ACCESS_KEY="operator"
export MAXIO_SECRET_KEY="$(openssl rand -hex 32)"
```

- [ ] Put TLS in front of MaxIO. The server speaks HTTP. A reverse proxy should terminate TLS and forward `X-Forwarded-Proto: https` so the console session cookie is marked `Secure`.

Caddy:

```
storage.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 0;
}
```

`client_max_body_size 0` lets large uploads through. Also raise the proxy read timeout for big multipart parts.

Console login limits count failed attempts: 10 per 5 minutes for one access key, and 50 per 5 minutes for one client IP across every access key. Behind this proxy, set `MAXIO_TRUSTED_PROXY` to the proxy's address (for example `127.0.0.1`) so MaxIO reads `X-Forwarded-For`. Without that setting every login is attributed to the proxy itself, so one client can lock the console for everyone until the window expires. Do not list a network that clients can connect from directly: a trusted proxy is allowed to choose the client address.

- [ ] Leave port 9000 bound to localhost when a proxy is on the same machine (`MAXIO_ADDRESS=127.0.0.1`). If clients reach MaxIO directly, allow that port only from the networks that should use it.
- [ ] Keep clocks in sync (for example chrony). Signature V4 requests outside the clock skew window are rejected.

## Data you must be able to restore

- [ ] The data directory, `<data-dir>/.maxio-keys.json`, and `<data-dir>/iam.json` (IAM users and sealed access-key secrets) are backed up together, and the backup is not only on the same disk.
- [ ] You have restored that pair onto a spare host once, or you have a written restore command you have actually run.
- [ ] `MAXIO_MASTER_KEY`, if you set it, is in the same backup plan as the data directory. An override key that is not backed up is the same as losing the keyring.
- [ ] The volume is large enough for the objects you will store. Erasure coding uses extra space for parity shards when you enable it.

A backup is a copy of the data directory while MaxIO is stopped, or a filesystem snapshot that is consistent. Copying the live directory during writes can capture a torn object.

## Repair flags

Stop MaxIO before `maxio check --repair`. The scan fixes only what the bytes already on disk can prove. These flags change that, and none of them is the default:

- `--accept-current-checksums` records the payload's checksum or single-part etag instead of quarantining a mismatch.
- `--accept-unverifiable-current` applies when a versioned object's current bytes and the archived copy of the same version differ and neither copy can be verified. It records a content hash of the current bytes and rebuilds the archive from them. The current bytes stay, including when those bytes are the corrupt copy.
- `--restore-unverifiable-from-archive` applies to that same unverifiable divergence, when the archive of the same version id is still there. It quarantines the current bytes and restores the current object from the archive. Pass this only when the archive is the copy you want to keep. If both this flag and `--accept-unverifiable-current` are set, the archive is restored and the current bytes are quarantined.

An empty, truncated, or non-text sidecar is rebuilt only when the object bytes are provably not MaxIO SSE ciphertext. Every server creates `.maxio-keys.json`, so the presence of that file is not the test. MaxIO SSE frames are `[12-byte nonce][ciphertext][16-byte tag]`. Full frames are 65564 bytes. The nonce ends with the frame index, which is 0, 1, 2, … A file that cannot be split that way is rebuilt as a plain object, including a plain multipart object, and a multipart `-N` etag is kept when the broken sidecar still contains it. A file that does match that layout is left in place: the data key lives only in the sidecar, so `check` cannot trial-decrypt the bytes with the master key. GET returns an error instead of ciphertext. A plaintext file that happens to use the same sizes and nonce indexes stays unavailable until its sidecar is restored. A 0-byte object is the same kind of ambiguity: SSE-S3 of an empty object writes no frame, so a missing sidecar is not rebuilt and the object is not served as plaintext. `.maxio-key-check.json` still tells `check` that an external master key was used; it does not by itself cause a plaintext sidecar to be written over ciphertext.

`check --repair` refuses to start, and does not change any file, when SSE-S3 data needs a master key that this command cannot verify. That is an external key (`.maxio-key-check.json` with no matching `.maxio-keys.json`), a missing on-disk keyring, or a key that does not match the check file. Pass `--master-key`, `--master-key-file`, `MAXIO_MASTER_KEY`, or `MAXIO_MASTER_KEY_FILE`, and the key must match `.maxio-key-check.json`. An on-disk keyring that already matches is enough. A read-only `check` without that key still runs. SSE-S3 objects it cannot decrypt, and every SSE-C object (the server never has the customer key), are an info line, `unverifiable without key`. They are not counted as issues, and `--repair` does not quarantine them. A checksum is quarantined only when it was computed and does not match.

`check` never writes `.maxio-keys.json` or `.maxio-key-check.json`. A supplied master key that is not the recorded key is ignored: a read-only check prints a warning and still exits 0, and `check --repair` refuses before it changes anything. A multipart checksum that ends in `-N` is a composite of the part checksums. It is recomputed from the stored part sizes, including when a broken sidecar is rebuilt, or left as an info line (`composite-checksum`) only when those sizes are absent. A part-size list that does not add up to the recorded size is damage for an SSE object, and for a plain object when the parts also do not add up to the file. A plain object whose parts match the file gets its sidecar size rewritten to the file length; the checksum and content hash stay. GET of a plain object uses the file length when the sidecar size is shorter, so a bad size does not drop the tail. It is not compared with a checksum of the whole object, and the value the client stored is not rewritten. `CRC64NVME` multipart checksums are of the full object and are checked that way. Every SSE-S3 sidecar is checked with the same MAC GET uses. A mismatch is restored from an intact archived copy of those bytes when one exists; otherwise the original sidecar is copied to `.maxio-quarantine/` and left in place. It is not replaced with a plaintext sidecar.

## Capacity

Start small and raise the limits when the workload needs it. These are starting points for a single small server, not a sizing formula.

- [ ] Memory limit of at least 512MiB. A host with room for the page cache (a few GiB) will serve reads faster.
- [ ] Open-file limit of at least 65535 for the MaxIO process (`LimitNOFILE` in systemd, or `ulimits` in Docker).
- [ ] A pid limit high enough for the worker threads (Docker `--pids-limit` of a few hundred is enough to start; raise it if the process is killed for pid exhaustion).
- [ ] Disk monitoring on the data volume. MaxIO does not enforce a quota.

Docker example:

```bash
docker run -d --name maxio \
  --memory=1g --pids-limit=512 \
  --ulimit nofile=65535:65535 \
  -p 127.0.0.1:9000:9000 \
  -v /var/lib/maxio:/data \
  -e MAXIO_ACCESS_KEY -e MAXIO_SECRET_KEY \
  ghcr.io/coollabsio/maxio:1.0.0
```

systemd:

```
MemoryMax=1G
LimitNOFILE=65535
```

## Health

- [ ] The process supervisor uses `GET /maxio/health/live` or `maxio healthcheck`. A 200 body looks like `{"status":"ok"}` and does not include the version. `Cache-Control` is `no-store`.
- [ ] `/maxio/health/ready` is the readiness probe (`503` when the data directory cannot be read).
- [ ] MinIO-compatible probes answer the same way: `/minio/health/live` (liveness), `/minio/health/ready` (readiness), `/minio/health/cluster` and `/minio/health/cluster/read` (single-node quorum, same result as readiness). `mc ready` calls `/minio/health/cluster`. Coolify's MinIO template runs `mc ready local`, which needs that path. `GET /minio/health/cluster?maintenance=true` is `412` while the node is up, because this build is one node and taking it down loses the service.
- [ ] These probes are unauthenticated `GET` and `HEAD`. They skip the in-flight and request-time limits. `/healthz` and `/readyz` are ordinary bucket names, not probes.
- [ ] The container image does not include `curl` or `mc`. Its healthcheck is `maxio healthcheck` against `/maxio/health/live`. A copied MinIO compose check (`mc ready local`, or `curl` of `/minio/health/live`) fails inside this image even though those URLs work from outside the container.
- [ ] The image tag or binary version is pinned. `latest` is for experiments.
- [ ] You know which version is installed (`maxio --version`) and which format the data directory is on (the startup log, or `.maxio-format`). Unauthenticated health URLs do not report that version. A signed-in console session can read `GET /maxio/api/version`.

## Still single node

Replication and distributed mode are not in this release. One data directory must have one writer. Do not mount the same directory on two MaxIO processes.
