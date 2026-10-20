# Upgrade and rollback

Stop MaxIO before you replace the binary or the image. Two files matter as much as the object data:

- the data directory (`MAXIO_DATA_DIR`, `/data` in the container)
- `<data-dir>/.maxio-keys.json`, the SSE-S3 keyring, unless you inject the master key with `MAXIO_MASTER_KEY`

Losing the keyring makes SSE-S3 objects unreadable. There is no escrow key.

## Before you upgrade

1. Note the running version: `maxio --version`, or `GET /api/version`.
2. Stop the process and confirm nothing else is writing the data directory.
3. Copy the whole data directory, including hidden files, to a place that is not the live path.

```bash
sudo systemctl stop maxio
tar -C /var/lib -czf "/backup/maxio-$(date +%Y%m%d).tar.gz" maxio
```

The container equivalent is a copy of the volume while the container is stopped. Keep that copy until the new version has read and written the data you care about.

## Upgrade a binary

1. Download the archive for your platform and check `SHA256SUMS` ([platforms](PLATFORMS.md)).
2. Replace the binary.
3. Start MaxIO with the same data directory, credentials, and master key as before.
4. Confirm the version and that the process stayed up:

```bash
maxio --version
curl -fsS http://127.0.0.1:9000/maxio/health/live
```

`/maxio/health/live` returns `{"status":"ok"}` and does not include the version. The log line `on-disk format version 2` means the data directory was accepted. `/maxio/health/ready` is `503` when the data directory cannot be read.

## Upgrade a container

Pin the version tag. `latest` moves.

```bash
docker pull ghcr.io/coollabsio/maxio:1.0.0
docker stop maxio
docker rm maxio
docker run -d --name maxio \
  -p 9000:9000 \
  -v /var/lib/maxio:/data \
  -e MAXIO_ACCESS_KEY \
  -e MAXIO_SECRET_KEY \
  ghcr.io/coollabsio/maxio:1.0.0
```

Keep the previous image on the host until you are sure you do not need to roll back (`docker image ls`).

## On-disk format

`<data-dir>/.maxio-format` records the layout version. This binary writes `{"version":2}`.

- A missing marker is format 0 (a data directory from a build that predates the marker, including the tree at `1ddf339`). Format 1 is the marker with the previous object layout. `serve`, `check --repair`, and `keyring merge` upgrade either one to version 2. Object bytes stay where they are. `iam.json` is not rewritten.
- Read-only `maxio check` accepts format 0, 1, and 2 and does not write the marker. It refuses a newer marker before it reports anything.
- Format 2 is the key-and-prefix layout. A key that is also a prefix (`photos/cat.jpg` and `photos/cat.jpg/thumb`) is stored at `photos/cat.jpg/.maxio.object`. A binary that only understands format 1 refuses that marker. It does not open the directory as a file.
- Format 3 or newer makes `serve`, `check`, `check --repair`, and `keyring merge` refuse to open the directory. The message names both versions. The data directory, including `iam.json`, is left unchanged. Install the newer release instead of deleting the marker.

Future releases append a migration step and bump the marker only after that step succeeds. A failed migration leaves the previous marker in place.

## Rollback

Do not roll back to a pre-1.0 build after this upgrade. No format-1 binary was released. Builds from before 1.0.0 ignore `.maxio-format`. They start on a version 2 directory and then return `InternalError` for a key stored at `<key>/.maxio.object`. Deleting the marker does not make those objects readable.

Future releases refuse a marker newer than they understand. That refusal is the safe path. Do not delete the marker to force an older binary to start.

To undo an upgrade that has not yet stored data you need:

1. Stop the new process.
2. Restore the whole data directory from the backup taken before the upgrade, including `.maxio-keys.json` and `iam.json`. A keyring from a different copy will not decrypt objects or IAM access-key secrets.
3. Start the previous 1.0.x binary or image tag (not a pre-1.0 build) and check `/maxio/health/live`.
