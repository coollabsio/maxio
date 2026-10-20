# Upgrade and rollback

Stop MaxIO before you replace the binary or the image. Two files matter as much as the object data:

- the data directory (`MAXIO_DATA_DIR`, `/data` in the container)
- `<data-dir>/.maxio-keys.json`, the SSE-S3 keyring, unless you inject the master key with `MAXIO_MASTER_KEY`

Losing the keyring makes SSE-S3 objects unreadable. There is no escrow key.

## Before you upgrade

1. Note the running version: `maxio --version`, or `GET /version`.
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
curl -fsS http://127.0.0.1:9000/healthz
```

`/healthz` returns `{"status":"ok","version":"..."}`. The log line `on-disk format version 1` means the data directory was accepted.

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

`<data-dir>/.maxio-format` records the layout version (`{"version":1}`).

- A missing marker is format 0. Current releases run a no-op migration and write version 1. Object bytes are not rewritten.
- The same version starts with no further migration.
- A **newer** marker than this binary understands makes MaxIO refuse to start. The message names both versions. The data directory is left unchanged. Install the newer release instead of deleting the marker.

Future releases append a migration step and bump the marker only after that step succeeds. A failed migration leaves the previous marker in place.

## Rollback

Roll back when the new process fails to start, or when you have not yet accepted its writes.

1. Stop the new process.
2. If the format version is still 1 and you have not stored new data you need, the previous 0.4.x binary ignores `.maxio-format` and can start on the same directory.
3. If a future release migrated the layout (the marker version increased and the changelog says the layout changed), restore the backup from before the upgrade. Do not point an older binary at a migrated directory.
4. Restore `.maxio-keys.json` from the same backup as the objects. A keyring from a different copy will not decrypt those objects.
5. Start the previous binary or image tag and check `/healthz`.

Deleting `.maxio-format` to force an older binary to start is not a rollback. If the marker is newer than the binary, the binary is telling you the data needs that newer release.
