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

`/healthz` returns `{"status":"ok","version":"..."}`. The log line `on-disk format version 2` means the data directory was accepted.

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

Roll back when the new process fails to start, or when you have not yet accepted its writes.

1. Stop the new process.
2. A 0.4.x binary ignores `.maxio-format`. It can open a directory that has not yet stored a key at `<key>/.maxio.object`. Once any key has been promoted, or the marker is version 2 and you are not willing to risk that, restore the backup taken before this upgrade.
3. A binary that understands only format 1 refuses a version 2 marker. That refusal is the safe path. Do not delete the marker to force the older binary to start.
4. Restore `.maxio-keys.json` and `iam.json` from the same backup as the objects. A keyring from a different copy will not decrypt objects or IAM access-key secrets.
5. Start the previous binary or image tag and check `/healthz`.

Deleting `.maxio-format` to force an older binary to start is not a rollback. If the marker is newer than the binary, the binary is telling you the data needs that newer release.
