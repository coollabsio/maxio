# Upgrading MaxIO

## Reserved object-key names

This version reserves path segments that MaxIO uses on disk:

- `.maxio.object`
- `.maxio-promote-*` (including `.maxio-promote-target` and `.maxio-promote-ready`)
- `.maxio-tmp-*`
- `.maxio-bak-*`
- `.maxio-quarantine`
- `.meta.json` and `.ec` suffixes, `.folder`, `.uploads`, `.versions`, `.bucket.json`

The match is ASCII case-insensitive (`p/.MAXIO.OBJECT` is the same as `p/.maxio.object`).

New writes of those names return `400 InvalidArgument` (PUT, copy, delete, multipart create, upload part, and complete). GET and HEAD return `NoSuchKey`.

A data directory written by a pre-1.0 build can still contain real objects whose keys use those names, for example:

- `.maxio-promote-photos/img.jpg`
- `y/.maxio-promote-bar/file.txt`
- `a/.maxio.object` (sidecar `a/.maxio.object.meta.json`)
- `.maxio-quarantine/f`

MaxIO will not start if any such object is present. Startup prints the bucket and key (up to 32 names) and stops without changing the data directory. `maxio check` reports each one as `legacy-reserved-key` and does not modify it, including with `--repair`.

Start the previous MaxIO version on this data directory and rename or delete the keys, then start this version:

```bash
aws s3 mv s3://bucket/a/.maxio.object s3://bucket/a-object --endpoint-url http://127.0.0.1:9000
```

A `.maxio-promote-*` directory with no `*.meta.json` sidecar is this version's own crash leftover, not one of those objects. Startup removes an empty directory, removes a duplicate payload when the original object is still there, and restores a payload when the original is missing.

## Key and prefix layout

A key that is also a prefix (`photos/cat.jpg` and `photos/cat.jpg/thumb`) keeps its bytes at `photos/cat.jpg/.maxio.object`.

1.0.0 records that layout in `<data-dir>/.maxio-format` as version 2. Opening a directory with no marker, or with format 1, upgrades the marker to 2 and does not rewrite object bytes or `iam.json`.

Do not roll back to a pre-1.0 build after upgrading. Those builds ignore the marker, start on a version 2 directory, and return `InternalError` for a promoted key. A future build that only understands an older format refuses a newer marker instead. Do not delete the marker to force an older binary to start. See [docs/UPGRADE.md](docs/UPGRADE.md).
