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

New writes of those names return `400 InvalidArgument` (PUT, copy, multipart create, upload part, and complete). GET and HEAD return `NoSuchKey`. Listings skip them.

An older build accepted these names as ordinary keys. A data directory from that build can still contain them, for example:

- `.maxio-promote-photos/img.jpg`
- `y/.maxio-promote-bar/file.txt`
- `a/.maxio.object` with sidecar `a/.maxio.object.meta.json` (this is not the inline payload of key `a`)
- `.maxio-quarantine/f`

Startup does not delete those objects. A `.maxio-promote-*` directory is treated as a crash leftover only when it contains a valid target marker and nothing except that marker, the ready marker, and `.maxio.object`. Anything else is left untouched.

`maxio check` reports each legacy key as `legacy-reserved-key`. `--repair` does not delete the bytes or the sidecar. The sidecar holds the wrapped SSE-S3 data key, so deleting it would make the object unrecoverable.

`DELETE` and `DeleteObjects` remove an existing legacy object. After they are gone, the bucket can be deleted. Copy the files out of the data directory first if you still need the bytes. GET will not return them.

## Key and prefix layout

A key that is also a prefix (`photos/cat.jpg` and `photos/cat.jpg/thumb`) keeps its bytes at `photos/cat.jpg/.maxio.object`. Older MaxIO builds return `InternalError` on GET of that key. Do not point an older binary at a data directory that already contains promoted keys.
