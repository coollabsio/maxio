//! Transparent zstd compression at rest.
//!
//! A compressed payload is the concatenation of independent chunks. Each chunk
//! holds `chunk_size` original bytes (the last may be shorter) and is stored as
//! one zstd frame, or as the original bytes when zstd did not shrink it. There
//! are no framing bytes: the sidecar `CompressionMeta` is the only index, and
//! readers never inspect the payload to decide how to decode it.
//!
//! Compression happens before SSE framing and erasure coding, so `stored_size`
//! is the plaintext length that the SSE frame decryptor sees.

use super::{ByteStream, StorageError};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub const COMPRESSION_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_COMPRESS_BYTES: u64 = 1024;

const ZSTD: &str = "zstd";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompressionMeta {
    /// Always "zstd".
    pub algorithm: String,
    pub level: i32,
    /// Uncompressed bytes of every chunk except the shorter tail.
    pub chunk_size: u32,
    /// Sum of stored chunk payloads. This is the byte length of the
    /// pre-encryption payload. SSE frame decryptors must use this as their
    /// plaintext length, not ObjectMeta.size.
    pub stored_size: u64,
    pub chunks: Vec<CompressionChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompressionChunk {
    /// Payload bytes for this chunk before SSE framing.
    pub size: u32,
    /// True when zstd did not shrink the chunk and the payload is raw bytes.
    pub raw: bool,
}

/// Content types that are already compressed. `image/*` and `video/*` are
/// matched by prefix, and `audio/*` is too except for the WAV types.
const PRECOMPRESSED_TYPES: &[&str] = &[
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/zstd",
    "application/x-zstd",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-xz",
    "application/x-bzip",
    "application/x-bzip2",
    "application/pdf",
    "font/woff2",
    "application/font-woff2",
];

const WAV_TYPES: &[&str] = &["audio/wav", "audio/x-wav", "audio/wave", "audio/vnd.wave"];

/// Key extensions that mark an already-compressed object when the client sent
/// no specific content type.
const PRECOMPRESSED_EXTENSIONS: &[&str] = &[
    "gz", "gzip", "zip", "zst", "zstd", "7z", "rar", "xz", "bz2", "bz", "pdf", "woff2", "png",
    "jpg", "jpeg", "gif", "webp", "avif", "mp4", "mov", "webm", "mkv", "mp3", "aac", "ogg", "flac",
    "opus", "m4a",
];

/// Whether a new object is worth compressing. `enabled` is the bucket override
/// or, without one, the server default.
pub fn should_compress(
    enabled: bool,
    key: &str,
    content_type: &str,
    content_encoding: Option<&str>,
) -> bool {
    if !enabled || content_encoding.is_some_and(|enc| !enc.trim().is_empty()) {
        return false;
    }
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if mime.is_empty() || mime == "application/octet-stream" {
        let name = key.rsplit('/').next().unwrap_or(key);
        let extension = name
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase());
        return !extension.is_some_and(|ext| PRECOMPRESSED_EXTENSIONS.contains(&ext.as_str()));
    }
    let precompressed = match mime.split_once('/') {
        Some(("image" | "video", _)) => true,
        Some(("audio", _)) => !WAV_TYPES.contains(&mime.as_str()),
        _ => PRECOMPRESSED_TYPES.contains(&mime.as_str()),
    };
    !precompressed
}

/// Turns a stream of original bytes into the stored payload, one chunk at a
/// time. Feed every read to `push`, call `finish` at end of stream, then
/// `into_meta` for the sidecar index.
pub struct ChunkCompressor {
    /// `None` stores the bytes as sent.
    level: Option<i32>,
    pending: Vec<u8>,
    chunks: Vec<CompressionChunk>,
}

impl ChunkCompressor {
    pub fn new(level: i32) -> Self {
        Self {
            level: Some(level),
            pending: Vec::new(),
            chunks: Vec::new(),
        }
    }

    /// Passes bytes through unchanged and never produces an index.
    pub fn off() -> Self {
        Self {
            level: None,
            pending: Vec::new(),
            chunks: Vec::new(),
        }
    }

    /// Stored bytes to write or encrypt now. Empty while a chunk is still
    /// filling.
    pub fn push<'a>(&mut self, original: &'a [u8]) -> Cow<'a, [u8]> {
        let Some(level) = self.level else {
            return Cow::Borrowed(original);
        };
        self.pending.extend_from_slice(original);
        let mut out = Vec::new();
        while self.pending.len() >= COMPRESSION_CHUNK_SIZE {
            encode_chunk(
                level,
                &self.pending[..COMPRESSION_CHUNK_SIZE],
                &mut out,
                &mut self.chunks,
            );
            self.pending.drain(..COMPRESSION_CHUNK_SIZE);
        }
        Cow::Owned(out)
    }

    /// Stored bytes for the tail chunk. An object under `MIN_COMPRESS_BYTES`
    /// comes back as sent.
    pub fn finish(&mut self) -> Vec<u8> {
        let pending = std::mem::take(&mut self.pending);
        let Some(level) = self.level else {
            return pending;
        };
        if pending.is_empty()
            || (self.chunks.is_empty() && (pending.len() as u64) < MIN_COMPRESS_BYTES)
        {
            return pending;
        }
        let mut out = Vec::new();
        encode_chunk(level, &pending, &mut out, &mut self.chunks);
        out
    }

    /// The sidecar index, present only when at least one chunk shrank. With
    /// every chunk raw the payload equals the original bytes.
    pub fn into_meta(self) -> Option<CompressionMeta> {
        let level = self.level?;
        if self.chunks.iter().all(|chunk| chunk.raw) {
            return None;
        }
        Some(CompressionMeta {
            algorithm: ZSTD.to_string(),
            level,
            chunk_size: COMPRESSION_CHUNK_SIZE as u32,
            stored_size: self.chunks.iter().map(|chunk| chunk.size as u64).sum(),
            chunks: self.chunks,
        })
    }
}

fn encode_chunk(level: i32, plain: &[u8], out: &mut Vec<u8>, chunks: &mut Vec<CompressionChunk>) {
    match zstd::bulk::compress(plain, level) {
        Ok(frame) if frame.len() < plain.len() => {
            out.extend_from_slice(&frame);
            chunks.push(CompressionChunk {
                size: frame.len() as u32,
                raw: false,
            });
        }
        _ => {
            out.extend_from_slice(plain);
            chunks.push(CompressionChunk {
                size: plain.len() as u32,
                raw: true,
            });
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ChunkSpan {
    stored: u32,
    raw: bool,
    plain: u64,
}

/// The stored bytes that hold an original byte range, and how to decode them.
#[derive(Debug)]
pub struct CompressedRange {
    /// Offset of the first touched chunk in the stored payload.
    pub stored_offset: u64,
    /// Stored bytes from `stored_offset` to the end of the last touched chunk.
    pub stored_length: u64,
    chunks: Vec<ChunkSpan>,
    skip: u64,
    length: u64,
}

impl CompressionMeta {
    /// Map original bytes `[offset, offset + length)` of an object whose
    /// original size is `original_size` to the chunks that hold them.
    pub fn range(
        &self,
        original_size: u64,
        offset: u64,
        length: u64,
    ) -> Result<CompressedRange, StorageError> {
        self.validate(original_size)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= original_size)
            .ok_or_else(|| {
                StorageError::IntegrityError(format!(
                    "range {offset}+{length} is outside the {original_size}-byte object"
                ))
            })?;
        if length == 0 {
            return Ok(CompressedRange {
                stored_offset: 0,
                stored_length: 0,
                chunks: Vec::new(),
                skip: 0,
                length: 0,
            });
        }
        let chunk_size = self.chunk_size as u64;
        let first = (offset / chunk_size) as usize;
        let last = ((end - 1) / chunk_size) as usize;
        let chunks: Vec<ChunkSpan> = (first..=last)
            .map(|index| ChunkSpan {
                stored: self.chunks[index].size,
                raw: self.chunks[index].raw,
                plain: self.plain_len(index, original_size),
            })
            .collect();
        Ok(CompressedRange {
            stored_offset: self.chunks[..first]
                .iter()
                .map(|chunk| chunk.size as u64)
                .sum(),
            stored_length: chunks.iter().map(|chunk| chunk.stored as u64).sum(),
            chunks,
            skip: offset - first as u64 * chunk_size,
            length,
        })
    }

    fn plain_len(&self, index: usize, original_size: u64) -> u64 {
        let chunk_size = self.chunk_size as u64;
        if index + 1 == self.chunks.len() {
            original_size - chunk_size * index as u64
        } else {
            chunk_size
        }
    }

    fn validate(&self, original_size: u64) -> Result<(), StorageError> {
        let invalid = |why: String| Err(StorageError::IntegrityError(why));
        if self.algorithm != ZSTD {
            return invalid(format!(
                "unsupported compression algorithm {:?}",
                self.algorithm
            ));
        }
        let chunk_size = self.chunk_size as u64;
        let count = self.chunks.len() as u64;
        if chunk_size == 0 || count == 0 {
            return invalid("compression index has no chunks".into());
        }
        let before_last = chunk_size * (count - 1);
        if original_size <= before_last || original_size - before_last > chunk_size {
            return invalid(format!(
                "compression index of {count} chunks does not cover {original_size} bytes"
            ));
        }
        let stored: u64 = self.chunks.iter().map(|chunk| chunk.size as u64).sum();
        if stored != self.stored_size {
            return invalid(format!(
                "compression chunks add up to {stored} bytes, index records {}",
                self.stored_size
            ));
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.size == 0
                || (chunk.raw && chunk.size as u64 != self.plain_len(index, original_size))
            {
                return invalid(format!("compression chunk {index} has an invalid size"));
            }
        }
        Ok(())
    }
}

impl CompressedRange {
    /// Original bytes of the range. `stored` must start at `stored_offset`.
    pub fn decompress(self, stored: ByteStream) -> ByteStream {
        Box::pin(Decompressor {
            inner: stored,
            chunks: self.chunks,
            next: 0,
            skip: self.skip as usize,
            remaining: self.length,
            input: Vec::new(),
            filled: 0,
            out: Vec::new(),
            pos: 0,
        })
    }
}

struct Decompressor {
    inner: ByteStream,
    chunks: Vec<ChunkSpan>,
    next: usize,
    /// Original bytes to drop from the front of the first chunk.
    skip: usize,
    remaining: u64,
    input: Vec<u8>,
    filled: usize,
    out: Vec<u8>,
    pos: usize,
}

impl Decompressor {
    fn decode(&mut self, span: ChunkSpan) -> io::Result<()> {
        let plain = if span.raw {
            std::mem::take(&mut self.input)
        } else {
            zstd::bulk::decompress(&self.input, span.plain as usize).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("compressed chunk does not decode: {err}"),
                )
            })?
        };
        if plain.len() as u64 != span.plain {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "compressed chunk decoded to {} bytes, index records {}",
                    plain.len(),
                    span.plain
                ),
            ));
        }
        self.input.clear();
        self.filled = 0;
        self.out = plain;
        self.pos = std::mem::take(&mut self.skip);
        self.next += 1;
        Ok(())
    }
}

impl AsyncRead for Decompressor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pos < this.out.len() && this.remaining > 0 {
                let n = (this.out.len() - this.pos)
                    .min(buf.remaining())
                    .min(usize::try_from(this.remaining).unwrap_or(usize::MAX));
                buf.put_slice(&this.out[this.pos..this.pos + n]);
                this.pos += n;
                this.remaining -= n as u64;
                return Poll::Ready(Ok(()));
            }
            if this.remaining == 0 || this.next == this.chunks.len() {
                return Poll::Ready(Ok(()));
            }
            let span = this.chunks[this.next];
            let size = span.stored as usize;
            if this.input.len() != size {
                this.input.resize(size, 0);
            }
            while this.filled < size {
                let mut read = ReadBuf::new(&mut this.input[this.filled..]);
                match this.inner.as_mut().poll_read(cx, &mut read) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {
                        let n = read.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "compressed payload ended inside a chunk",
                            )));
                        }
                        this.filled += n;
                    }
                }
            }
            if let Err(err) = this.decode(span) {
                return Poll::Ready(Err(err));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn compressible(len: usize) -> Vec<u8> {
        let line = b"2026-11-17T10:00:00Z level=info msg=\"request served\" status=200\n";
        line.iter().copied().cycle().take(len).collect()
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn store(level: i32, original: &[u8], read_size: usize) -> (Vec<u8>, Option<CompressionMeta>) {
        let mut compressor = ChunkCompressor::new(level);
        let mut stored = Vec::new();
        for piece in original.chunks(read_size) {
            stored.extend_from_slice(&compressor.push(piece));
        }
        stored.extend(compressor.finish());
        (stored, compressor.into_meta())
    }

    async fn read_range(
        meta: &CompressionMeta,
        stored: &[u8],
        size: u64,
        offset: u64,
        length: u64,
    ) -> Vec<u8> {
        let range = meta.range(size, offset, length).unwrap();
        let start = range.stored_offset as usize;
        let end = start + range.stored_length as usize;
        let reader = range.decompress(Box::pin(std::io::Cursor::new(stored[start..end].to_vec())));
        let mut out = Vec::new();
        Box::pin(reader).read_to_end(&mut out).await.unwrap();
        out
    }

    #[test]
    fn skips_precompressed_and_encoded_objects() {
        assert!(should_compress(true, "logs/app.log", "text/plain", None));
        assert!(should_compress(
            true,
            "a.json",
            "application/json; charset=utf-8",
            None
        ));
        assert!(should_compress(
            true,
            "data.bin",
            "application/octet-stream",
            None
        ));
        assert!(should_compress(true, "noext", "", None));
        assert!(should_compress(true, "sound.wav", "audio/wav", None));
        assert!(should_compress(
            true,
            "sound.wav",
            "application/octet-stream",
            None
        ));
        assert!(should_compress(true, "a.txt", "text/plain", Some("")));

        assert!(!should_compress(false, "logs/app.log", "text/plain", None));
        assert!(!should_compress(true, "a.txt", "text/plain", Some("gzip")));
        assert!(!should_compress(true, "x", "IMAGE/PNG", None));
        assert!(!should_compress(true, "x", "video/mp4", None));
        assert!(!should_compress(true, "x", "audio/mpeg", None));
        assert!(!should_compress(true, "x", "application/zip", None));
        assert!(!should_compress(
            true,
            "x",
            "application/pdf; foo=bar",
            None
        ));
        assert!(!should_compress(
            true,
            "dir/a.GZ",
            "application/octet-stream",
            None
        ));
        assert!(!should_compress(true, "photo.jpeg", "", None));
        assert!(
            should_compress(true, "dir.gz/readme", "application/octet-stream", None),
            "only the last path segment carries the extension"
        );
        assert!(
            should_compress(true, "notes.gz", "text/plain", None),
            "a specific content type wins over the extension"
        );
    }

    #[tokio::test]
    async fn round_trips_and_reads_ranges_across_chunks() {
        let original = compressible(3 * COMPRESSION_CHUNK_SIZE + 12_345);
        let (stored, meta) = store(3, &original, 256 * 1024);
        let meta = meta.expect("compressible bytes keep an index");
        assert_eq!(meta.algorithm, "zstd");
        assert_eq!(meta.chunks.len(), 4);
        assert_eq!(meta.stored_size, stored.len() as u64);
        assert!(stored.len() < original.len() / 4);

        let size = original.len() as u64;
        assert_eq!(read_range(&meta, &stored, size, 0, size).await, original);
        let chunk = COMPRESSION_CHUNK_SIZE as u64;
        for (offset, length) in [
            (chunk - 10, 20),
            (5, 1),
            (chunk, chunk),
            (2 * chunk + 7, size - 2 * chunk - 7),
            (size - 1, 1),
        ] {
            let got = read_range(&meta, &stored, size, offset, length).await;
            assert_eq!(
                got,
                original[offset as usize..(offset + length) as usize],
                "range {offset}+{length}"
            );
        }
    }

    #[tokio::test]
    async fn mixes_raw_and_compressed_chunks() {
        let mut original = noise(COMPRESSION_CHUNK_SIZE);
        original.extend(compressible(COMPRESSION_CHUNK_SIZE / 2));
        let (stored, meta) = store(3, &original, 100_000);
        let meta = meta.unwrap();
        assert_eq!(
            meta.chunks[0],
            CompressionChunk {
                size: COMPRESSION_CHUNK_SIZE as u32,
                raw: true
            }
        );
        assert!(!meta.chunks[1].raw);
        assert_eq!(
            &stored[..COMPRESSION_CHUNK_SIZE],
            &original[..COMPRESSION_CHUNK_SIZE]
        );
        let size = original.len() as u64;
        let offset = COMPRESSION_CHUNK_SIZE as u64 - 3;
        assert_eq!(
            read_range(&meta, &stored, size, offset, 10).await,
            original[offset as usize..offset as usize + 10]
        );
    }

    #[test]
    fn small_incompressible_and_disabled_input_is_stored_as_sent() {
        let small = compressible(MIN_COMPRESS_BYTES as usize - 1);
        assert_eq!(store(3, &small, 100), (small.clone(), None));

        let random = noise(2 * COMPRESSION_CHUNK_SIZE + 5);
        assert_eq!(store(3, &random, 256 * 1024), (random.clone(), None));

        let text = compressible(COMPRESSION_CHUNK_SIZE);
        let mut off = ChunkCompressor::off();
        assert!(matches!(off.push(&text), Cow::Borrowed(_)));
        assert!(off.finish().is_empty());
        assert_eq!(off.into_meta(), None);
    }

    #[test]
    fn rejects_an_index_that_does_not_add_up() {
        let original = compressible(COMPRESSION_CHUNK_SIZE + 10);
        let (_, meta) = store(3, &original, 4096);
        let meta = meta.unwrap();
        let size = original.len() as u64;
        assert!(meta.range(size, 0, size).is_ok());
        assert!(meta.range(size, 0, size + 1).is_err());
        assert!(
            meta.range(size + COMPRESSION_CHUNK_SIZE as u64, 0, 1)
                .is_err()
        );
        assert!(meta.range(COMPRESSION_CHUNK_SIZE as u64, 0, 1).is_err());

        let mut wrong_total = meta.clone();
        wrong_total.stored_size += 1;
        assert!(wrong_total.range(size, 0, 1).is_err());

        let mut unknown = meta.clone();
        unknown.algorithm = "brotli".into();
        assert!(unknown.range(size, 0, 1).is_err());
    }
}

#[cfg(test)]
mod filesystem_tests {
    use super::*;
    use crate::storage::check::check;
    use crate::storage::filesystem::FilesystemStorage;
    use crate::storage::keys::Keyring;
    use crate::storage::{
        BucketMeta, ChecksumAlgorithm, EncryptionMode, EncryptionRequest, PutOptions,
        StoredObjectMetadata, UploadEncryptionSpec,
    };
    use md5::{Digest, Md5};
    use std::io::Cursor;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    fn logs(len: usize) -> Vec<u8> {
        let line = b"{\"ts\":\"2026-11-17T10:00:00Z\",\"msg\":\"request served\",\"status\":200}\n";
        line.iter().copied().cycle().take(len).collect()
    }

    fn bucket(name: &str) -> BucketMeta {
        BucketMeta {
            name: name.to_string(),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            region: "us-east-1".into(),
            versioning: false,
            cors_rules: None,
            encryption_config: None,
            public_read: false,
            public_list: false,
            versioning_suspended: false,
            tags: None,
            lifecycle: None,
            compression: None,
        }
    }

    async fn storage(dir: &std::path::Path, on: bool) -> FilesystemStorage {
        let keyring = Arc::new(Keyring::load(dir.to_str().unwrap(), None).await.unwrap());
        let mut storage =
            FilesystemStorage::new(dir.to_str().unwrap(), false, 1024 * 1024, 0, keyring)
                .await
                .unwrap();
        storage.set_compression(on, 3);
        storage.create_bucket(&bucket("logs")).await.unwrap();
        storage
    }

    async fn put(storage: &FilesystemStorage, key: &str, content_type: &str, body: &[u8]) {
        storage
            .put_object(
                "logs",
                key,
                content_type,
                Box::pin(Cursor::new(body.to_vec())),
                None,
                None,
            )
            .await
            .unwrap();
    }

    async fn read(storage: &FilesystemStorage, key: &str) -> (Vec<u8>, crate::storage::ObjectMeta) {
        let (mut reader, meta) = storage.get_object("logs", key, None).await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        (buf, meta)
    }

    fn payload(dir: &std::path::Path, key: &str) -> u64 {
        std::fs::metadata(dir.join("buckets/logs").join(key))
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn round_trip_range_etag_and_disk_size() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path(), true).await;
        let body = logs(2 * COMPRESSION_CHUNK_SIZE + 50_000);
        let etag = format!("\"{}\"", hex::encode(Md5::digest(&body)));
        let crc = {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&body);
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                hasher.finalize().to_be_bytes(),
            )
        };
        let put = storage
            .put_object(
                "logs",
                "app.log",
                "application/json",
                Box::pin(Cursor::new(body.clone())),
                Some((ChecksumAlgorithm::CRC32, None)),
                None,
            )
            .await
            .unwrap();
        assert_eq!(put.etag, etag);
        assert_eq!(put.size, body.len() as u64);
        assert_eq!(put.checksum_value.as_deref(), Some(crc.as_str()));

        let (got, meta) = read(&storage, "app.log").await;
        assert_eq!(got, body);
        assert_eq!(meta.size, body.len() as u64);
        assert!(meta.compression.is_some());
        let on_disk = payload(dir.path(), "app.log");
        assert!(
            on_disk < body.len() as u64 / 4,
            "compressed file is {on_disk} bytes, original is {}",
            body.len()
        );

        let offset = COMPRESSION_CHUNK_SIZE as u64 - 20;
        let (mut reader, _) = storage
            .get_object_range("logs", "app.log", offset, 100, None)
            .await
            .unwrap();
        let mut range = Vec::new();
        reader.read_to_end(&mut range).await.unwrap();
        assert_eq!(range, body[offset as usize..offset as usize + 100]);

        let listed = storage.list_objects("logs", "app.log").await.unwrap();
        assert_eq!(listed[0].size, body.len() as u64);

        let report = check(dir.path(), false).await.unwrap();
        assert!(
            report.issues.iter().all(|issue| issue.kind
                != crate::storage::check::IssueKind::SizeMismatch
                && issue.kind != crate::storage::check::IssueKind::EtagMismatch),
            "{:?}",
            report.issues
        );
        let again = read(&storage, "app.log").await.0;
        assert_eq!(again, body);
    }

    #[tokio::test]
    async fn old_objects_survive_toggling_and_a_bucket_override() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = storage(dir.path(), false).await;
        let old = logs(64 * 1024);
        put(&storage, "old.log", "text/plain", &old).await;
        assert!(read(&storage, "old.log").await.1.compression.is_none());
        assert_eq!(payload(dir.path(), "old.log"), old.len() as u64);

        storage.set_compression(true, 3);
        assert_eq!(read(&storage, "old.log").await.0, old);
        let new = logs(64 * 1024);
        put(&storage, "new.log", "text/plain", &new).await;
        assert!(read(&storage, "new.log").await.1.compression.is_some());
        assert!(payload(dir.path(), "new.log") < new.len() as u64);

        storage.set_compression(false, 3);
        assert_eq!(read(&storage, "old.log").await.0, old);
        assert_eq!(read(&storage, "new.log").await.0, new);

        storage.set_bucket_compression("logs", true).await.unwrap();
        put(&storage, "bucket.log", "text/plain", &new).await;
        assert!(read(&storage, "bucket.log").await.1.compression.is_some());
        storage.set_bucket_compression("logs", false).await.unwrap();
        storage.set_compression(true, 3);
        put(&storage, "off.log", "text/plain", &new).await;
        assert!(read(&storage, "off.log").await.1.compression.is_none());
        assert_eq!(payload(dir.path(), "off.log"), new.len() as u64);
    }

    #[tokio::test]
    async fn skips_and_stores_incompressible_bytes_raw() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path(), true).await;
        let text = logs(8 * 1024);
        put(&storage, "pic.png", "image/png", &text).await;
        put(&storage, "archive.gz", "application/octet-stream", &text).await;
        let opts = PutOptions {
            metadata: StoredObjectMetadata {
                content_encoding: Some("gzip".into()),
                ..StoredObjectMetadata::default()
            },
            ..PutOptions::default()
        };
        storage
            .put_object_with(
                "logs",
                "encoded.txt",
                "text/plain",
                Box::pin(Cursor::new(text.clone())),
                None,
                None,
                &opts,
            )
            .await
            .unwrap();
        put(&storage, "tiny.txt", "text/plain", b"hello").await;
        let mut noise = vec![0u8; 8 * 1024];
        for (i, byte) in noise.iter_mut().enumerate() {
            *byte = (i.wrapping_mul(17)) as u8;
        }
        // High-entropy bytes. A short xorshift buffer is enough that zstd
        // does not shrink every chunk, and a fully raw object drops the index.
        let mut state = 0x1234_5678_9abc_def0u64;
        for byte in &mut noise {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        put(&storage, "random.bin", "application/octet-stream", &noise).await;

        for key in [
            "pic.png",
            "archive.gz",
            "encoded.txt",
            "tiny.txt",
            "random.bin",
        ] {
            let (got, meta) = read(&storage, key).await;
            assert!(meta.compression.is_none(), "{key} should be stored raw");
            let expected: &[u8] = match key {
                "tiny.txt" => b"hello",
                "random.bin" => &noise,
                _ => &text,
            };
            assert_eq!(got, expected, "{key}");
            assert_eq!(payload(dir.path(), key), expected.len() as u64, "{key}");
        }
    }

    #[tokio::test]
    async fn sse_and_multipart_round_trip_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage(dir.path(), true).await;
        let body = logs(COMPRESSION_CHUNK_SIZE + 10_000);
        storage
            .put_object(
                "logs",
                "secret.log",
                "text/plain",
                Box::pin(Cursor::new(body.clone())),
                None,
                Some(EncryptionRequest::sse_s3()),
            )
            .await
            .unwrap();
        let (got, meta) = read(&storage, "secret.log").await;
        assert_eq!(got, body);
        assert!(meta.compression.is_some());
        assert_eq!(
            meta.encryption.as_ref().map(|enc| enc.mode.clone()),
            Some(EncryptionMode::SseS3)
        );
        assert!(payload(dir.path(), "secret.log") < body.len() as u64);
        let offset = COMPRESSION_CHUNK_SIZE as u64 - 5;
        let (mut reader, _) = storage
            .get_object_range("logs", "secret.log", offset, 20, None)
            .await
            .unwrap();
        let mut range = Vec::new();
        reader.read_to_end(&mut range).await.unwrap();
        assert_eq!(range, body[offset as usize..offset as usize + 20]);

        let part_a = logs(5 * 1024 * 1024);
        let part_b = logs(64 * 1024);
        let upload = storage
            .create_multipart_upload(
                "logs",
                "multi.log",
                "text/plain",
                None,
                None,
                Some(UploadEncryptionSpec {
                    mode: EncryptionMode::SseS3,
                    customer_key_md5: None,
                    upload_dek_wrapped: None,
                    upload_dek_wrap_nonce: None,
                    upload_dek_key_id: None,
                    upload_nonce_prefix: String::new(),
                }),
                StoredObjectMetadata::default(),
                None,
            )
            .await
            .unwrap();
        let first = storage
            .upload_part(
                "logs",
                &upload.upload_id,
                1,
                Box::pin(Cursor::new(part_a.clone())),
                None,
                None,
            )
            .await
            .unwrap();
        let second = storage
            .upload_part(
                "logs",
                &upload.upload_id,
                2,
                Box::pin(Cursor::new(part_b.clone())),
                None,
                None,
            )
            .await
            .unwrap();
        let done = storage
            .complete_multipart_upload(
                "logs",
                &upload.upload_id,
                &[(1, first.etag), (2, second.etag)],
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(done.etag.contains('-'), "{}", done.etag);
        let mut whole = part_a.clone();
        whole.extend_from_slice(&part_b);
        let (got, meta) = read(&storage, "multi.log").await;
        assert_eq!(got, whole);
        assert_eq!(meta.size, whole.len() as u64);
        assert!(meta.compression.is_some());
        assert!(meta.encryption.is_some());
        let boundary = part_a.len() as u64 - 10;
        let (mut reader, _) = storage
            .get_object_range("logs", "multi.log", boundary, 30, None)
            .await
            .unwrap();
        let mut across = Vec::new();
        reader.read_to_end(&mut across).await.unwrap();
        assert_eq!(across, whole[boundary as usize..boundary as usize + 30]);

        storage.set_versioning("logs", true).await.unwrap();
        put(&storage, "versioned.log", "text/plain", &body).await;
        let version = read(&storage, "versioned.log").await.1.version_id.unwrap();
        let (mut reader, meta) = storage
            .get_object_version("logs", "versioned.log", &version, None)
            .await
            .unwrap();
        let mut versioned = Vec::new();
        reader.read_to_end(&mut versioned).await.unwrap();
        assert_eq!(versioned, body);
        assert!(meta.compression.is_some());
    }
}
