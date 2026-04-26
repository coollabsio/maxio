//! AES-256-GCM chunked frame encryption / decryption for object data.
//!
//! ## Frame format (on disk)
//!
//! ```text
//! [nonce: 12 B][ciphertext: N B][tag: 16 B]   →  total = N + 28 B
//! ```
//!
//! * `nonce` = 4-byte per-object prefix || 8-byte chunk-index (little-endian).
//! * `N` = `FRAME_CHUNK_SIZE` (65536) for every frame except the last, which
//!   may be shorter.
//! * Frame overhead is ≈ 0.043 % for large objects.
//!
//! ## AsyncRead adapters
//!
//! * [`FrameEncryptor`] — wraps a plaintext `AsyncRead`, produces ciphertext.
//! * [`FrameDecryptor`] — wraps a ciphertext `AsyncRead`, produces plaintext.
//!   For range reads, seek the underlying file to the correct ciphertext offset
//!   **before** wrapping (use [`FrameDecryptor::ciphertext_offset`]) and
//!   construct via [`FrameDecryptor::for_range`].

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

/// Closure that produces the AAD for a given frame chunk index. Returning an
/// empty slice encrypts without AAD (legacy-compatible with v0 frames — kept
/// for unit tests; production always supplies a non-empty AAD).
pub type AadBuilder = Arc<dyn Fn(u64) -> Vec<u8> + Send + Sync>;

/// An AAD builder that yields no AAD (empty slice). Intended for tests only.
#[allow(dead_code)]
pub fn no_aad() -> AadBuilder {
    Arc::new(|_| Vec::new())
}

/// Plaintext bytes per encryption frame.
pub const FRAME_CHUNK_SIZE: usize = 65536;
/// Bytes of overhead added per frame (nonce + GCM tag).
const FRAME_OVERHEAD: usize = 12 + 16;

// ─────────────────────────────────────────────────────────────────────────────
// FrameEncryptor
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a plaintext `AsyncRead` and produces an encrypted frame stream.
///
/// The caller is responsible for tracking the plaintext size separately
/// (needed to construct the decryptor later).
#[allow(dead_code)]
pub struct FrameEncryptor {
    inner: Pin<Box<dyn AsyncRead + Send>>,
    cipher: Aes256Gcm,
    nonce_prefix: [u8; 4],
    chunk_index: u64,
    aad_builder: AadBuilder,
    /// Plaintext accumulation buffer (capacity = FRAME_CHUNK_SIZE)
    pt_buf: Box<[u8; FRAME_CHUNK_SIZE]>,
    pt_len: usize,
    /// Encrypted frame ready for output
    ct_buf: Vec<u8>,
    ct_pos: usize,
    done: bool,
}

#[allow(dead_code)]
impl FrameEncryptor {
    pub fn new(
        inner: Pin<Box<dyn AsyncRead + Send>>,
        key: &[u8; 32],
        nonce_prefix: [u8; 4],
        aad_builder: AadBuilder,
    ) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        Self {
            inner,
            cipher,
            nonce_prefix,
            chunk_index: 0,
            aad_builder,
            pt_buf: Box::new([0u8; FRAME_CHUNK_SIZE]),
            pt_len: 0,
            ct_buf: Vec::with_capacity(FRAME_CHUNK_SIZE + FRAME_OVERHEAD),
            ct_pos: 0,
            done: false,
        }
    }

    fn encrypt_current_chunk(&mut self) -> io::Result<()> {
        let nonce_bytes = make_nonce(&self.nonce_prefix, self.chunk_index);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = (self.aad_builder)(self.chunk_index);

        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &self.pt_buf[..self.pt_len],
                    aad: &aad,
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "AES-GCM encryption failed"))?;

        self.ct_buf.clear();
        self.ct_buf.extend_from_slice(&nonce_bytes);
        self.ct_buf.extend_from_slice(&ct); // ciphertext || tag
        self.ct_pos = 0;

        self.chunk_index += 1;
        self.pt_len = 0;
        Ok(())
    }
}

impl AsyncRead for FrameEncryptor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Serve from encrypted output buffer.
            if this.ct_pos < this.ct_buf.len() {
                let avail = this.ct_buf.len() - this.ct_pos;
                let n = avail.min(buf.remaining());
                buf.put_slice(&this.ct_buf[this.ct_pos..this.ct_pos + n]);
                this.ct_pos += n;
                return Poll::Ready(Ok(()));
            }

            if this.done {
                return Poll::Ready(Ok(()));
            }

            // If plaintext buffer is full, encrypt it.
            if this.pt_len == FRAME_CHUNK_SIZE {
                this.encrypt_current_chunk()?;
                continue;
            }

            // Read more plaintext from inner.
            let pt_len = this.pt_len;
            let mut read_buf = ReadBuf::new(&mut this.pt_buf[pt_len..]);
            match this.inner.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        // EOF from inner.
                        if this.pt_len > 0 {
                            this.encrypt_current_chunk()?;
                            // Loop: will serve from ct_buf, then hit done.
                        } else {
                            this.done = true;
                        }
                    } else {
                        this.pt_len += n;
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FrameDecryptor
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a ciphertext `AsyncRead` and produces decrypted plaintext.
///
/// For full-object reads, use [`FrameDecryptor::new`].
/// For range reads, compute the ciphertext seek offset via
/// [`FrameDecryptor::ciphertext_offset`], seek the file, then use
/// [`FrameDecryptor::for_range`].
pub struct FrameDecryptor {
    inner: Pin<Box<dyn AsyncRead + Send>>,
    cipher: Aes256Gcm,
    aad_builder: AadBuilder,
    /// Total plaintext size of the object (needed to size the last frame).
    plaintext_size: u64,
    chunk_size: usize,
    /// Expected index of the next frame to read.
    chunk_index: u64,
    /// Plaintext bytes to skip at the start of output (range reads).
    skip_bytes: u64,
    /// Remaining plaintext bytes to emit.
    remaining: u64,
    /// Frame accumulation buffer: capacity = 12 + chunk_size + 16.
    frame_buf: Vec<u8>,
    frame_filled: usize,
    /// Total bytes expected in the current frame (0 = no more frames).
    frame_target: usize,
    /// Decrypted plaintext ready for output.
    out_buf: Vec<u8>,
    out_pos: usize,
    done: bool,
}

impl FrameDecryptor {
    /// Construct a decryptor for a full object read (offset=0, length=plaintext_size).
    pub fn new(
        inner: Pin<Box<dyn AsyncRead + Send>>,
        key: &[u8; 32],
        plaintext_size: u64,
        chunk_size: usize,
        aad_builder: AadBuilder,
    ) -> Self {
        Self::for_range_internal(
            inner,
            key,
            plaintext_size,
            chunk_size,
            0,
            plaintext_size,
            0,
            aad_builder,
        )
    }

    /// Construct a decryptor for a range read.
    ///
    /// The underlying reader must already be seeked to
    /// `ciphertext_offset(chunk_size, offset)` before calling this.
    pub fn for_range(
        inner: Pin<Box<dyn AsyncRead + Send>>,
        key: &[u8; 32],
        plaintext_size: u64,
        chunk_size: usize,
        offset: u64,
        length: u64,
        aad_builder: AadBuilder,
    ) -> Self {
        let start_frame = offset / chunk_size as u64;
        let frame_skip = offset % chunk_size as u64;
        Self::for_range_internal(
            inner,
            key,
            plaintext_size,
            chunk_size,
            start_frame,
            length,
            frame_skip,
            aad_builder,
        )
    }

    fn for_range_internal(
        inner: Pin<Box<dyn AsyncRead + Send>>,
        key: &[u8; 32],
        plaintext_size: u64,
        chunk_size: usize,
        start_frame: u64,
        remaining: u64,
        skip_bytes: u64,
        aad_builder: AadBuilder,
    ) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let frame_cap = 12 + chunk_size + 16;
        let done = plaintext_size == 0 || remaining == 0;
        let mut d = Self {
            inner,
            cipher,
            aad_builder,
            plaintext_size,
            chunk_size,
            chunk_index: start_frame,
            skip_bytes,
            remaining,
            frame_buf: vec![0u8; frame_cap],
            frame_filled: 0,
            frame_target: 0,
            out_buf: Vec::new(),
            out_pos: 0,
            done,
        };
        if !done {
            d.update_frame_target();
        }
        d
    }

    /// Ciphertext byte offset to seek to before reading frames starting at
    /// plaintext `offset`.  All frames before the start frame are full-sized.
    pub fn ciphertext_offset(chunk_size: usize, offset: u64) -> u64 {
        let start_frame = offset / chunk_size as u64;
        start_frame * (chunk_size as u64 + FRAME_OVERHEAD as u64)
    }

    /// Compute `frame_target` for the current `chunk_index`.
    fn update_frame_target(&mut self) {
        let bytes_before = self.chunk_index * self.chunk_size as u64;
        if bytes_before >= self.plaintext_size {
            self.frame_target = 0;
        } else {
            let pt = (self.plaintext_size - bytes_before).min(self.chunk_size as u64) as usize;
            self.frame_target = 12 + pt + 16;
        }
    }
}

impl AsyncRead for FrameDecryptor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Serve from decrypted output buffer.
            if this.out_pos < this.out_buf.len() {
                // Apply any leading skip (range read within first frame).
                if this.skip_bytes > 0 {
                    let avail = (this.out_buf.len() - this.out_pos) as u64;
                    let skip = this.skip_bytes.min(avail) as usize;
                    this.out_pos += skip;
                    this.skip_bytes -= skip as u64;
                }

                if this.out_pos < this.out_buf.len() && this.remaining > 0 {
                    let avail = (this.out_buf.len() - this.out_pos)
                        .min(this.remaining as usize)
                        .min(buf.remaining());
                    if avail > 0 {
                        buf.put_slice(&this.out_buf[this.out_pos..this.out_pos + avail]);
                        this.out_pos += avail;
                        this.remaining -= avail as u64;
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            // Done if remaining reaches 0 or no more frames.
            if this.done || this.remaining == 0 || this.frame_target == 0 {
                return Poll::Ready(Ok(()));
            }

            // If current frame buffer is complete, decrypt it.
            if this.frame_filled == this.frame_target {
                let nonce_bytes: [u8; 12] = this.frame_buf[..12].try_into().unwrap();
                let ct_with_tag = &this.frame_buf[12..this.frame_filled];

                // Verify that the nonce's chunk-index portion matches expected.
                let stored_idx = u64::from_le_bytes(nonce_bytes[4..12].try_into().unwrap());
                if stored_idx != this.chunk_index {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "frame index mismatch: expected {}, got {}",
                            this.chunk_index, stored_idx
                        ),
                    )));
                }

                let nonce = Nonce::from_slice(&nonce_bytes);
                let aad = (this.aad_builder)(this.chunk_index);
                match this.cipher.decrypt(
                    nonce,
                    Payload {
                        msg: ct_with_tag,
                        aad: &aad,
                    },
                ) {
                    Ok(pt) => {
                        this.out_buf = pt;
                        this.out_pos = 0;
                    }
                    Err(_) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AES-GCM decryption failed: authentication error",
                        )));
                    }
                }

                this.chunk_index += 1;
                this.frame_filled = 0;
                this.update_frame_target();
                // Loop to serve from out_buf.
                continue;
            }

            // Read more ciphertext bytes into the frame buffer.
            let filled = this.frame_filled;
            let target = this.frame_target;
            let mut read_buf = ReadBuf::new(&mut this.frame_buf[filled..target]);
            match this.inner.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if this.frame_filled == 0 {
                            // Clean EOF at a frame boundary.
                            this.done = true;
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated encrypted frame",
                            )));
                        }
                    }
                    this.frame_filled += n;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build the 12-byte GCM nonce: 4-byte prefix || 8-byte chunk index (LE).
pub fn make_nonce(prefix: &[u8; 4], chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    async fn encrypt_bytes(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let prefix = [1u8, 2, 3, 4];
        let enc = FrameEncryptor::new(
            Box::pin(std::io::Cursor::new(plaintext.to_vec())),
            key,
            prefix,
            no_aad(),
        );
        let mut out = Vec::new();
        let mut r = Box::pin(enc);
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    async fn decrypt_bytes(ciphertext: &[u8], key: &[u8; 32], plaintext_size: u64) -> Vec<u8> {
        let dec = FrameDecryptor::new(
            Box::pin(std::io::Cursor::new(ciphertext.to_vec())),
            key,
            plaintext_size,
            FRAME_CHUNK_SIZE,
            no_aad(),
        );
        let mut out = Vec::new();
        let mut r = Box::pin(dec);
        r.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn round_trip_small() {
        let key = test_key();
        let pt = b"hello, encrypted world!";
        let ct = encrypt_bytes(pt, &key).await;
        // Ciphertext should be pt.len() + 12 + 16 bytes
        assert_eq!(ct.len(), pt.len() + 28);
        let dec = decrypt_bytes(&ct, &key, pt.len() as u64).await;
        assert_eq!(dec, pt);
    }

    #[tokio::test]
    async fn round_trip_empty() {
        let key = test_key();
        let ct = encrypt_bytes(&[], &key).await;
        assert_eq!(ct.len(), 0);
        let dec = decrypt_bytes(&ct, &key, 0).await;
        assert_eq!(dec, b"");
    }

    #[tokio::test]
    async fn round_trip_multi_frame() {
        let key = test_key();
        // 2.5 frames
        let pt: Vec<u8> = (0..FRAME_CHUNK_SIZE * 2 + 1000)
            .map(|i| (i % 256) as u8)
            .collect();
        let ct = encrypt_bytes(&pt, &key).await;
        let dec = decrypt_bytes(&ct, &key, pt.len() as u64).await;
        assert_eq!(dec, pt);
    }

    #[tokio::test]
    async fn range_read_within_first_frame() {
        let key = test_key();
        let pt: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let ct = encrypt_bytes(&pt, &key).await;

        let offset = 100u64;
        let length = 200u64;
        let ct_off = FrameDecryptor::ciphertext_offset(FRAME_CHUNK_SIZE, offset);

        let dec = FrameDecryptor::for_range(
            Box::pin(std::io::Cursor::new(ct[ct_off as usize..].to_vec())),
            &key,
            pt.len() as u64,
            FRAME_CHUNK_SIZE,
            offset,
            length,
            no_aad(),
        );
        let mut out = Vec::new();
        Box::pin(dec).read_to_end(&mut out).await.unwrap();
        assert_eq!(out, &pt[offset as usize..offset as usize + length as usize]);
    }

    #[tokio::test]
    async fn range_read_cross_frame() {
        let key = test_key();
        let pt: Vec<u8> = (0..FRAME_CHUNK_SIZE * 3).map(|i| (i % 256) as u8).collect();
        let ct = encrypt_bytes(&pt, &key).await;

        // Range spanning end of frame 0 and start of frame 1
        let offset = (FRAME_CHUNK_SIZE - 100) as u64;
        let length = 200u64;
        let ct_off = FrameDecryptor::ciphertext_offset(FRAME_CHUNK_SIZE, offset);

        let dec = FrameDecryptor::for_range(
            Box::pin(std::io::Cursor::new(ct[ct_off as usize..].to_vec())),
            &key,
            pt.len() as u64,
            FRAME_CHUNK_SIZE,
            offset,
            length,
            no_aad(),
        );
        let mut out = Vec::new();
        Box::pin(dec).read_to_end(&mut out).await.unwrap();
        assert_eq!(out, &pt[offset as usize..offset as usize + length as usize]);
    }

    #[tokio::test]
    async fn tampered_ciphertext_rejected() {
        let key = test_key();
        let pt = b"tamper test data";
        let mut ct = encrypt_bytes(pt, &key).await;
        // Flip a byte in the ciphertext (after the nonce, before the tag)
        ct[13] ^= 0xFF;

        let dec = FrameDecryptor::new(
            Box::pin(std::io::Cursor::new(ct)),
            &key,
            pt.len() as u64,
            FRAME_CHUNK_SIZE,
            no_aad(),
        );
        let mut out = Vec::new();
        let result = Box::pin(dec).read_to_end(&mut out).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wrong_key_rejected() {
        let key = test_key();
        let pt = b"wrong key test";
        let ct = encrypt_bytes(pt, &key).await;

        let wrong_key = [0xFFu8; 32];
        let dec = FrameDecryptor::new(
            Box::pin(std::io::Cursor::new(ct)),
            &wrong_key,
            pt.len() as u64,
            FRAME_CHUNK_SIZE,
            no_aad(),
        );
        let mut out = Vec::new();
        let result = Box::pin(dec).read_to_end(&mut out).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn aad_round_trip() {
        let key = test_key();
        let pt = b"aad bound data";
        let prefix = [1u8, 2, 3, 4];
        let aad: AadBuilder = Arc::new(|idx| format!("bucket/key#{}", idx).into_bytes());

        let enc = FrameEncryptor::new(
            Box::pin(std::io::Cursor::new(pt.to_vec())),
            &key,
            prefix,
            aad.clone(),
        );
        let mut ct = Vec::new();
        Box::pin(enc).read_to_end(&mut ct).await.unwrap();

        let dec = FrameDecryptor::new(
            Box::pin(std::io::Cursor::new(ct.clone())),
            &key,
            pt.len() as u64,
            FRAME_CHUNK_SIZE,
            aad,
        );
        let mut out = Vec::new();
        Box::pin(dec).read_to_end(&mut out).await.unwrap();
        assert_eq!(out, pt);
    }

    #[tokio::test]
    async fn wrong_aad_rejected() {
        let key = test_key();
        let pt = b"aad bound data";
        let prefix = [1u8, 2, 3, 4];
        let aad_a: AadBuilder = Arc::new(|_| b"bucket-A".to_vec());
        let aad_b: AadBuilder = Arc::new(|_| b"bucket-B".to_vec());

        let enc = FrameEncryptor::new(
            Box::pin(std::io::Cursor::new(pt.to_vec())),
            &key,
            prefix,
            aad_a,
        );
        let mut ct = Vec::new();
        Box::pin(enc).read_to_end(&mut ct).await.unwrap();

        let dec = FrameDecryptor::new(
            Box::pin(std::io::Cursor::new(ct)),
            &key,
            pt.len() as u64,
            FRAME_CHUNK_SIZE,
            aad_b,
        );
        let mut out = Vec::new();
        let result = Box::pin(dec).read_to_end(&mut out).await;
        assert!(result.is_err());
    }
}
