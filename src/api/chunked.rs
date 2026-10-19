//! Streaming decoder for `Content-Encoding: aws-chunked` request bodies.
//!
//! Supported `x-amz-content-sha256` modes:
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: signed chunks (mc / minio-go over HTTP).
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: signed chunks + signed trailer.
//! - `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: plain chunks + checksum trailer
//!   (AWS SDKs / AWS CLI v2 over HTTPS).
//!
//! Wire format: `hex-size[;chunk-signature=sig]\r\n<data>\r\n` repeated, a final
//! zero-size chunk, then optional trailer lines (`name:value\r\n`) and a final
//! `\r\n`. See
//! https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html and
//! https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html
//!
//! The decoder is wired into the request by the auth middleware (which owns the
//! signing context): the body is replaced by the decoded stream, and any
//! decoding failure is recorded in a [`FailureSlot`] so the middleware can turn
//! it into the proper S3 error response. Storage writes to a temp file and only
//! publishes after EOF, so a decoding error never produces a stored object.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use bytes::Bytes;
use futures::TryStreamExt;
use http::HeaderMap;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::auth::signature_v4::{StreamingSigningContext, constant_time_eq};
use crate::error::S3Error;
use crate::storage::{ChecksumAlgorithm, ChecksumHasher};

pub const STREAMING_SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Max length of a chunk header or trailer line (a signed header is ~90 bytes).
const MAX_LINE_LEN: usize = 4096;
/// Max cumulative trailer section size.
const MAX_TRAILER_LEN: usize = 16 * 1024;
/// Chunks larger than this are rejected (no buffering happens, it is a sanity bound).
const MAX_CHUNK_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const READ_BUF_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingMode {
    Signed,
    SignedTrailer,
    UnsignedTrailer,
}

impl StreamingMode {
    /// `Ok(None)` for non-streaming payloads (hex hash, `UNSIGNED-PAYLOAD`, absent).
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, S3Error> {
        let Some(v) = headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(None);
        };
        match v {
            STREAMING_SIGNED => Ok(Some(Self::Signed)),
            STREAMING_SIGNED_TRAILER => Ok(Some(Self::SignedTrailer)),
            STREAMING_UNSIGNED_TRAILER => Ok(Some(Self::UnsignedTrailer)),
            other if other.starts_with("STREAMING-") => Err(S3Error::not_implemented(&format!(
                "x-amz-content-sha256 {} is not supported",
                other
            ))),
            _ => Ok(None),
        }
    }

    pub fn is_signed(self) -> bool {
        matches!(self, Self::Signed | Self::SignedTrailer)
    }
}

/// Checksum algorithm declared via `x-amz-trailer`. Used by the PUT handlers so
/// storage computes and records the checksum the decoder validated.
pub fn trailer_checksum_algorithm(headers: &HeaderMap) -> Option<ChecksumAlgorithm> {
    headers
        .get("x-amz-trailer")
        .and_then(|v| v.to_str().ok())
        .and_then(declared_trailer_checksum)
}

fn declared_trailer_checksum(value: &str) -> Option<ChecksumAlgorithm> {
    value
        .split(',')
        .find_map(ChecksumAlgorithm::from_header_name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkedErrorKind {
    IncompleteBody,
    SignatureDoesNotMatch,
    InvalidRequest,
    BadDigest,
}

/// A decoding failure. Surfaced to readers as an `io::Error` (kind
/// `InvalidData`) wrapping this type, and recorded in the [`FailureSlot`].
#[derive(Debug, Clone)]
pub struct ChunkedBodyError {
    pub kind: ChunkedErrorKind,
    pub message: String,
}

impl ChunkedBodyError {
    fn new(kind: ChunkedErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn to_s3_error(&self) -> S3Error {
        match self.kind {
            ChunkedErrorKind::IncompleteBody => S3Error::incomplete_body(&self.message),
            ChunkedErrorKind::SignatureDoesNotMatch => S3Error::signature_mismatch(),
            ChunkedErrorKind::InvalidRequest => S3Error::invalid_request(&self.message),
            ChunkedErrorKind::BadDigest => {
                let mut e = S3Error::bad_digest();
                e.message = self.message.clone();
                e
            }
        }
    }
}

impl std::fmt::Display for ChunkedBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "aws-chunked {:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ChunkedBodyError {}

/// First decoding failure of a request, shared between decoder and middleware.
pub type FailureSlot = Arc<Mutex<Option<ChunkedBodyError>>>;

/// Find a [`ChunkedBodyError`] anywhere in an error's source chain.
pub fn find_chunked_error<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a ChunkedBodyError> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(c) = e.downcast_ref::<ChunkedBodyError>() {
            return Some(c);
        }
        if let Some(io) = e.downcast_ref::<io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(c) = inner.downcast_ref::<ChunkedBodyError>() {
                    return Some(c);
                }
            }
        }
        cur = e.source();
    }
    None
}

#[derive(Debug, Clone)]
pub struct DecoderConfig {
    pub mode: StreamingMode,
    pub signing: Option<StreamingSigningContext>,
    pub declared_trailer: Option<ChecksumAlgorithm>,
    pub decoded_length: Option<u64>,
}

impl DecoderConfig {
    pub fn from_headers(
        mode: StreamingMode,
        headers: &HeaderMap,
        signing: Option<StreamingSigningContext>,
    ) -> Result<Self, S3Error> {
        if mode.is_signed() && signing.is_none() {
            return Err(S3Error::invalid_request(
                "Signed streaming payloads require Authorization header signing",
            ));
        }
        let declared_trailer = match headers.get("x-amz-trailer") {
            None => None,
            Some(v) => {
                let v = v
                    .to_str()
                    .map_err(|_| S3Error::invalid_request("Invalid x-amz-trailer header"))?;
                if v.trim().is_empty() {
                    None
                } else {
                    Some(declared_trailer_checksum(v).ok_or_else(|| {
                        S3Error::invalid_request(&format!("Unsupported x-amz-trailer: {}", v))
                    })?)
                }
            }
        };
        if declared_trailer.is_some() && mode == StreamingMode::Signed {
            return Err(S3Error::invalid_request(
                "x-amz-trailer requires a STREAMING-*-TRAILER payload",
            ));
        }
        let decoded_length = match headers.get("x-amz-decoded-content-length") {
            None => None,
            Some(v) => Some(
                v.to_str()
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .ok_or_else(|| {
                        S3Error::invalid_argument("Invalid x-amz-decoded-content-length")
                    })?,
            ),
        };
        Ok(Self {
            mode,
            signing,
            declared_trailer,
            decoded_length,
        })
    }
}

/// Replace the body of a streaming request with the decoded stream and fix up
/// headers (`Content-Encoding` loses the `aws-chunked` token, `Content-Length`
/// becomes the decoded length). Returns `None` for the slot when the request is
/// not an aws-chunked upload (request returned unchanged).
pub fn prepare_request(
    request: Request,
    signing: Option<StreamingSigningContext>,
) -> Result<(Request, Option<FailureSlot>), S3Error> {
    let Some(mode) = StreamingMode::from_headers(request.headers())? else {
        return Ok((request, None));
    };
    let cfg = DecoderConfig::from_headers(mode, request.headers(), signing)?;
    let decoded_length = cfg.decoded_length;
    let slot = FailureSlot::default();

    let (mut parts, body) = request.into_parts();
    // `aws-chunked` must never be persisted as the object's encoding.
    let encoding = parts
        .headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .and_then(super::object::strip_aws_chunked)
        .and_then(|v| http::HeaderValue::from_str(&v).ok());
    match encoding {
        Some(v) => parts.headers.insert(http::header::CONTENT_ENCODING, v),
        None => parts.headers.remove(http::header::CONTENT_ENCODING),
    };
    match decoded_length {
        Some(len) => {
            parts
                .headers
                .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
        }
        None => {
            parts.headers.remove(http::header::CONTENT_LENGTH);
        }
    }

    let raw = raw_reader(body);
    let stream = decode_stream(raw, cfg, slot.clone());
    Ok((
        Request::from_parts(parts, Body::from_stream(stream)),
        Some(slot),
    ))
}

type BoxReader = Pin<Box<dyn AsyncRead + Send>>;

fn raw_reader(body: Body) -> BoxReader {
    let stream = body.into_data_stream().map_err(|e| {
        // Preserve a decoder error (if the body was already decoded) so it can be
        // recognised by `find_chunked_error`.
        if let Some(c) = find_chunked_error(&e) {
            io::Error::new(io::ErrorKind::InvalidData, c.clone())
        } else {
            io::Error::other(e)
        }
    });
    Box::pin(tokio_util::io::StreamReader::new(stream))
}

/// Request body → `AsyncRead`. aws-chunked bodies are already decoded by the
/// auth middleware ([`prepare_request`]), so this is a plain adapter.
pub async fn body_to_reader(_headers: &HeaderMap, body: Body) -> Result<BoxReader, S3Error> {
    Ok(raw_reader(body))
}

/// Wrap an encoded reader as a decoded `AsyncRead`.
#[cfg(test)]
fn decoding_reader<R: AsyncRead + Send + Unpin + 'static>(
    inner: R,
    cfg: DecoderConfig,
    slot: FailureSlot,
) -> BoxReader {
    Box::pin(tokio_util::io::StreamReader::new(decode_stream(
        inner, cfg, slot,
    )))
}

pub fn decode_stream<R: AsyncRead + Send + Unpin + 'static>(
    inner: R,
    cfg: DecoderConfig,
    slot: FailureSlot,
) -> impl futures::Stream<Item = io::Result<Bytes>> + Send + 'static {
    let decoder = Decoder::new(inner, cfg, slot);
    futures::stream::try_unfold(decoder, |mut d| async move {
        match d.next_piece().await {
            Ok(Some(b)) => Ok(Some((b, d))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    })
}

enum State {
    Header,
    Data,
    Done,
}

struct Decoder<R> {
    reader: BufReader<R>,
    cfg: DecoderConfig,
    slot: FailureSlot,
    state: State,
    prev_signature: String,
    chunk_remaining: u64,
    chunk_signature: Option<String>,
    chunk_hasher: Option<Sha256>,
    checksum: Option<ChecksumHasher>,
    decoded: u64,
}

impl<R: AsyncRead + Unpin> Decoder<R> {
    fn new(inner: R, cfg: DecoderConfig, slot: FailureSlot) -> Self {
        let prev_signature = cfg
            .signing
            .as_ref()
            .map(|s| s.seed_signature.clone())
            .unwrap_or_default();
        let checksum = cfg.declared_trailer.map(ChecksumHasher::new);
        Self {
            reader: BufReader::with_capacity(READ_BUF_SIZE, inner),
            cfg,
            slot,
            state: State::Header,
            prev_signature,
            chunk_remaining: 0,
            chunk_signature: None,
            chunk_hasher: None,
            checksum,
            decoded: 0,
        }
    }

    async fn next_piece(&mut self) -> io::Result<Option<Bytes>> {
        match self.step().await {
            Ok(v) => Ok(v),
            Err(StepError::Io(e)) => {
                self.state = State::Done;
                Err(e)
            }
            Err(StepError::Chunked(c)) => {
                self.state = State::Done;
                tracing::debug!("aws-chunked decode failed: {}", c);
                let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
                if slot.is_none() {
                    *slot = Some(c.clone());
                }
                Err(io::Error::new(io::ErrorKind::InvalidData, c))
            }
        }
    }

    async fn step(&mut self) -> Result<Option<Bytes>, StepError> {
        loop {
            match self.state {
                State::Done => return Ok(None),
                State::Header => {
                    let line = self
                        .read_line()
                        .await?
                        .ok_or_else(|| incomplete("missing aws-chunked chunk header"))?;
                    let (size, sig) = parse_chunk_header(&line, self.cfg.mode.is_signed())?;
                    if let Some(expected) = self.cfg.decoded_length {
                        if self.decoded + size > expected {
                            return Err(incomplete(
                                "aws-chunked payload exceeds x-amz-decoded-content-length",
                            ));
                        }
                    }
                    if size == 0 {
                        self.verify_chunk_signature(sig.as_deref(), EMPTY_SHA256)?;
                        self.finish().await?;
                        self.state = State::Done;
                        return Ok(None);
                    }
                    self.chunk_remaining = size;
                    self.chunk_signature = sig;
                    self.chunk_hasher = self.cfg.mode.is_signed().then(Sha256::new);
                    self.state = State::Data;
                }
                State::Data => {
                    if self.chunk_remaining == 0 {
                        let mut crlf = [0u8; 2];
                        match self.reader.read_exact(&mut crlf).await {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                                return Err(incomplete("aws-chunked chunk not terminated"));
                            }
                            Err(e) => return Err(StepError::Io(e)),
                        }
                        if &crlf != b"\r\n" {
                            return Err(invalid("aws-chunked chunk data not followed by CRLF"));
                        }
                        let data_hash = self
                            .chunk_hasher
                            .take()
                            .map(|h| hex::encode(h.finalize()))
                            .unwrap_or_default();
                        let sig = self.chunk_signature.take();
                        self.verify_chunk_signature(sig.as_deref(), &data_hash)?;
                        self.state = State::Header;
                        continue;
                    }
                    let buf = self.reader.fill_buf().await.map_err(StepError::Io)?;
                    if buf.is_empty() {
                        return Err(incomplete("aws-chunked body ended inside a chunk"));
                    }
                    let n = buf.len().min(self.chunk_remaining as usize);
                    let piece = Bytes::copy_from_slice(&buf[..n]);
                    self.reader.consume(n);
                    if let Some(h) = self.chunk_hasher.as_mut() {
                        h.update(&piece);
                    }
                    if let Some(c) = self.checksum.as_mut() {
                        c.update(&piece);
                    }
                    self.chunk_remaining -= n as u64;
                    self.decoded += n as u64;
                    return Ok(Some(piece));
                }
            }
        }
    }

    fn verify_chunk_signature(
        &mut self,
        provided: Option<&str>,
        data_hash_hex: &str,
    ) -> Result<(), StepError> {
        let Some(ctx) = self
            .cfg
            .signing
            .as_ref()
            .filter(|_| self.cfg.mode.is_signed())
        else {
            return Ok(());
        };
        let provided = provided.ok_or_else(|| invalid("missing chunk-signature"))?;
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            ctx.timestamp, ctx.scope, self.prev_signature, EMPTY_SHA256, data_hash_hex
        );
        let computed = ctx.hmac_hex(&sts);
        if !constant_time_eq(
            computed.as_bytes(),
            provided.to_ascii_lowercase().as_bytes(),
        ) {
            return Err(ChunkedBodyError::new(
                ChunkedErrorKind::SignatureDoesNotMatch,
                "chunk signature mismatch",
            )
            .into());
        }
        self.prev_signature = computed;
        Ok(())
    }

    /// After the zero-size chunk: length check, trailers, trailer signature, checksum.
    async fn finish(&mut self) -> Result<(), StepError> {
        if let Some(expected) = self.cfg.decoded_length {
            if self.decoded != expected {
                return Err(incomplete(&format!(
                    "decoded {} bytes but x-amz-decoded-content-length is {}",
                    self.decoded, expected
                )));
            }
        }

        let mut trailers: Vec<(String, String)> = Vec::new();
        let mut trailer_signature: Option<String> = None;
        let mut total = 0usize;
        // Lenient about the final CRLF: some clients end the body right after
        // the last chunk / trailer line.
        while let Some(line) = self.read_line().await? {
            if line.is_empty() {
                break;
            }
            total += line.len();
            if total > MAX_TRAILER_LEN {
                return Err(invalid("aws-chunked trailer section too large"));
            }
            let line = std::str::from_utf8(&line).map_err(|_| invalid("invalid trailer line"))?;
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("malformed trailer line"))?;
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "x-amz-trailer-signature" {
                trailer_signature = Some(value);
            } else {
                trailers.push((name, value));
            }
        }

        if self.cfg.mode == StreamingMode::SignedTrailer {
            let ctx = self
                .cfg
                .signing
                .as_ref()
                .ok_or_else(|| invalid("missing signing context"))?;
            let provided =
                trailer_signature.ok_or_else(|| invalid("missing x-amz-trailer-signature"))?;
            let canonical: String = trailers
                .iter()
                .map(|(n, v)| format!("{}:{}\n", n, v))
                .collect();
            let sts = format!(
                "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
                ctx.timestamp,
                ctx.scope,
                self.prev_signature,
                hex::encode(Sha256::digest(canonical.as_bytes()))
            );
            let computed = ctx.hmac_hex(&sts);
            if !constant_time_eq(
                computed.as_bytes(),
                provided.to_ascii_lowercase().as_bytes(),
            ) {
                return Err(ChunkedBodyError::new(
                    ChunkedErrorKind::SignatureDoesNotMatch,
                    "trailer signature mismatch",
                )
                .into());
            }
        }

        if let (Some(algo), Some(state)) = (self.cfg.declared_trailer, self.checksum.take()) {
            let expected = trailers
                .iter()
                .find(|(n, _)| n == algo.header_name())
                .map(|(_, v)| v.as_str())
                .ok_or_else(|| {
                    invalid(&format!(
                        "declared trailer {} missing from body",
                        algo.header_name()
                    ))
                })?;
            let computed = state.finalize_base64();
            if computed != expected {
                return Err(ChunkedBodyError::new(
                    ChunkedErrorKind::BadDigest,
                    format!(
                        "The {} you specified did not match the calculated checksum.",
                        algo.header_name()
                    ),
                )
                .into());
            }
        }
        Ok(())
    }

    /// Read one `\n`-terminated line (CR stripped) of bounded length.
    /// `Ok(None)` on clean EOF; a partial line at EOF is an incomplete body.
    async fn read_line(&mut self) -> Result<Option<Vec<u8>>, StepError> {
        let mut line = Vec::new();
        loop {
            let buf = self.reader.fill_buf().await.map_err(StepError::Io)?;
            if buf.is_empty() {
                if line.is_empty() {
                    return Ok(None);
                }
                return Err(incomplete("aws-chunked body ended mid-line"));
            }
            if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                if line.len() + pos > MAX_LINE_LEN {
                    return Err(invalid("aws-chunked line too long"));
                }
                line.extend_from_slice(&buf[..pos]);
                self.reader.consume(pos + 1);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            let n = buf.len();
            if line.len() + n > MAX_LINE_LEN {
                return Err(invalid("aws-chunked line too long"));
            }
            line.extend_from_slice(buf);
            self.reader.consume(n);
        }
    }
}

enum StepError {
    Io(io::Error),
    Chunked(ChunkedBodyError),
}

impl From<ChunkedBodyError> for StepError {
    fn from(e: ChunkedBodyError) -> Self {
        Self::Chunked(e)
    }
}

fn incomplete(msg: &str) -> StepError {
    ChunkedBodyError::new(ChunkedErrorKind::IncompleteBody, msg).into()
}

fn invalid(msg: &str) -> StepError {
    ChunkedBodyError::new(ChunkedErrorKind::InvalidRequest, msg).into()
}

/// Parse `hex-size[;chunk-signature=sig][;other-ext]`.
fn parse_chunk_header(line: &[u8], signed: bool) -> Result<(u64, Option<String>), StepError> {
    let line = std::str::from_utf8(line).map_err(|_| invalid("invalid chunk header"))?;
    let mut parts = line.split(';');
    let size_str = parts.next().unwrap_or("").trim();
    if size_str.is_empty()
        || size_str.len() > 16
        || !size_str.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("invalid aws-chunked chunk size"));
    }
    let size = u64::from_str_radix(size_str, 16).map_err(|_| invalid("invalid chunk size"))?;
    if size > MAX_CHUNK_SIZE {
        return Err(invalid("aws-chunked chunk size too large"));
    }
    let mut signature = None;
    for ext in parts {
        if let Some(v) = ext.trim().strip_prefix("chunk-signature=") {
            if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid("malformed chunk-signature"));
            }
            signature = Some(v.to_string());
        }
    }
    if signed && signature.is_none() {
        return Err(invalid("missing chunk-signature"));
    }
    Ok((size, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::signature_v4::derive_signing_key;
    use base64::Engine;

    // Vectors from
    // https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html
    const SEED: &str = "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e";
    const SIG1: &str = "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2";
    const SIG2: &str = "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7";
    const SIG_FINAL: &str = "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992";
    const SIG_TRAILER: &str = "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435";

    fn aws_ctx() -> StreamingSigningContext {
        StreamingSigningContext {
            signing_key: derive_signing_key(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "20130524",
                "us-east-1",
            ),
            timestamp: "20130524T000000Z".into(),
            scope: "20130524/us-east-1/s3/aws4_request".into(),
            seed_signature: SEED.into(),
        }
    }

    fn aws_body(sig2: &str, trailer_value: &str, trailer_sig: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(format!("10000;chunk-signature={}\r\n", SIG1).as_bytes());
        b.extend_from_slice(&[b'a'; 65536]);
        b.extend_from_slice(b"\r\n");
        b.extend_from_slice(format!("400;chunk-signature={}\r\n", sig2).as_bytes());
        b.extend_from_slice(&[b'a'; 1024]);
        b.extend_from_slice(b"\r\n");
        b.extend_from_slice(format!("0;chunk-signature={}\r\n", SIG_FINAL).as_bytes());
        b.extend_from_slice(format!("x-amz-checksum-crc32c:{}\r\n", trailer_value).as_bytes());
        b.extend_from_slice(format!("x-amz-trailer-signature:{}\r\n", trailer_sig).as_bytes());
        b.extend_from_slice(b"\r\n");
        b
    }

    fn cfg(
        mode: StreamingMode,
        trailer: Option<ChecksumAlgorithm>,
        len: Option<u64>,
    ) -> DecoderConfig {
        DecoderConfig {
            mode,
            signing: mode.is_signed().then(aws_ctx),
            declared_trailer: trailer,
            decoded_length: len,
        }
    }

    /// Feed `body` in pieces of `piece` bytes and decode it fully.
    async fn decode(
        body: Vec<u8>,
        piece: usize,
        cfg: DecoderConfig,
    ) -> (io::Result<Vec<u8>>, Option<ChunkedBodyError>) {
        let pieces: Vec<io::Result<Bytes>> = body
            .chunks(piece)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let inner = tokio_util::io::StreamReader::new(futures::stream::iter(pieces));
        let slot = FailureSlot::default();
        let mut reader = decoding_reader(inner, cfg, slot.clone());
        let mut out = Vec::new();
        let res = reader.read_to_end(&mut out).await.map(|_| out);
        let failure = slot.lock().unwrap().clone();
        (res, failure)
    }

    #[tokio::test]
    async fn aws_signed_trailer_vectors_decode() {
        for piece in [1, 7, 100, 65_537, 1 << 20] {
            let (res, failure) = decode(
                aws_body(SIG2, "sOO8/Q==", SIG_TRAILER),
                piece,
                cfg(
                    StreamingMode::SignedTrailer,
                    Some(ChecksumAlgorithm::CRC32C),
                    Some(66560),
                ),
            )
            .await;
            assert!(failure.is_none(), "piece {piece}: {failure:?}");
            let out = res.unwrap();
            assert_eq!(out.len(), 66560);
            assert!(out.iter().all(|&b| b == b'a'));
        }
    }

    #[tokio::test]
    async fn bad_chunk_signature_fails() {
        let bad = "0".repeat(64);
        let (res, failure) = decode(
            aws_body(&bad, "sOO8/Q==", SIG_TRAILER),
            4096,
            cfg(
                StreamingMode::SignedTrailer,
                Some(ChecksumAlgorithm::CRC32C),
                None,
            ),
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            find_chunked_error(&err).unwrap().kind,
            ChunkedErrorKind::SignatureDoesNotMatch
        );
        assert_eq!(
            failure.unwrap().kind,
            ChunkedErrorKind::SignatureDoesNotMatch
        );
    }

    #[tokio::test]
    async fn bad_trailer_signature_fails() {
        let bad = SIG_TRAILER.replace('d', "e");
        let (res, failure) = decode(
            aws_body(SIG2, "sOO8/Q==", &bad),
            4096,
            cfg(
                StreamingMode::SignedTrailer,
                Some(ChecksumAlgorithm::CRC32C),
                None,
            ),
        )
        .await;
        assert!(res.is_err());
        assert_eq!(
            failure.unwrap().kind,
            ChunkedErrorKind::SignatureDoesNotMatch
        );
    }

    #[tokio::test]
    async fn signed_trailer_with_tampered_value_fails_signature() {
        // Changing the trailer value breaks the trailer signature first.
        let (_, failure) = decode(
            aws_body(SIG2, "AAAAAA==", SIG_TRAILER),
            4096,
            cfg(
                StreamingMode::SignedTrailer,
                Some(ChecksumAlgorithm::CRC32C),
                None,
            ),
        )
        .await;
        assert_eq!(
            failure.unwrap().kind,
            ChunkedErrorKind::SignatureDoesNotMatch
        );
    }

    fn unsigned_body(chunks: &[&[u8]], trailer: Option<(&str, &str)>) -> Vec<u8> {
        let mut b = Vec::new();
        for c in chunks {
            b.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
            b.extend_from_slice(c);
            b.extend_from_slice(b"\r\n");
        }
        b.extend_from_slice(b"0\r\n");
        if let Some((n, v)) = trailer {
            b.extend_from_slice(format!("{}:{}\r\n", n, v).as_bytes());
        }
        b.extend_from_slice(b"\r\n");
        b
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[tokio::test]
    async fn unsigned_trailer_all_checksums() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
        let mut crc64 = ChecksumHasher::new(ChecksumAlgorithm::CRC64NVME);
        crc64.update(&data);
        let cases = [
            (
                ChecksumAlgorithm::CRC32,
                b64(&crc32fast::hash(&data).to_be_bytes()),
            ),
            (
                ChecksumAlgorithm::CRC32C,
                b64(&crc32c::crc32c(&data).to_be_bytes()),
            ),
            (
                ChecksumAlgorithm::SHA1,
                b64(&<sha1::Sha1 as sha1::Digest>::digest(&data)),
            ),
            (ChecksumAlgorithm::SHA256, b64(&Sha256::digest(&data))),
            (ChecksumAlgorithm::CRC64NVME, crc64.finalize_base64()),
        ];
        let chunks: Vec<&[u8]> = data.chunks(30_000).collect();
        for (algo, value) in cases {
            let (res, failure) = decode(
                unsigned_body(&chunks, Some((algo.header_name(), &value))),
                333,
                cfg(StreamingMode::UnsignedTrailer, Some(algo), Some(100_000)),
            )
            .await;
            assert!(failure.is_none(), "{algo:?}: {failure:?}");
            assert_eq!(res.unwrap(), data);

            let (res, failure) = decode(
                unsigned_body(&chunks, Some((algo.header_name(), "AAAAAAAA"))),
                333,
                cfg(StreamingMode::UnsignedTrailer, Some(algo), None),
            )
            .await;
            assert!(res.is_err());
            assert_eq!(
                failure.unwrap().kind,
                ChunkedErrorKind::BadDigest,
                "{algo:?}"
            );
        }
    }

    #[test]
    fn crc64nvme_check_value() {
        let mut s = ChecksumHasher::new(ChecksumAlgorithm::CRC64NVME);
        s.update(b"123456789");
        assert_eq!(
            s.finalize_base64(),
            b64(&0xAE8B_1486_0A79_9888u64.to_be_bytes())
        );
    }

    #[tokio::test]
    async fn missing_declared_trailer_fails() {
        let (res, failure) = decode(
            unsigned_body(&[b"hello"], None),
            3,
            cfg(
                StreamingMode::UnsignedTrailer,
                Some(ChecksumAlgorithm::CRC32),
                None,
            ),
        )
        .await;
        assert!(res.is_err());
        assert_eq!(failure.unwrap().kind, ChunkedErrorKind::InvalidRequest);
    }

    #[tokio::test]
    async fn truncated_body_is_incomplete() {
        let full = unsigned_body(&[b"hello world"], None);
        for cut in [3, 6, 10, 17] {
            let (res, failure) = decode(
                full[..cut].to_vec(),
                2,
                cfg(StreamingMode::UnsignedTrailer, None, None),
            )
            .await;
            assert!(res.is_err(), "cut {cut}");
            assert_eq!(
                failure.unwrap().kind,
                ChunkedErrorKind::IncompleteBody,
                "cut {cut}"
            );
        }
        // Empty body: no final chunk at all.
        let (_, failure) = decode(vec![], 1, cfg(StreamingMode::UnsignedTrailer, None, None)).await;
        assert_eq!(failure.unwrap().kind, ChunkedErrorKind::IncompleteBody);
    }

    #[tokio::test]
    async fn decoded_length_mismatch_is_incomplete() {
        for len in [5, 20] {
            let (_, failure) = decode(
                unsigned_body(&[b"hello world"], None),
                4,
                cfg(StreamingMode::UnsignedTrailer, None, Some(len)),
            )
            .await;
            assert_eq!(failure.unwrap().kind, ChunkedErrorKind::IncompleteBody);
        }
    }

    #[tokio::test]
    async fn trailer_parsing_tolerates_missing_final_crlf_and_extra_trailers() {
        let data = b"payload";
        let crc = b64(&crc32fast::hash(data).to_be_bytes());
        let body = format!(
            "7\r\npayload\r\n0\r\nx-amz-meta-other: x\r\nX-Amz-Checksum-Crc32: {}\r\n",
            crc
        );
        let (res, failure) = decode(
            body.into_bytes(),
            5,
            cfg(
                StreamingMode::UnsignedTrailer,
                Some(ChecksumAlgorithm::CRC32),
                Some(7),
            ),
        )
        .await;
        assert!(failure.is_none(), "{failure:?}");
        assert_eq!(res.unwrap(), data);
    }

    #[tokio::test]
    async fn malformed_and_oversized_headers_rejected() {
        for body in [
            b"zz\r\nabc\r\n0\r\n\r\n".to_vec(),
            b"fffffffffffffffff\r\n".to_vec(),
            b"ffffffffff\r\n".to_vec(),
            [vec![b'1'; MAX_LINE_LEN + 10], b"\r\n".to_vec()].concat(),
            b"3\r\nabcXY0\r\n\r\n".to_vec(),
        ] {
            let (res, failure) =
                decode(body, 3, cfg(StreamingMode::UnsignedTrailer, None, None)).await;
            assert!(res.is_err());
            assert_eq!(failure.unwrap().kind, ChunkedErrorKind::InvalidRequest);
        }
        // Signed mode requires chunk signatures.
        let (_, failure) = decode(
            b"3\r\nabc\r\n0\r\n\r\n".to_vec(),
            3,
            cfg(StreamingMode::Signed, None, None),
        )
        .await;
        assert_eq!(failure.unwrap().kind, ChunkedErrorKind::InvalidRequest);
    }

    #[test]
    fn mode_detection() {
        let mut h = HeaderMap::new();
        assert_eq!(StreamingMode::from_headers(&h).unwrap(), None);
        h.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(StreamingMode::from_headers(&h).unwrap(), None);
        h.insert(
            "x-amz-content-sha256",
            STREAMING_UNSIGNED_TRAILER.parse().unwrap(),
        );
        assert_eq!(
            StreamingMode::from_headers(&h).unwrap(),
            Some(StreamingMode::UnsignedTrailer)
        );
        h.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD".parse().unwrap(),
        );
        assert!(StreamingMode::from_headers(&h).is_err());
    }
}
