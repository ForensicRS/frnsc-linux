//! Decompression for a journal `DATA` object's payload.
//!
//! Confirmed against systemd's own `src/basic/compress.c` (`compress_blob_journal`/
//! `decompress_blob_lz4`/`decompress_blob_zstd`/`decompress_blob_xz`, the functions actually used
//! for journal `DATA` object payloads — a different code path from the `LZ4F_*`
//! frame-format functions the same file uses elsewhere for journal-remote's network stream):
//!
//! - **LZ4**: an 8-byte little-endian uncompressed-size prefix, then a raw `LZ4_compress_default`/
//!   `LZ4_decompress_safe` block (the *block* API, not the LZ4 frame format — there is no LZ4
//!   frame magic to look for here).
//! - **ZSTD**: a standard zstd frame produced by plain `ZSTD_compress`, which embeds the content
//!   size in the frame header.
//! - **XZ**: a standard `.xz` container produced by `lzma_stream_buffer_encode`.
//!
//! Every path is bounded by `max_output`: a payload that claims (LZ4) or would produce (ZSTD/XZ,
//! read incrementally) more than that is an `Err`, never an unbounded allocation — see
//! `a_payload_claiming_more_than_the_cap_is_rejected_before_allocating` and the per-codec
//! zip-bomb-shaped tests below. `MAX_DECOMPRESSED_SIZE` is deliberately larger than the real
//! `linux-journal-zip-bomb-synthetic` fixture's 64 MiB message (a legitimate, if extreme, journal
//! field — see `crates/frnsc-linux/tests/journal_real_samples.rs`), so that fixture still
//! round-trips; the hostile-input guarantee is instead pinned by hand-built fixtures whose claimed
//! size exceeds the cap outright.

use forensic_rs::prelude::*;

/// Upper bound on any single decompressed payload. Chosen to comfortably clear the real
/// `linux-journal-zip-bomb-synthetic` fixture's 64 MiB message while still bounding worst-case
/// memory for a hostile file with an inflated claimed size.
pub const MAX_DECOMPRESSED_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Xz,
    Lz4,
    Zstd,
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Xz => "xz",
            Codec::Lz4 => "lz4",
            Codec::Zstd => "zstd",
        }
    }
}

/// `ObjectHeader.flags` bits meaningful on a `DATA` object. `1<<0`=XZ, `1<<1`=LZ4, `1<<2`=ZSTD —
/// note this is a *different* bit assignment from `Header.incompatible_flags`, which orders
/// XZ/LZ4/KEYED_HASH/ZSTD/COMPACT.
pub fn codec_from_object_flags(flags: u8) -> Option<Codec> {
    if flags & 0x1 != 0 {
        Some(Codec::Xz)
    } else if flags & 0x2 != 0 {
        Some(Codec::Lz4)
    } else if flags & 0x4 != 0 {
        Some(Codec::Zstd)
    } else {
        None
    }
}

/// Decompresses `compressed` with `codec`, bounded by `max_output` bytes. Never allocates more
/// than `max_output` regardless of what the compressed stream claims or would otherwise produce.
pub fn decompress(codec: Codec, compressed: &[u8], max_output: u64) -> ForensicResult<Vec<u8>> {
    match codec {
        Codec::Lz4 => decompress_lz4(compressed, max_output),
        Codec::Zstd => decompress_zstd(compressed, max_output),
        Codec::Xz => decompress_xz(compressed, max_output),
    }
}

fn too_big(codec: Codec, claimed_or_seen: u64, max_output: u64) -> ForensicError {
    ForensicError::invalid_format(
        "journal data payload",
        format!(
            "{} payload is {claimed_or_seen} byte(s) uncompressed, exceeding the {max_output} \
             byte cap",
            codec.name()
        ),
    )
}

fn unsupported(codec: Codec) -> ForensicError {
    ForensicError::other(
        "journal",
        format!(
            "{} payload found but frnsc-linux was built without the \"{}\" feature",
            codec.name(),
            codec.name()
        ),
    )
}

#[cfg(feature = "lz4")]
fn decompress_lz4(compressed: &[u8], max_output: u64) -> ForensicResult<Vec<u8>> {
    if compressed.len() < 8 {
        return Err(ForensicError::invalid_format(
            "journal data payload",
            format!(
                "lz4 payload is only {} byte(s), too short for the 8-byte size prefix",
                compressed.len()
            ),
        ));
    }
    let declared_size = u64::from_le_bytes(compressed[0..8].try_into().unwrap());
    if declared_size > max_output {
        return Err(too_big(Codec::Lz4, declared_size, max_output));
    }
    lz4_flex::block::decompress(&compressed[8..], declared_size as usize).map_err(|e| {
        ForensicError::invalid_format(
            "journal data payload",
            format!("lz4 block decompression failed: {e}"),
        )
    })
}

#[cfg(not(feature = "lz4"))]
fn decompress_lz4(_compressed: &[u8], _max_output: u64) -> ForensicResult<Vec<u8>> {
    Err(unsupported(Codec::Lz4))
}

#[cfg(feature = "zstd")]
fn decompress_zstd(compressed: &[u8], max_output: u64) -> ForensicResult<Vec<u8>> {
    // `new_with_max_window_size` rejects a frame whose declared window exceeds `max_output`
    // *before* allocating that window, so a hostile frame header alone cannot force a large
    // allocation ahead of the byte-by-byte cap `read_capped` enforces below.
    let mut decoder =
        ruzstd::decoding::StreamingDecoder::new_with_max_window_size(compressed, max_output)
            .map_err(|e| {
                ForensicError::invalid_format(
                    "journal data payload",
                    format!("zstd frame header is malformed or its window is too large: {e}"),
                )
            })?;
    read_capped(&mut decoder, max_output, Codec::Zstd)
}

#[cfg(not(feature = "zstd"))]
fn decompress_zstd(_compressed: &[u8], _max_output: u64) -> ForensicResult<Vec<u8>> {
    Err(unsupported(Codec::Zstd))
}

#[cfg(feature = "xz")]
fn decompress_xz(compressed: &[u8], max_output: u64) -> ForensicResult<Vec<u8>> {
    let mut input = compressed;
    let mut writer = CappedWriter::new(max_output, Codec::Xz);
    match lzma_rs::xz_decompress(&mut input, &mut writer) {
        Ok(()) => Ok(writer.buf),
        Err(lzma_rs::error::Error::IoError(e)) if e.kind() == std::io::ErrorKind::OutOfMemory => {
            Err(writer.into_cap_error())
        }
        Err(e) => Err(ForensicError::invalid_format(
            "journal data payload",
            format!("xz decompression failed: {e}"),
        )),
    }
}

#[cfg(not(feature = "xz"))]
fn decompress_xz(_compressed: &[u8], _max_output: u64) -> ForensicResult<Vec<u8>> {
    Err(unsupported(Codec::Xz))
}

/// Reads `src` to completion into a freshly allocated `Vec`, erroring out as soon as the total
/// would exceed `max_output` — bounded memory regardless of how large the stream actually is,
/// without needing to trust any size the stream's own header claims.
#[cfg(feature = "zstd")]
fn read_capped(
    src: &mut impl std::io::Read,
    max_output: u64,
    codec: Codec,
) -> ForensicResult<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = src.read(&mut chunk).map_err(|e| {
            ForensicError::invalid_format(
                "journal data payload",
                format!("{} decompression failed: {e}", codec.name()),
            )
        })?;
        if n == 0 {
            break;
        }
        if buf.len() as u64 + n as u64 > max_output {
            return Err(too_big(codec, buf.len() as u64 + n as u64, max_output));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// A `Write` sink that errors instead of growing past `max_output` — how `xz`'s streaming decoder
/// is bounded, since the `.xz` container has no reliable upfront content-size field to check
/// before allocating (unlike zstd's frame header or lz4's explicit size prefix here).
#[cfg(feature = "xz")]
struct CappedWriter {
    buf: Vec<u8>,
    max: u64,
    codec: Codec,
}

#[cfg(feature = "xz")]
impl CappedWriter {
    fn new(max: u64, codec: Codec) -> Self {
        CappedWriter {
            buf: Vec::new(),
            max,
            codec,
        }
    }

    fn into_cap_error(self) -> ForensicError {
        too_big(self.codec, self.buf.len() as u64, self.max)
    }
}

#[cfg(feature = "xz")]
impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() as u64 + data.len() as u64 > self.max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "journal xz payload exceeds the decompression cap",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, feature = "lz4"))]
mod lz4_tests {
    use super::*;

    fn lz4_block_encode(data: &[u8]) -> Vec<u8> {
        let compressed = lz4_flex::block::compress(data);
        let mut out = Vec::with_capacity(8 + compressed.len());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn round_trips_a_normal_payload() {
        let payload = b"MESSAGE=hello from the journal";
        let encoded = lz4_block_encode(payload);
        let decoded = decompress(Codec::Lz4, &encoded, MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_a_declared_size_over_the_cap_without_allocating_it() {
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&(u64::MAX / 2).to_le_bytes()); // absurd claimed size
        hostile.extend_from_slice(&[0u8; 16]); // some compressed-looking bytes
        assert!(decompress(Codec::Lz4, &hostile, MAX_DECOMPRESSED_SIZE).is_err());
    }

    #[test]
    fn rejects_a_payload_too_short_for_the_size_prefix_instead_of_panicking() {
        assert!(decompress(Codec::Lz4, &[1, 2, 3], MAX_DECOMPRESSED_SIZE).is_err());
    }
}

#[cfg(all(test, feature = "zstd"))]
mod zstd_tests {
    use super::*;

    #[test]
    fn round_trips_a_normal_payload() {
        let payload = b"MESSAGE=hello from the journal, zstd edition";
        let encoded = zstd_encode_for_test(payload);
        let decoded = decompress(Codec::Zstd, &encoded, MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn a_stream_that_would_exceed_the_cap_is_rejected_not_fully_buffered() {
        // A real zstd-compressible "zip bomb" shape: highly repetitive input compresses to a
        // small frame but decompresses far past a small cap.
        let payload = vec![b'A'; 4 * 1024 * 1024];
        let encoded = zstd_encode_for_test(&payload);
        let err = decompress(Codec::Zstd, &encoded, 1024).unwrap_err();
        assert!(err.to_string().contains("exceeding"), "{err}");
    }

    /// `ruzstd` ships its own pure-Rust encoder, so tests round-trip through it directly rather
    /// than depending on an external `zstd` binary being present.
    fn zstd_encode_for_test(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }
}

#[cfg(all(test, feature = "xz"))]
mod xz_tests {
    use super::*;

    fn xz_encode_for_test(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lzma_rs::xz_compress(&mut &data[..], &mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_a_normal_payload() {
        let payload = b"MESSAGE=hello from the journal, xz edition";
        let encoded = xz_encode_for_test(payload);
        let decoded = decompress(Codec::Xz, &encoded, MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn a_stream_that_would_exceed_the_cap_is_rejected() {
        let payload = vec![b'A'; 4 * 1024 * 1024];
        let encoded = xz_encode_for_test(&payload);
        assert!(decompress(Codec::Xz, &encoded, 1024).is_err());
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn decodes_object_flags() {
        assert_eq!(codec_from_object_flags(0), None);
        assert_eq!(codec_from_object_flags(0x1), Some(Codec::Xz));
        assert_eq!(codec_from_object_flags(0x2), Some(Codec::Lz4));
        assert_eq!(codec_from_object_flags(0x4), Some(Codec::Zstd));
    }

    #[cfg(not(feature = "lz4"))]
    #[test]
    fn a_disabled_codec_is_a_clean_error_not_a_missing_symbol() {
        let err = decompress(Codec::Lz4, &[0; 16], MAX_DECOMPRESSED_SIZE).unwrap_err();
        assert!(err.to_string().contains("lz4"));
    }
}
