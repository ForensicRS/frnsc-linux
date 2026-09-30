//! Byte-level layout for `utmp`/`wtmp`/`btmp`/`lastlog` fixed-size login records.
//!
//! This module only turns raw bytes into [`UtmpRecord`] values; it deliberately does not
//! implement `ArtifactParserFactory` yet. Wiring this into a factory that resolves
//! `LinuxUtmpFiles`/`LinuxWtmp`/`LinuxLastlogFile`/`UnixUtmpFile` through the run's artifact
//! catalog (no hardcoded paths) and emits `Artifact::Linux(LinuxArtifacts::Utmp)` records needs
//! two things that do not exist in `forensic-rs` yet: the `LinuxArtifacts::Utmp` variant and a
//! handful of `dictionary` ECS constants (`PROCESS_PID`, `HOST_HOSTNAME`, `SOURCE_ADDRESS`, ...).
//! That upstream, additive change is out of scope for this crate — see the workspace
//! `FINDINGS.md` entry for `frnsc-linux` for the tracking issue.
//!
//! # Layout
//!
//! Every record is a fixed size, in one of two on-disk layouts that differ only in the width of
//! `session`/`tv_sec`/`tv_usec`. Reference:
//! <https://github.com/libyal/dtformats/blob/main/documentation/Utmp%20login%20records%20format.asciidoc>
//!
//! **Narrow (32-bit-compatible), [`RECORD_SIZE_32`] = 384 bytes** — used by both 32-bit Linux
//! and by 64-bit x86/x86_64 builds, which keep `session`/`tv_sec`/`tv_usec` at 4 bytes each so
//! the on-disk format stays byte-identical between 32- and 64-bit readers (glibc's
//! `__WORDSIZE_TIME64_COMPAT32`). This is the layout the overwhelming majority of real evidence
//! uses.
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0   | 4   | `ut_type` |
//! | 4   | 4   | `ut_pid` |
//! | 8   | 32  | `ut_line` |
//! | 40  | 4   | `ut_id` |
//! | 44  | 32  | `ut_user` |
//! | 76  | 256 | `ut_host` |
//! | 332 | 2   | termination status |
//! | 334 | 2   | exit status |
//! | 336 | 4   | `ut_session` |
//! | 340 | 4   | `ut_tv.tv_sec` |
//! | 344 | 4   | `ut_tv.tv_usec` |
//! | 348 | 16  | `ut_addr_v6` |
//! | 364 | 20  | reserved |
//!
//! **Wide (genuine 64-bit), [`RECORD_SIZE_64`] = 400 bytes** — architectures that do not keep
//! the 32-bit-compatible layout widen `session`/`tv_sec`/`tv_usec` to 8 bytes each; everything
//! before offset 336 is unchanged, and the reserved tail grows to 24 bytes.
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 336 | 8  | `ut_session` |
//! | 344 | 8  | `ut_tv.tv_sec` |
//! | 352 | 8  | `ut_tv.tv_usec` |
//! | 360 | 16 | `ut_addr_v6` |
//! | 376 | 24 | reserved |
//!
//! `lastlog` is a different, simpler fixed-size record (no `ut_type`/`ut_line` classification);
//! it is not covered by this module yet.

use forensic_rs::prelude::*;

/// Record size under the narrow (32-bit-compatible) on-disk layout. See the module docs.
pub const RECORD_SIZE_32: usize = 384;
/// Record size under the wide (genuine 64-bit) on-disk layout. See the module docs.
pub const RECORD_SIZE_64: usize = 400;

const UT_LINE_SIZE: usize = 32;
const UT_USER_SIZE: usize = 32;
const UT_HOST_SIZE: usize = 256;

/// Which on-disk layout a record (or a whole file of them) uses. See the module docs for the
/// exact byte offsets of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtmpLayout {
    /// `session`/`tv_sec`/`tv_usec` as 4-byte fields. [`RECORD_SIZE_32`] bytes per record.
    Narrow32,
    /// `session`/`tv_sec`/`tv_usec` as 8-byte fields. [`RECORD_SIZE_64`] bytes per record.
    Wide64,
}

impl UtmpLayout {
    pub fn record_size(self) -> usize {
        match self {
            UtmpLayout::Narrow32 => RECORD_SIZE_32,
            UtmpLayout::Wide64 => RECORD_SIZE_64,
        }
    }
}

/// One parsed `utmp`/`wtmp`/`btmp` record.
///
/// `ut_line_raw`, `ut_user_raw` and `ut_host_raw` keep the exact fixed-width bytes as read — a
/// non-UTF-8 value (a corrupted or deliberately hostile field) is never dropped and never
/// silently replaced. [`Self::user`], [`Self::host`] and [`Self::line`] lossy-decode the
/// NUL-terminated prefix for display only; they are not a substitute for the raw fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtmpRecord {
    pub layout: UtmpLayout,
    pub ut_type: i32,
    pub ut_pid: i32,
    /// Full `UT_LINESIZE` (32) bytes as read, not NUL-trimmed.
    pub ut_line_raw: Vec<u8>,
    /// 4-byte inittab identifier. Not conventionally NUL-terminated text, so kept verbatim with
    /// no trimming.
    pub ut_id: [u8; 4],
    /// Full `UT_NAMESIZE` (32) bytes as read, not NUL-trimmed.
    pub ut_user_raw: Vec<u8>,
    /// Full `UT_HOSTSIZE` (256) bytes as read, not NUL-trimmed.
    pub ut_host_raw: Vec<u8>,
    pub termination_status: i16,
    pub exit_status: i16,
    /// Widened to `i64` regardless of the source layout, so callers never have to branch on
    /// [`UtmpLayout`] to read it.
    pub session: i64,
    pub tv_sec: i64,
    pub tv_usec: i64,
    /// `ut_addr_v6`: an IPv4 address in the first element with the rest zero, or a full IPv6
    /// address across all four, per glibc convention. Kept as the raw four 32-bit words — no
    /// address-family guess is made here.
    pub addr_v6: [u32; 4],
}

impl UtmpRecord {
    /// [`Self::ut_line_raw`], lossy-decoded up to its first NUL, for display only.
    pub fn line(&self) -> std::borrow::Cow<'_, str> {
        cstr_lossy(&self.ut_line_raw)
    }
    /// [`Self::ut_user_raw`], lossy-decoded up to its first NUL, for display only.
    pub fn user(&self) -> std::borrow::Cow<'_, str> {
        cstr_lossy(&self.ut_user_raw)
    }
    /// [`Self::ut_host_raw`], lossy-decoded up to its first NUL, for display only.
    pub fn host(&self) -> std::borrow::Cow<'_, str> {
        cstr_lossy(&self.ut_host_raw)
    }
}

fn cstr_lossy(buf: &[u8]) -> std::borrow::Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
}

/// Parses exactly one record of `bytes`, which must be exactly `layout.record_size()` long.
/// Bounds-checked throughout via [`ByteReader`]; never panics on truncated or hostile input.
pub fn parse_record(bytes: &[u8], layout: UtmpLayout) -> ForensicResult<UtmpRecord> {
    let expected = layout.record_size();
    if bytes.len() != expected {
        return Err(ForensicError::invalid_format(
            "utmp record",
            format!(
                "expected exactly {expected} bytes for {layout:?}, got {}",
                bytes.len()
            ),
        ));
    }
    let mut reader = ByteReader::new(bytes);
    let ut_type = reader.read_i32_le()?;
    let ut_pid = reader.read_i32_le()?;
    let ut_line_raw = reader.read_bytes(UT_LINE_SIZE)?.to_vec();
    let ut_id = reader.read_fixed::<4>()?;
    let ut_user_raw = reader.read_bytes(UT_USER_SIZE)?.to_vec();
    let ut_host_raw = reader.read_bytes(UT_HOST_SIZE)?.to_vec();
    let termination_status = reader.read_i16_le()?;
    let exit_status = reader.read_i16_le()?;
    let (session, tv_sec, tv_usec) = match layout {
        UtmpLayout::Narrow32 => (
            reader.read_i32_le()? as i64,
            reader.read_i32_le()? as i64,
            reader.read_i32_le()? as i64,
        ),
        UtmpLayout::Wide64 => (
            reader.read_i64_le()?,
            reader.read_i64_le()?,
            reader.read_i64_le()?,
        ),
    };
    let mut addr_v6 = [0u32; 4];
    for slot in addr_v6.iter_mut() {
        *slot = reader.read_u32_le()?;
    }
    // The reserved tail carries nothing defined; it is deliberately not read.
    Ok(UtmpRecord {
        layout,
        ut_type,
        ut_pid,
        ut_line_raw,
        ut_id,
        ut_user_raw,
        ut_host_raw,
        termination_status,
        exit_status,
        session,
        tv_sec,
        tv_usec,
        addr_v6,
    })
}

/// Which [`UtmpLayout`] a file of `len` bytes most likely uses.
///
/// [`UtmpLayout::Wide64`] is returned only when `len` is an exact, *unambiguous* multiple of
/// [`RECORD_SIZE_64`] (and not also a multiple of [`RECORD_SIZE_32`]). Every other case —
/// including a clean multiple of both, and a length that is a multiple of neither — defaults to
/// [`UtmpLayout::Narrow32`], since that is what the overwhelming majority of real (x86/x86_64)
/// evidence uses.
///
/// This is a real, documented limitation, not a corner case worth hiding: a genuinely
/// [`UtmpLayout::Wide64`] file with a truncated tail (so its length is no longer an exact
/// multiple of 400) is misdetected as [`UtmpLayout::Narrow32`], and every field offset from
/// there on is wrong. Byte length alone cannot distinguish "wide layout, truncated" from
/// "narrow layout, truncated" when both remainders are plausible trailing-partial sizes — that
/// needs either external knowledge of the source architecture or a content-based sanity check
/// (plausible `ut_type`/timestamp ranges), neither of which this module has. See
/// `a_wide64_file_truncated_mid_record_is_misdetected_as_narrow32` below, which pins the
/// behaviour so a future fix is a deliberate change, not a silent one.
pub fn detect_layout(len: usize) -> UtmpLayout {
    let rem32 = len % RECORD_SIZE_32;
    let rem64 = len % RECORD_SIZE_64;
    if rem64 == 0 && rem32 != 0 {
        UtmpLayout::Wide64
    } else {
        UtmpLayout::Narrow32
    }
}

/// The result of scanning one utmp-family file into fixed-size records.
#[derive(Debug)]
pub struct ScanResult {
    pub layout: UtmpLayout,
    /// One item per whole record found, in file order. A record that fails to parse is one
    /// `Err` item; the scan still returns every other record.
    pub records: Vec<ForensicResult<UtmpRecord>>,
    /// Bytes left over after the last whole record, because `bytes.len()` was not an exact
    /// multiple of the detected record size. A trailing partial record — never a panic, never a
    /// silent truncation; the caller turns a nonzero value into a `Finding`.
    pub trailing_partial_bytes: usize,
}

/// Detects the layout of `bytes` and parses every whole record it contains.
pub fn scan_records(bytes: &[u8]) -> ScanResult {
    let layout = detect_layout(bytes.len());
    let size = layout.record_size();
    let whole = bytes.len() / size;
    let trailing_partial_bytes = bytes.len() % size;
    let records = (0..whole)
        .map(|i| parse_record(&bytes[i * size..(i + 1) * size], layout))
        .collect();
    ScanResult {
        layout,
        records,
        trailing_partial_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one raw record of `layout`, with every field distinguishable so field-order bugs
    /// show up as test failures rather than coincidentally passing.
    fn sample_record_bytes(layout: UtmpLayout, user: &[u8], host: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(layout.record_size());
        buf.extend_from_slice(&7i32.to_le_bytes()); // ut_type = USER_PROCESS
        buf.extend_from_slice(&1234i32.to_le_bytes()); // ut_pid
        let mut line = [0u8; UT_LINE_SIZE];
        line[..4].copy_from_slice(b"tty1");
        buf.extend_from_slice(&line);
        buf.extend_from_slice(b"ttyA"); // ut_id, 4 bytes, no NUL convention
        let mut user_buf = [0u8; UT_USER_SIZE];
        user_buf[..user.len()].copy_from_slice(user);
        buf.extend_from_slice(&user_buf);
        let mut host_buf = [0u8; UT_HOST_SIZE];
        host_buf[..host.len()].copy_from_slice(host);
        buf.extend_from_slice(&host_buf);
        buf.extend_from_slice(&0i16.to_le_bytes()); // termination_status
        buf.extend_from_slice(&0i16.to_le_bytes()); // exit_status
        match layout {
            UtmpLayout::Narrow32 => {
                buf.extend_from_slice(&42i32.to_le_bytes()); // session
                buf.extend_from_slice(&1_700_000_000i32.to_le_bytes()); // tv_sec
                buf.extend_from_slice(&500_000i32.to_le_bytes()); // tv_usec
            }
            UtmpLayout::Wide64 => {
                buf.extend_from_slice(&42i64.to_le_bytes());
                buf.extend_from_slice(&1_700_000_000i64.to_le_bytes());
                buf.extend_from_slice(&500_000i64.to_le_bytes());
            }
        }
        // ut_addr_v6: four u32 words. IPv4 127.0.0.1 in the first word, rest zero.
        buf.extend_from_slice(&u32::from_be_bytes([127, 0, 0, 1]).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        let reserved = layout.record_size() - buf.len();
        buf.extend(std::iter::repeat_n(0u8, reserved));
        assert_eq!(buf.len(), layout.record_size());
        buf
    }

    #[test]
    fn parses_the_64_bit_wide_layout() {
        let bytes = sample_record_bytes(UtmpLayout::Wide64, b"root", b"");
        let record = parse_record(&bytes, UtmpLayout::Wide64).unwrap();
        assert_eq!(record.layout, UtmpLayout::Wide64);
        assert_eq!(record.ut_type, 7);
        assert_eq!(record.ut_pid, 1234);
        assert_eq!(record.line(), "tty1");
        assert_eq!(&record.ut_id, b"ttyA");
        assert_eq!(record.user(), "root");
        assert_eq!(record.host(), "");
        assert_eq!(record.session, 42);
        assert_eq!(record.tv_sec, 1_700_000_000);
        assert_eq!(record.tv_usec, 500_000);
        assert_eq!(record.addr_v6, [u32::from_be_bytes([127, 0, 0, 1]), 0, 0, 0]);
    }

    #[test]
    fn parses_the_32_bit_narrow_layout() {
        let bytes = sample_record_bytes(UtmpLayout::Narrow32, b"alice", b"remote.example");
        let record = parse_record(&bytes, UtmpLayout::Narrow32).unwrap();
        assert_eq!(record.layout, UtmpLayout::Narrow32);
        assert_eq!(record.user(), "alice");
        assert_eq!(record.host(), "remote.example");
        assert_eq!(record.session, 42);
        assert_eq!(record.tv_sec, 1_700_000_000);
    }

    #[test]
    fn a_non_utf8_user_is_kept_as_raw_bytes_and_only_lossy_decoded_for_display() {
        let invalid_utf8: &[u8] = &[0xFF, 0xFE, b'x', 0x80];
        let bytes = sample_record_bytes(UtmpLayout::Narrow32, invalid_utf8, b"host");
        let record = parse_record(&bytes, UtmpLayout::Narrow32).unwrap();
        // Raw bytes are exactly what was read: never dropped, never replaced.
        assert_eq!(&record.ut_user_raw[..invalid_utf8.len()], invalid_utf8);
        assert!(std::str::from_utf8(&record.ut_user_raw).is_err());
        // Display form never panics and never silently claims valid UTF-8.
        let displayed = record.user();
        assert!(displayed.contains('\u{FFFD}'), "{displayed:?}");
    }

    #[test]
    fn a_non_utf8_host_is_kept_as_raw_bytes_and_only_lossy_decoded_for_display() {
        let invalid_utf8: &[u8] = &[b'h', 0xC0, 0xAF];
        let bytes = sample_record_bytes(UtmpLayout::Narrow32, b"user", invalid_utf8);
        let record = parse_record(&bytes, UtmpLayout::Narrow32).unwrap();
        assert_eq!(&record.ut_host_raw[..invalid_utf8.len()], invalid_utf8);
        assert!(std::str::from_utf8(&record.ut_host_raw).is_err());
        assert!(record.host().contains('\u{FFFD}'));
    }

    #[test]
    fn rejects_a_record_of_the_wrong_size_instead_of_misreading_it() {
        let mut bytes = sample_record_bytes(UtmpLayout::Narrow32, b"x", b"");
        bytes.pop();
        assert!(parse_record(&bytes, UtmpLayout::Narrow32).is_err());
        assert!(parse_record(&bytes, UtmpLayout::Wide64).is_err());
    }

    #[test]
    fn detects_the_narrow_layout_from_an_exact_multiple() {
        assert_eq!(detect_layout(RECORD_SIZE_32 * 3), UtmpLayout::Narrow32);
    }

    #[test]
    fn detects_the_wide_layout_from_an_exact_multiple() {
        assert_eq!(detect_layout(RECORD_SIZE_64 * 2), UtmpLayout::Wide64);
    }

    #[test]
    fn an_empty_file_is_not_an_error() {
        let result = scan_records(&[]);
        assert!(result.records.is_empty());
        assert_eq!(result.trailing_partial_bytes, 0);
    }

    #[test]
    fn a_trailing_partial_record_is_reported_not_silently_dropped_and_not_a_panic() {
        let mut bytes = sample_record_bytes(UtmpLayout::Narrow32, b"bob", b"");
        bytes.extend_from_slice(&[0xAA; 50]); // a second, truncated record
        let result = scan_records(&bytes);
        assert_eq!(result.layout, UtmpLayout::Narrow32);
        assert_eq!(result.records.len(), 1, "only the one whole record parses");
        assert!(result.records[0].is_ok());
        assert_eq!(result.trailing_partial_bytes, 50);
    }

    #[test]
    fn a_wide64_file_truncated_mid_record_is_misdetected_as_narrow32() {
        // REGRESSION PIN, NOT AN ENDORSEMENT — see `detect_layout`'s docs. Byte length alone
        // cannot tell "wide64, truncated" apart from "narrow32, truncated" in general; this
        // pins the documented default so a future fix (e.g. a content-based sanity check) is a
        // deliberate, visible change instead of a silent behaviour drift.
        let mut bytes = sample_record_bytes(UtmpLayout::Wide64, b"carol", b"");
        bytes.extend_from_slice(&[0xAA; 50]); // truncated second wide64 record
        assert_eq!(bytes.len(), RECORD_SIZE_64 + 50);
        let result = scan_records(&bytes);
        assert_eq!(
            result.layout,
            UtmpLayout::Narrow32,
            "PINNED CURRENT BEHAVIOUR: length alone defaults to Narrow32 here"
        );
        // Misdetection means the first RECORD_SIZE_32 bytes of a real wide64 record are
        // misread as a whole narrow32 record — garbage fields, not a crash and not a dropped
        // record. This is the cost of the documented default, made visible rather than hidden.
        // `ut_user` sits before the layouts diverge (offset 44, common to both), so it still
        // reads correctly; `tv_sec` sits inside the widened `session`/`tv` region and comes out
        // wrong instead.
        assert_eq!(result.records.len(), 1);
        let record = result.records[0].as_ref().unwrap();
        assert_eq!(record.user(), "carol", "fields before offset 336 are unaffected");
        assert_ne!(
            record.tv_sec, 1_700_000_000,
            "fields at/after offset 336 are misread once the layout is wrong"
        );
    }

    #[test]
    fn multiple_whole_records_all_parse_and_stay_in_file_order() {
        let mut bytes = sample_record_bytes(UtmpLayout::Narrow32, b"first", b"");
        bytes.extend(sample_record_bytes(UtmpLayout::Narrow32, b"second", b""));
        bytes.extend(sample_record_bytes(UtmpLayout::Narrow32, b"third", b""));
        let result = scan_records(&bytes);
        assert_eq!(result.trailing_partial_bytes, 0);
        let users: Vec<String> = result
            .records
            .iter()
            .map(|r| r.as_ref().unwrap().user().to_string())
            .collect();
        assert_eq!(users, vec!["first", "second", "third"]);
    }
}
