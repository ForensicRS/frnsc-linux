//! Byte-level layout for `utmp`/`wtmp`/`btmp`/`lastlog` fixed-size login records, and
//! [`UtmpParserFactory`], the [`ArtifactParserFactory`] that resolves
//! `LinuxUtmpFiles`/`LinuxWtmp`/`LinuxLastlogFile`/`UnixUtmpFile` through the run's artifact
//! catalog (no hardcoded paths) and emits `Artifact::Linux(LinuxArtifacts::Utmp)` records.
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
//! `lastlog` is a different, simpler fixed-size record (no `ut_type`/`ut_line` classification):
//! one fixed 292-byte slot per UID, indexed by the UID itself (the record's position in the
//! file) rather than carrying a user field. See [`LastlogRecord`].

use std::collections::BTreeMap;
use std::io::Read;

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

/// Fixed size of one `lastlog` slot: `ll_time` (4 bytes) + `ll_line` ([`UT_LINE_SIZE`]) +
/// `ll_host` ([`UT_HOST_SIZE`]). Unlike [`UtmpLayout`], `lastlog` has no narrow/wide split:
/// `ll_time` stays a 32-bit `time_t` on every layout this module has seen.
pub const LASTLOG_RECORD_SIZE: usize = 4 + UT_LINE_SIZE + UT_HOST_SIZE;

/// One slot of a `lastlog` file: the most recent login for one UID, or "never logged in" when
/// [`Self::never_logged_in`] is true.
///
/// `lastlog` carries no user field of its own — a slot's UID is its byte offset in the file
/// divided by [`LASTLOG_RECORD_SIZE`], supplied by the scanner as [`Self::uid`]. Files are
/// conventionally sparse up to the highest UID that ever logged in, so most slots in a real file
/// are all-zero and never logged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastlogRecord {
    pub uid: u32,
    pub ll_time: i32,
    /// Full [`UT_LINE_SIZE`] bytes as read, not NUL-trimmed.
    pub ll_line_raw: Vec<u8>,
    /// Full [`UT_HOST_SIZE`] bytes as read, not NUL-trimmed.
    pub ll_host_raw: Vec<u8>,
}

impl LastlogRecord {
    /// [`Self::ll_line_raw`], lossy-decoded up to its first NUL, for display only.
    pub fn line(&self) -> std::borrow::Cow<'_, str> {
        cstr_lossy(&self.ll_line_raw)
    }
    /// [`Self::ll_host_raw`], lossy-decoded up to its first NUL, for display only.
    pub fn host(&self) -> std::borrow::Cow<'_, str> {
        cstr_lossy(&self.ll_host_raw)
    }
    /// `ll_time == 0` is `lastlog(8)`'s own convention for "this UID has no recorded login" —
    /// not a login that happened at the Unix epoch. An all-zero slot (no line, no host) besides
    /// the zero timestamp is the ordinary shape of a never-populated sparse-file hole.
    pub fn never_logged_in(&self) -> bool {
        self.ll_time == 0
    }
}

/// Parses one [`LASTLOG_RECORD_SIZE`]-byte slot at UID `uid`. Bounds-checked throughout via
/// [`ByteReader`]; never panics on truncated or hostile input.
pub fn parse_lastlog_record(bytes: &[u8], uid: u32) -> ForensicResult<LastlogRecord> {
    if bytes.len() != LASTLOG_RECORD_SIZE {
        return Err(ForensicError::invalid_format(
            "lastlog record",
            format!(
                "expected exactly {LASTLOG_RECORD_SIZE} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    let mut reader = ByteReader::new(bytes);
    let ll_time = reader.read_i32_le()?;
    let ll_line_raw = reader.read_bytes(UT_LINE_SIZE)?.to_vec();
    let ll_host_raw = reader.read_bytes(UT_HOST_SIZE)?.to_vec();
    Ok(LastlogRecord {
        uid,
        ll_time,
        ll_line_raw,
        ll_host_raw,
    })
}

/// The result of scanning one `lastlog` file into fixed-size slots.
#[derive(Debug)]
pub struct LastlogScanResult {
    /// One item per whole slot found, in file (UID) order. A slot that fails to parse is one
    /// `Err` item; the scan still returns every other slot. [`LastlogRecord::never_logged_in`]
    /// slots are included here too — the caller decides whether to filter them.
    pub records: Vec<ForensicResult<LastlogRecord>>,
    /// Bytes left over after the last whole slot. A trailing partial record — never a panic,
    /// never a silent truncation; the caller turns a nonzero value into a `Finding`.
    pub trailing_partial_bytes: usize,
}

/// Parses every whole [`LASTLOG_RECORD_SIZE`]-byte slot `bytes` contains, in UID order.
pub fn scan_lastlog_records(bytes: &[u8]) -> LastlogScanResult {
    let whole = bytes.len() / LASTLOG_RECORD_SIZE;
    let trailing_partial_bytes = bytes.len() % LASTLOG_RECORD_SIZE;
    let records = (0..whole)
        .map(|i| {
            parse_lastlog_record(
                &bytes[i * LASTLOG_RECORD_SIZE..(i + 1) * LASTLOG_RECORD_SIZE],
                i as u32,
            )
        })
        .collect();
    LastlogScanResult {
        records,
        trailing_partial_bytes,
    }
}

/// Registration id of [`UtmpParserFactory`], in the `ParserRegistry`/`AccessRequirements`
/// namespace.
pub const PARSER_ID: &str = "linux.utmp";

/// The ForensicArtifacts definitions this parser reads, in the order it reads them.
///
/// The catalog is the source of truth for *where* these files live; there is deliberately no
/// local glob list here to drift from it. Sorted, so a run's output order is deterministic.
/// [`LASTLOG_DEFINITION`] uses the `lastlog` record layout; every other definition here uses the
/// shared utmp/wtmp/btmp layout ([`UtmpRecord`]).
pub const DEFINITIONS: &[&str] = &[
    "LinuxLastlogFile",
    "LinuxUtmpFiles",
    "LinuxWtmp",
    "UnixUtmpFile",
];

/// The one [`DEFINITIONS`] entry parsed with the `lastlog` layout instead of the utmp layout.
const LASTLOG_DEFINITION: &str = "LinuxLastlogFile";

/// Known `ut_type` values (`<utmp.h>`). `None` for a value outside this table — kept as its raw
/// number in the output either way, never guessed at.
fn utmp_type_name(ut_type: i32) -> Option<&'static str> {
    match ut_type {
        0 => Some("EMPTY"),
        1 => Some("RUN_LVL"),
        2 => Some("BOOT_TIME"),
        3 => Some("NEW_TIME"),
        4 => Some("OLD_TIME"),
        5 => Some("INIT_PROCESS"),
        6 => Some("LOGIN_PROCESS"),
        7 => Some("USER_PROCESS"),
        8 => Some("DEAD_PROCESS"),
        9 => Some("ACCOUNTING"),
        _ => None,
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex of `bytes`, with no allocation-failure/Result surface to drop.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

/// `ut_addr_v6` as the 16 raw address bytes (big-endian per word, the conventional byte order
/// for both the IPv4-in-first-word and full-IPv6 cases) — no address-family guess is made here,
/// matching [`UtmpRecord::addr_v6`]'s own docs.
fn hex_addr_v6(words: [u32; 4]) -> String {
    let mut bytes = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    hex_encode(&bytes)
}

/// Combines `tv_sec`/`tv_usec` exactly as read into one `@timestamp`, or `None` when the
/// combination overflows `i64` microseconds — no plausibility judgment beyond that; the raw
/// `linux.utmp.tv_sec`/`tv_usec` fields carry the values either way.
fn record_timestamp(tv_sec: i64, tv_usec: i64) -> Option<ForensicTimestamp> {
    let micros = tv_sec.checked_mul(1_000_000)?.checked_add(tv_usec)?;
    Some(ForensicTimestamp::from_unix_micros(micros))
}

/// Emits one [`ForensicData`] per `utmp`/`wtmp`/`btmp` record and one per populated `lastlog`
/// slot, from every location the run's [`ArtifactCatalog`] locates for [`DEFINITIONS`].
///
/// Stateless (`&self`): the open files, byte buffers and registered sources all live inside
/// [`Self::open`] and the [`ParserRun::Push`] closure it returns, never in `self`.
///
/// # Requires an artifact catalog
///
/// Files are located exclusively through [`ParseContext::resolve_artifact`] over
/// [`DEFINITIONS`]. A run with no catalog configured on its `TriageSources` cannot be served, and
/// [`Self::can_parse`] returns `false` rather than falling back to a hand-maintained glob list
/// that would silently diverge from the knowledge base.
///
/// # Failure granularity
///
/// One unreadable file is one `Err` item and the other files are still read. Within a file, a
/// trailing partial record — a length that is not an exact multiple of the record size — is one
/// more `Err` item after that file's whole records, never a panic and never a silent truncation;
/// the pipeline turns it into a `Finding` like any other parser error (see
/// [`forensic_rs::pipeline::processor`]). Every whole `utmp`/`wtmp`/`btmp` record is emitted,
/// including `EMPTY`-type slots: this parser does not filter by type. A `lastlog` slot with
/// [`LastlogRecord::never_logged_in`] is the one case that is filtered, because it is the
/// format's own "no data here" marker, not a login event.
pub struct UtmpParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for UtmpParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> =
            DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux utmp/wtmp/btmp/lastlog login records",
                "Emits one record per utmp/wtmp/btmp login-record slot and one per populated \
                 lastlog entry, from every location the artifact catalog resolves for \
                 LinuxUtmpFiles, LinuxWtmp, UnixUtmpFile and LinuxLastlogFile",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Linux(LinuxArtifacts::Utmp)])
            .with_requirements(requirements),
        }
    }
}

impl UtmpParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for UtmpParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    /// Both a filesystem to read and a catalog to locate the files with. Deliberately does not
    /// resolve the definitions here: that walks the evidence, and [`Self::open`] would only have
    /// to walk it again.
    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some() && ctx.sources().catalog().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().cloned().ok_or_else(|| {
            ForensicError::missing_data("FileSystem source required", CompactString::const_new(PARSER_ID))
        })?;
        if ctx.sources().catalog().is_none() {
            return Err(ForensicError::missing_data(
                "ArtifactCatalog required: this parser locates login-record files by artifact \
                 definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        // Problems first, so they are not buried after thousands of records.
        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        // Keyed by path so a file two definitions both name is read once, and so emission order
        // does not depend on the filesystem's walk order.
        let mut targets: BTreeMap<FPathBuf, &'static str> = BTreeMap::new();
        for definition in DEFINITIONS.iter().copied() {
            let resolution = match ctx.resolve_artifact(definition) {
                Ok(resolution) => resolution,
                Err(e) => {
                    head.push(Err(e));
                    continue;
                }
            };
            // A directory that could not be listed is not the same as "the file is absent": it
            // is a hole in the evidence and stays visible as its own item.
            head.extend(resolution.errors.into_iter().map(Err));
            head.extend(resolution.unresolved.into_iter().map(|u| {
                Err(ForensicError::other(
                    "catalog",
                    format!(
                        "{definition}: source {:?} was not searched: {}",
                        u.source, u.reason
                    ),
                ))
            }));
            for note in &resolution.notes {
                debug!("{PARSER_ID}: {definition}: {note}");
            }
            for file in resolution.files {
                if file.directory {
                    debug!("{PARSER_ID}: {definition}: ignoring directory {}", file.path);
                    continue;
                }
                if let Some(first) = targets.get(&file.path) {
                    debug!(
                        "{PARSER_ID}: {} matched both {first} and {definition}; attributed to {first}",
                        file.path
                    );
                    continue;
                }
                targets.insert(file.path, definition);
            }
        }

        // One registered source per real file — never one wildcard standing in for several.
        let targets: Vec<(FPathBuf, &'static str, SourceHandle)> = targets
            .into_iter()
            .map(|(path, definition)| {
                let source = ctx.register_source(SourceKey::Path(path.as_str().to_string()));
                (path, definition, source)
            })
            .collect();

        Ok(ParserRun::push(move |out| {
            for item in head {
                if out.emit(item).is_stop() {
                    return Ok(());
                }
            }
            for (path, definition, source) in targets {
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                let bytes = match read_file(fs.as_ref(), path.as_path()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        if out.emit(Err(e)).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                if definition == LASTLOG_DEFINITION {
                    let scan = scan_lastlog_records(&bytes);
                    for record in scan.records {
                        if cancellation.is_cancelled() {
                            return Ok(());
                        }
                        match record {
                            Ok(record) if record.never_logged_in() => continue,
                            Ok(record) => {
                                let data = lastlog_to_forensic_data(
                                    &host,
                                    definition,
                                    path.as_path(),
                                    &source,
                                    acquisition,
                                    &record,
                                );
                                if out.emit(Ok(data)).is_stop() {
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    if scan.trailing_partial_bytes != 0 {
                        let e = ForensicError::invalid_format(
                            "lastlog file",
                            format!(
                                "{} trailing byte(s) after the last whole {LASTLOG_RECORD_SIZE}-byte slot",
                                scan.trailing_partial_bytes
                            ),
                        )
                        .with_path(path.clone());
                        if out.emit(Err(e)).is_stop() {
                            return Ok(());
                        }
                    }
                } else {
                    let scan = scan_records(&bytes);
                    for record in scan.records {
                        if cancellation.is_cancelled() {
                            return Ok(());
                        }
                        match record {
                            Ok(record) => {
                                let data = utmp_to_forensic_data(
                                    &host,
                                    definition,
                                    path.as_path(),
                                    &source,
                                    acquisition,
                                    &record,
                                );
                                if out.emit(Ok(data)).is_stop() {
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    if scan.trailing_partial_bytes != 0 {
                        let e = ForensicError::invalid_format(
                            "utmp file",
                            format!(
                                "{} trailing byte(s) after the last whole record ({:?} layout)",
                                scan.trailing_partial_bytes, scan.layout
                            ),
                        )
                        .with_path(path.clone());
                        if out.emit(Err(e)).is_stop() {
                            return Ok(());
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

/// Reads the whole file at `path`. Every failure carries the path, so an `Err` item names the
/// file it came from.
fn read_file(fs: &dyn FileSystem, path: &FPath) -> ForensicResult<Vec<u8>> {
    let mut file = fs
        .open(path)
        .map_err(|e| e.with_path(FPathBuf::from(path.as_str())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| {
        ForensicError::io_error_with_source(e, format!("{PARSER_ID}: reading {path}"))
    })?;
    Ok(bytes)
}

fn utmp_to_forensic_data(
    host: &str,
    definition: &'static str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    record: &UtmpRecord,
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Utmp), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(
        "linux.utmp.layout",
        match record.layout {
            UtmpLayout::Narrow32 => "narrow32",
            UtmpLayout::Wide64 => "wide64",
        },
    );
    data.set("linux.utmp.type", record.ut_type as i64);
    if let Some(name) = utmp_type_name(record.ut_type) {
        data.set("linux.utmp.type_name", name);
    }
    data.set(PROCESS_PID, record.ut_pid as i64);
    data.set("linux.utmp.line", record.line().into_owned());
    data.set("linux.utmp.line_raw", hex_encode(&record.ut_line_raw));
    data.set("linux.utmp.id_raw", hex_encode(&record.ut_id));
    data.set(USER_NAME, record.user().into_owned());
    data.set("linux.utmp.user_raw", hex_encode(&record.ut_user_raw));
    data.set(SOURCE_ADDRESS, record.host().into_owned());
    data.set("linux.utmp.host_raw", hex_encode(&record.ut_host_raw));
    data.set(
        "linux.utmp.termination_status",
        record.termination_status as i64,
    );
    data.set("linux.utmp.exit_status", record.exit_status as i64);
    data.set("linux.utmp.session", record.session);
    data.set("linux.utmp.tv_sec", record.tv_sec);
    data.set("linux.utmp.tv_usec", record.tv_usec);
    data.set("linux.utmp.addr_v6", hex_addr_v6(record.addr_v6));
    if let Some(ts) = record_timestamp(record.tv_sec, record.tv_usec) {
        data.set(TIMESTAMP, ts);
    }
    data
}

fn lastlog_to_forensic_data(
    host: &str,
    definition: &'static str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    record: &LastlogRecord,
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Utmp), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set("linux.utmp.record_type", "lastlog");
    data.set("linux.utmp.lastlog.uid", record.uid as u64);
    data.set("linux.utmp.line", record.line().into_owned());
    data.set("linux.utmp.line_raw", hex_encode(&record.ll_line_raw));
    data.set(SOURCE_ADDRESS, record.host().into_owned());
    data.set("linux.utmp.host_raw", hex_encode(&record.ll_host_raw));
    data.set("linux.utmp.tv_sec", record.ll_time as i64);
    if let Some(ts) = record_timestamp(record.ll_time as i64, 0) {
        data.set(TIMESTAMP, ts);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one raw record of `layout`, with every field distinguishable so field-order bugs
    /// show up as test failures rather than coincidentally passing.
    pub(super) fn sample_record_bytes(layout: UtmpLayout, user: &[u8], host: &[u8]) -> Vec<u8> {
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

    fn sample_lastlog_bytes(ll_time: i32, line: &[u8], host: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(LASTLOG_RECORD_SIZE);
        buf.extend_from_slice(&ll_time.to_le_bytes());
        let mut line_buf = [0u8; UT_LINE_SIZE];
        line_buf[..line.len()].copy_from_slice(line);
        buf.extend_from_slice(&line_buf);
        let mut host_buf = [0u8; UT_HOST_SIZE];
        host_buf[..host.len()].copy_from_slice(host);
        buf.extend_from_slice(&host_buf);
        assert_eq!(buf.len(), LASTLOG_RECORD_SIZE);
        buf
    }

    #[test]
    fn parses_a_populated_lastlog_slot() {
        let bytes = sample_lastlog_bytes(1_700_000_000, b"tty1", b"remote.example");
        let record = parse_lastlog_record(&bytes, 1000).unwrap();
        assert_eq!(record.uid, 1000);
        assert_eq!(record.ll_time, 1_700_000_000);
        assert_eq!(record.line(), "tty1");
        assert_eq!(record.host(), "remote.example");
        assert!(!record.never_logged_in());
    }

    #[test]
    fn a_zero_time_lastlog_slot_is_never_logged_in() {
        let bytes = sample_lastlog_bytes(0, b"", b"");
        let record = parse_lastlog_record(&bytes, 7).unwrap();
        assert!(record.never_logged_in());
    }

    #[test]
    fn a_non_utf8_lastlog_host_is_kept_as_raw_bytes() {
        let invalid_utf8: &[u8] = &[0xFF, 0xFE];
        let bytes = sample_lastlog_bytes(1_700_000_000, b"tty1", invalid_utf8);
        let record = parse_lastlog_record(&bytes, 3).unwrap();
        assert_eq!(&record.ll_host_raw[..invalid_utf8.len()], invalid_utf8);
        assert!(record.host().contains('\u{FFFD}'));
    }

    #[test]
    fn rejects_a_lastlog_slot_of_the_wrong_size() {
        let mut bytes = sample_lastlog_bytes(1, b"", b"");
        bytes.pop();
        assert!(parse_lastlog_record(&bytes, 0).is_err());
    }

    #[test]
    fn scans_lastlog_slots_in_uid_order_and_reports_a_trailing_partial_slot() {
        let mut bytes = sample_lastlog_bytes(0, b"", b""); // uid 0: never logged in
        bytes.extend(sample_lastlog_bytes(1_700_000_001, b"tty1", b"host-a")); // uid 1
        bytes.extend(sample_lastlog_bytes(1_700_000_002, b"tty2", b"host-b")); // uid 2
        bytes.extend_from_slice(&[0xAA; 100]); // trailing partial slot
        let result = scan_lastlog_records(&bytes);
        assert_eq!(result.records.len(), 3);
        assert_eq!(result.trailing_partial_bytes, 100);
        let uids: Vec<u32> = result.records.iter().map(|r| r.as_ref().unwrap().uid).collect();
        assert_eq!(uids, vec![0, 1, 2]);
        assert!(result.records[0].as_ref().unwrap().never_logged_in());
        assert!(!result.records[1].as_ref().unwrap().never_logged_in());
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::tests::sample_record_bytes;
    use super::*;

    const UTMP_DEF: &str = "LinuxUtmpFiles";
    const WTMP_DEF: &str = "LinuxWtmp";
    const UNIX_UTMP_DEF: &str = "UnixUtmpFile";
    const LASTLOG_DEF: &str = "LinuxLastlogFile";

    /// The real definitions this factory declares, restated as an in-test catalog: the crate
    /// cannot depend on `frnsc-artifacts` (that would invert the dependency), and a pinned copy
    /// here also fails loudly if a definition's paths change.
    fn definition(name: &'static str, paths: &'static [Text]) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::File {
                    paths: Cow::Borrowed(paths),
                    separator: Separator::Slash,
                },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Linux]),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn catalog() -> Arc<dyn ArtifactCatalog> {
        let defs = vec![
            definition(
                LASTLOG_DEF,
                &[Cow::Borrowed("/var/log/lastlog")],
            ),
            definition(
                UTMP_DEF,
                &[
                    Cow::Borrowed("/var/log/btmp*"),
                    Cow::Borrowed("/var/log/wtmp*"),
                    Cow::Borrowed("/var/run/utmp*"),
                ],
            ),
            definition(WTMP_DEF, &[Cow::Borrowed("/var/log/wtmp*")]),
            definition(
                UNIX_UTMP_DEF,
                &[
                    Cow::Borrowed("/var/log/btmp"),
                    Cow::Borrowed("/var/log/wtmp"),
                    Cow::Borrowed("/var/run/utmp"),
                ],
            ),
        ];
        Arc::new(SliceCatalog::new(defs).unwrap())
    }

    fn sources(vfs: InMemoryVirtualFileSystem, with_catalog: bool) -> TriageSources {
        let mut builder = TriageSources::builder()
            .vfs(Arc::new(vfs))
            .acquisition(Acquisition::ImageRead);
        if with_catalog {
            builder = builder.catalog(catalog());
        }
        builder.build()
    }

    fn run(sources: &TriageSources) -> Vec<ForensicResult<ForensicData>> {
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(sources, &triage, &cancellation);
        let parser = UtmpParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = UtmpParserFactory::new();
        let declared: Vec<&str> = parser
            .descriptor()
            .requirements
            .iter()
            .filter_map(|r| match r {
                Requirement::Artifact(a) => Some(a.name.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(declared, DEFINITIONS.to_vec());
        assert!(!parser.descriptor().artifacts.is_empty());
        assert!(parser.descriptor().handles(&Artifact::Linux(LinuxArtifacts::Utmp)));
    }

    #[test]
    fn a_wtmp_file_is_read_once_despite_matching_three_definitions() {
        let bytes = sample_record_bytes(UtmpLayout::Narrow32, b"alice", b"");
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/wtmp", bytes);
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(
            items.iter().all(|i| i.is_ok()),
            "unexpected error items: {:?}",
            items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>()
        );
        assert_eq!(records.len(), 1, "one file matching several definitions is read once");
        assert_eq!(
            field(records[0], ARTIFACT_DEFINITION),
            Some(UTMP_DEF),
            "attributed to the first matching definition in DEFINITIONS order"
        );
    }

    #[test]
    fn emits_ecs_and_raw_fields_with_per_file_provenance() {
        let bytes = sample_record_bytes(UtmpLayout::Narrow32, b"alice", b"10.0.0.7");
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/wtmp", bytes);
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(record.artifact(), &Artifact::Linux(LinuxArtifacts::Utmp));
        assert_eq!(field(record, ARTIFACT_PATH), Some("var/log/wtmp"));
        assert_eq!(field(record, USER_NAME), Some("alice"));
        assert_eq!(field(record, SOURCE_ADDRESS), Some("10.0.0.7"));
        assert_eq!(record.field_as_u64(PROCESS_PID), Some(1234));
        assert_eq!(field(record, "linux.utmp.type_name"), Some("USER_PROCESS"));
        assert_eq!(field(record, "linux.utmp.layout"), Some("narrow32"));
        // The raw field is never dropped even though the display value already decoded cleanly.
        assert!(field(record, "linux.utmp.user_raw").unwrap().len() == UT_USER_SIZE * 2);
        assert!(record.field_as_date(TIMESTAMP).is_some());
    }

    #[test]
    fn a_non_utf8_user_is_never_dropped_from_the_record() {
        let invalid_utf8: &[u8] = &[0xFF, 0xFE, b'x', 0x80];
        let bytes = sample_record_bytes(UtmpLayout::Narrow32, invalid_utf8, b"");
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/wtmp", bytes);
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        let raw = field(records[0], "linux.utmp.user_raw").unwrap();
        assert_eq!(&raw[..invalid_utf8.len() * 2], "fffe7880");
        // The lossy display value still exists, replacement character and all.
        assert!(field(records[0], USER_NAME).unwrap().contains('\u{FFFD}'));
    }

    #[test]
    fn a_trailing_partial_record_is_one_err_item_and_whole_records_still_parse() {
        let mut bytes = sample_record_bytes(UtmpLayout::Narrow32, b"bob", b"");
        bytes.extend_from_slice(&[0xAA; 50]);
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/wtmp", bytes);
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        let errors: Vec<&ForensicError> = items.iter().filter_map(|i| i.as_ref().err()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].to_string().contains("50"));
    }

    #[test]
    fn lastlog_never_logged_in_slots_are_filtered_and_populated_ones_are_not() {
        let mut bytes = vec![0u8; LASTLOG_RECORD_SIZE]; // uid 0: never logged in
        let mut populated = vec![0u8; LASTLOG_RECORD_SIZE];
        populated[0..4].copy_from_slice(&1_700_000_000i32.to_le_bytes());
        populated[4..8].copy_from_slice(b"tty1");
        bytes.extend(populated); // uid 1
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/lastlog", bytes);
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(
            items.iter().all(|i| i.is_ok()),
            "unexpected error items: {:?}",
            items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>()
        );
        assert_eq!(records.len(), 1, "the never-logged-in uid 0 slot must not appear");
        assert_eq!(records[0].field_as_u64("linux.utmp.lastlog.uid"), Some(1));
        assert_eq!(field(records[0], ARTIFACT_DEFINITION), Some(LASTLOG_DEF));
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("var/log/wtmp", sample_record_bytes(UtmpLayout::Narrow32, b"x", b""));
        let sources = sources(vfs, false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = UtmpParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let items = run(&sources(InMemoryVirtualFileSystem::new(), true));
        assert!(items.is_empty());
    }
}
