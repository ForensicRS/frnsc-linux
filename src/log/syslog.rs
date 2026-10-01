//! BSD syslog (RFC3164) and structured syslog (RFC5424) parsing, and [`SyslogParserFactory`],
//! the [`ArtifactParserFactory`] that resolves `LinuxAuthLogs`/`LinuxSysLogFiles`/
//! `LinuxMessagesLogFiles`/`LinuxKernelLogFiles`/`LinuxDaemonLogFiles`/`LinuxCronLogs` through the
//! run's artifact catalog (no hardcoded paths) and emits `Artifact::Linux(LinuxArtifacts::Log(..))`
//! records, one per line, on top of the shared [`super::text`] scaffold.
//!
//! # Formats
//!
//! Both formats optionally start with a `<PRI>` prefix (`PRI = facility * 8 + severity`); classic
//! local files written directly by `syslogd`/`rsyslog` usually omit it (see `auth.log` below),
//! while lines relayed from the network or written by `rsyslog`'s own templates often keep it.
//!
//! **RFC3164** (`Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`) carries **no year** — see
//! [`YearTracker`] for how one is derived without ever inventing it. `TAG` may have no `[PID]`
//! (`kernel:`), or no colon at all (rare; treated as tag-less, the whole remainder becomes the
//! message rather than erroring the line).
//!
//! **RFC5424** (`1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`) has an explicit
//! ISO-8601 timestamp with a UTC offset, and any header field may be the nil value `-`.
//! STRUCTURED-DATA is `-` or one or more bracketed `[SD-ID key="value" ...]` elements
//! concatenated with no space between them; values may contain further `[`/`]` only inside
//! quotes, which this module's bracket walk respects.

use forensic_rs::prelude::*;

use super::text::{hex_encode, scan_lines, systematic_parse_failure};

/// Registration id of [`SyslogParserFactory`].
pub const PARSER_ID: &str = "linux.syslog";

/// The ForensicArtifacts definitions this parser reads, sorted for deterministic requirement
/// order. The catalog is the source of truth for *where* these files live.
pub const DEFINITIONS: &[&str] = &[
    "LinuxAuthLogs",
    "LinuxCronLogs",
    "LinuxDaemonLogFiles",
    "LinuxKernelLogFiles",
    "LinuxMessagesLogFiles",
    "LinuxSysLogFiles",
];

/// Maps a [`DEFINITIONS`] entry to the `Linux(Log(..))` sub-artifact tag. `"unknown"` never
/// happens in practice — every definition this factory declares has an arm — but a parser must
/// not panic on its own bookkeeping going stale either.
fn log_kind(definition: &str) -> &'static str {
    match definition {
        "LinuxAuthLogs" => "auth",
        "LinuxCronLogs" => "cron",
        "LinuxDaemonLogFiles" => "daemon",
        "LinuxKernelLogFiles" => "kernel",
        "LinuxMessagesLogFiles" => "messages",
        "LinuxSysLogFiles" => "syslog",
        _ => "unknown",
    }
}

/// Which syslog variant a line was parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFormat {
    Rfc3164,
    Rfc5424,
}

impl SyslogFormat {
    fn as_str(self) -> &'static str {
        match self {
            SyslogFormat::Rfc3164 => "rfc3164",
            SyslogFormat::Rfc5424 => "rfc5424",
        }
    }
}

/// One parsed syslog line, before RFC3164 year derivation (see [`YearTracker`]): that step needs
/// file-level context this module does not have, so [`Self::rfc3164_month_day`] carries the raw
/// calendar fields for the caller to resolve into a timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSyslogLine {
    pub format: SyslogFormat,
    /// `<PRI>`, if the line had one. `0..=191`; `facility = pri / 8`, `severity = pri % 8`.
    pub priority: Option<u16>,
    /// `None` for RFC5424's nil value (`-`), not just "absent".
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    /// Kept as read: RFC5424 PROCID is not required to be numeric.
    pub proc_id: Option<String>,
    /// RFC5424 only.
    pub msg_id: Option<String>,
    /// RFC5424 only: the raw `[SD-ID ...]` text (possibly several concatenated elements), or
    /// `None` for nil (`-`) or RFC3164 (which has no structured data at all).
    pub structured_data: Option<String>,
    pub message: String,
    /// Fully resolved for RFC5424 (the timestamp is self-contained). `None` for RFC3164 — see
    /// [`Self::rfc3164_month_day`].
    pub timestamp: Option<ForensicTimestamp>,
    /// `(month, day, hour, minute, second)`, present only for RFC3164, which carries no year.
    pub rfc3164_month_day: Option<(u8, u8, u8, u8, u8)>,
}

fn ascii_digit(b: u8) -> Option<u8> {
    if b.is_ascii_digit() {
        Some(b - b'0')
    } else {
        None
    }
}

fn two_digit(bytes: &[u8]) -> Option<u8> {
    ascii_digit(*bytes.first()?)?
        .checked_mul(10)?
        .checked_add(ascii_digit(*bytes.get(1)?)?)
}

const MONTH_ABBREVS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

fn month_index(abbrev: &[u8]) -> Option<u8> {
    MONTH_ABBREVS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(abbrev))
        .map(|i| (i + 1) as u8)
}

/// Parses the fixed 16-byte `"Mmm dd hh:mm:ss "` prefix (month abbreviation, space-or-digit-padded
/// day, space, `hh:mm:ss`, trailing space) from the *start* of `text`. Works over bytes, never
/// `str` slicing, so a non-ASCII byte anywhere in this region fails the match instead of
/// panicking on a char-boundary. Returns the calendar fields and how many bytes were consumed
/// (always 16 on success, including the trailing separator space).
fn parse_rfc3164_timestamp(text: &str) -> Option<(u8, u8, u8, u8, u8, usize)> {
    let bytes = text.as_bytes();
    if bytes.len() < 16 {
        return None;
    }
    let month = month_index(bytes.get(0..3)?)?;
    if bytes.get(3)? != &b' ' {
        return None;
    }
    let day_bytes = bytes.get(4..6)?;
    let day = if day_bytes[0] == b' ' {
        ascii_digit(day_bytes[1])?
    } else {
        ascii_digit(day_bytes[0])?
            .checked_mul(10)?
            .checked_add(ascii_digit(day_bytes[1])?)?
    };
    if bytes.get(6)? != &b' ' {
        return None;
    }
    let hour = two_digit(bytes.get(7..9)?)?;
    if bytes.get(9)? != &b':' {
        return None;
    }
    let minute = two_digit(bytes.get(10..12)?)?;
    if bytes.get(12)? != &b':' {
        return None;
    }
    let second = two_digit(bytes.get(13..15)?)?;
    if bytes.get(15)? != &b' ' {
        return None;
    }
    if day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((month, day, hour, minute, second, 16))
}

/// Splits `s` (the text after `TIMESTAMP HOSTNAME `) into `(tag, pid, message)`. `TAG[PID]: MSG`
/// and `TAG: MSG` are both standard; a line with neither a `[` nor a `:` before anything else is
/// tolerated as tag-less rather than rejected, since the tag is a convention, not something
/// RFC3164 strictly mandates.
fn split_tag(s: &str) -> (Option<&str>, Option<&str>, &str) {
    let bracket = s.find('[');
    let colon = s.find(':');
    let use_bracket = match (bracket, colon) {
        (Some(b), Some(c)) => b < c,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if use_bracket {
        if let Some(b) = bracket {
            if let Some((tag, pid, msg)) = split_bracket_tag(s, b) {
                return (Some(tag), Some(pid), msg);
            }
        }
    }
    match colon {
        Some(c) => {
            let tag = &s[..c];
            let after = s.get(c + 1..).unwrap_or("");
            let msg = after.strip_prefix(' ').unwrap_or(after);
            (Some(tag), None, msg)
        }
        None => (None, None, s),
    }
}

fn split_bracket_tag(s: &str, bracket: usize) -> Option<(&str, &str, &str)> {
    let after_bracket = s.get(bracket + 1..)?;
    let close_rel = after_bracket.find(']')?;
    let tag = &s[..bracket];
    let pid = &after_bracket[..close_rel];
    let after_close = after_bracket.get(close_rel + 1..)?;
    let after_colon = after_close.strip_prefix(':')?;
    let msg = after_colon.strip_prefix(' ').unwrap_or(after_colon);
    Some((tag, pid, msg))
}

/// Splits off the next space-delimited token. `None` when `s` is already empty — a required
/// RFC5424 header field is missing, not merely empty.
fn take_token(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    match s.find(' ') {
        Some(i) => Some((s.get(0..i)?, s.get(i + 1..)?)),
        None => Some((s, "")),
    }
}

/// Parses RFC5424 STRUCTURED-DATA (`-`, or one or more concatenated `[SD-ID ...]` elements) off
/// the front of `s`, returning the raw SD text (if any) and whatever follows as MSG. A `"` inside
/// an element toggles a quoted span during which `[`/`]` do not affect bracket depth, per the
/// spec's escaping rules; `\"` inside a quoted span is a literal quote, not a close. Tolerates
/// malformed input (no leading `-`/`[`, or an unterminated `[`) by treating the whole remainder
/// as MSG with no structured data, rather than erroring the line over one field.
fn parse_structured_data(s: &str) -> (Option<String>, &str) {
    if let Some(rest) = s.strip_prefix('-') {
        let msg = rest.strip_prefix(' ').unwrap_or(rest);
        return (None, msg);
    }
    if !s.starts_with('[') {
        return (None, s);
    }
    let mut depth: u32 = 0;
    let mut in_quotes = false;
    let mut escape = false;
    let mut chars = s.char_indices().peekable();
    let mut end = None;
    while let Some((_, c)) = chars.next() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escape = true,
            '"' => in_quotes = !in_quotes,
            '[' if !in_quotes => depth += 1,
            ']' if !in_quotes => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    match chars.peek() {
                        Some(&(_, '[')) => continue,
                        Some(&(j, _)) => {
                            end = Some(j);
                            break;
                        }
                        None => {
                            end = Some(s.len());
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    match end {
        Some(e) => {
            let sd = s.get(..e).unwrap_or(s);
            let rest = s.get(e..).unwrap_or("");
            let msg = rest.strip_prefix(' ').unwrap_or(rest);
            (Some(sd.to_string()), msg)
        }
        None => (None, s),
    }
}

/// Parses an RFC3339-ish timestamp (`YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)`), the format
/// RFC5424 requires. Works entirely through `str::get` (never raw indexing), so malformed or
/// non-ASCII input returns `None` rather than panicking on a char boundary.
fn parse_iso8601(s: &str) -> Option<ForensicTimestamp> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    if bytes.get(4)? != &b'-'
        || bytes.get(7)? != &b'-'
        || !matches!(bytes.get(10)?, b'T' | b't')
        || bytes.get(13)? != &b':'
        || bytes.get(16)? != &b':'
    {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u8 = s.get(5..7)?.parse().ok()?;
    let day: u8 = s.get(8..10)?.parse().ok()?;
    let hour: u8 = s.get(11..13)?.parse().ok()?;
    let minute: u8 = s.get(14..16)?.parse().ok()?;
    let second: u8 = s.get(17..19)?.parse().ok()?;
    let mut idx = 19usize;
    let mut nanos: u32 = 0;
    if bytes.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while bytes.get(idx).is_some_and(|b| b.is_ascii_digit()) {
            idx += 1;
        }
        let frac = s.get(start..idx)?;
        if !frac.is_empty() {
            let mut digits = [b'0'; 9];
            let take = frac.len().min(9);
            digits[..take].copy_from_slice(&frac.as_bytes()[..take]);
            nanos = std::str::from_utf8(&digits).ok()?.parse().ok()?;
        }
    }
    let offset_minutes: Option<i16> = match bytes.get(idx) {
        Some(b'Z') | Some(b'z') => Some(0),
        Some(&sign_byte @ (b'+' | b'-')) => {
            let sign: i16 = if sign_byte == b'-' { -1 } else { 1 };
            let off_str = s.get(idx + 1..)?;
            if off_str.len() < 5 || off_str.as_bytes().get(2)? != &b':' {
                return None;
            }
            let oh: i16 = off_str.get(0..2)?.parse().ok()?;
            let om: i16 = off_str.get(3..5)?.parse().ok()?;
            Some(sign * (oh * 60 + om))
        }
        None => None,
        _ => return None,
    };
    ForensicTimestamp::try_with_ymd_and_hms_nanos(
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos,
        offset_minutes,
    )
    .ok()
}

fn nil_token(s: &str) -> Option<String> {
    if s == "-" {
        None
    } else {
        Some(s.to_string())
    }
}

fn parse_pri(text: &str) -> Result<(Option<u16>, &str), &'static str> {
    match text.strip_prefix('<') {
        Some(rest) => {
            let close = rest.find('>').ok_or("unterminated PRI")?;
            let digits = rest.get(0..close).ok_or("invalid PRI")?;
            if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return Err("invalid PRI digits");
            }
            let pri: u16 = digits.parse().map_err(|_| "invalid PRI digits")?;
            if pri > 191 {
                return Err("PRI out of range");
            }
            let after = rest.get(close + 1..).ok_or("invalid PRI")?;
            Ok((Some(pri), after))
        }
        None => Ok((None, text)),
    }
}

fn parse_rfc3164(priority: Option<u16>, rest: &str) -> Result<ParsedSyslogLine, &'static str> {
    let (month, day, hour, minute, second, consumed) =
        parse_rfc3164_timestamp(rest).ok_or("malformed RFC3164 timestamp")?;
    let after_ts = rest.get(consumed..).ok_or("malformed RFC3164 timestamp")?;
    let space = after_ts.find(' ').ok_or("missing RFC3164 hostname")?;
    let hostname = after_ts.get(..space).ok_or("malformed RFC3164 hostname")?;
    if hostname.is_empty() {
        return Err("empty RFC3164 hostname");
    }
    let after_host = after_ts
        .get(space + 1..)
        .ok_or("malformed RFC3164 hostname")?;
    let (tag, pid, message) = split_tag(after_host);
    Ok(ParsedSyslogLine {
        format: SyslogFormat::Rfc3164,
        priority,
        hostname: Some(hostname.to_string()),
        app_name: tag.map(str::to_string),
        proc_id: pid.map(str::to_string),
        msg_id: None,
        structured_data: None,
        message: message.to_string(),
        timestamp: None,
        rfc3164_month_day: Some((month, day, hour, minute, second)),
    })
}

fn parse_rfc5424(priority: Option<u16>, rest: &str) -> Result<ParsedSyslogLine, &'static str> {
    let (timestamp_tok, rest) = take_token(rest).ok_or("missing RFC5424 timestamp")?;
    let (hostname_tok, rest) = take_token(rest).ok_or("missing RFC5424 hostname")?;
    let (app_tok, rest) = take_token(rest).ok_or("missing RFC5424 app-name")?;
    let (proc_tok, rest) = take_token(rest).ok_or("missing RFC5424 procid")?;
    let (msgid_tok, rest) = take_token(rest).ok_or("missing RFC5424 msgid")?;
    let (structured_data, message) = parse_structured_data(rest);
    let timestamp = if timestamp_tok == "-" {
        None
    } else {
        Some(parse_iso8601(timestamp_tok).ok_or("malformed RFC5424 timestamp")?)
    };
    Ok(ParsedSyslogLine {
        format: SyslogFormat::Rfc5424,
        priority,
        hostname: nil_token(hostname_tok),
        app_name: nil_token(app_tok),
        proc_id: nil_token(proc_tok),
        msg_id: nil_token(msgid_tok),
        structured_data,
        message: message.to_string(),
        timestamp,
        rfc3164_month_day: None,
    })
}

/// Parses one already lossily-decoded syslog line. The caller keeps the original raw bytes
/// separately (see [`SyslogParserFactory::open`]) — this function only ever sees display text.
pub fn parse_line(text: &str) -> Result<ParsedSyslogLine, &'static str> {
    let (priority, rest) = parse_pri(text)?;
    match rest.strip_prefix("1 ") {
        Some(after_version) => parse_rfc5424(priority, after_version),
        None => parse_rfc3164(priority, rest),
    }
}

/// How an RFC3164 line's missing year was derived. Never "invented": both variants trace back to
/// real evidence (the file's own mtime, or the ordering of lines already in the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YearDerivation {
    /// Anchored on the collected file's modification time (adjusted back one year if the
    /// mtime-anchored year would place the very first line in the future).
    FileMtime,
    /// At least one earlier line in this file forced a year increment: a large backward jump in
    /// month (e.g. December followed by January) while scanning a file in append order means the
    /// log crossed a new year's boundary partway through.
    ContextRollover,
}

/// Derives the year for successive RFC3164 timestamps within one file — see the module docs and
/// [`YearDerivation`]. Never invents a year with no anchor: without a usable file mtime, every
/// line in the file carries no `@timestamp` at all, only the raw calendar fields.
pub struct YearTracker {
    year: Option<u16>,
    last_month: Option<u8>,
    rolled_over: bool,
}

impl YearTracker {
    pub fn new(mtime: Option<ForensicTimestamp>) -> Self {
        Self {
            year: mtime.and_then(|t| u16::try_from(t.year()).ok()),
            last_month: None,
            rolled_over: false,
        }
    }

    /// Resolves `(month, day, hour, minute, second)` into a full timestamp plus how the year was
    /// derived, or `None` when this tracker has no anchor at all.
    pub fn resolve(
        &mut self,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        mtime: Option<ForensicTimestamp>,
    ) -> Option<(ForensicTimestamp, YearDerivation)> {
        let is_first = self.last_month.is_none();
        if !is_first {
            if let Some(last_month) = self.last_month {
                if month < last_month && last_month - month >= 6 {
                    // `checked_add` rather than a bare `+ 1`: a file whose mtime-derived year
                    // is already `u16::MAX` (tampered or corrupt metadata) must lose its year
                    // anchor, not overflow into a fabricated one.
                    self.year = self.year.and_then(|y| y.checked_add(1));
                    self.rolled_over = true;
                }
            }
        }
        self.last_month = Some(month);
        let mut year = self.year?;
        if is_first {
            if let Some(mtime) = mtime {
                if let Ok(candidate) =
                    ForensicTimestamp::with_ymd_and_hms(year, month, day, 0, 0, 0, 0)
                {
                    // One day of tolerance for clock skew between the collected file's mtime
                    // and the timestamps it contains.
                    if candidate.to_unix_secs() > mtime.to_unix_secs() + 86_400 {
                        // Same reasoning as the increment above: a year of 0 has no valid
                        // predecessor, so lose the anchor rather than underflow it.
                        let Some(prior_year) = year.checked_sub(1) else {
                            self.year = None;
                            return None;
                        };
                        year = prior_year;
                        self.year = Some(year);
                    }
                }
            }
        }
        let timestamp =
            ForensicTimestamp::with_ymd_and_hms(year, month, day, hour, minute, second, 0).ok()?;
        let derivation = if self.rolled_over {
            YearDerivation::ContextRollover
        } else {
            YearDerivation::FileMtime
        };
        // Mark the derived year as inferred, never presented as read directly off the evidence
        // the way the rest of the timestamp's fields were.
        let inferred = ForensicTimestamp::try_from_parts(
            timestamp.utc_seconds(),
            timestamp.nanoseconds(),
            timestamp.utc_offset_minutes(),
            timestamp.flags() | TimestampFlags::INFERRED,
        )
        .unwrap_or(timestamp);
        Some((inferred, derivation))
    }
}

impl YearDerivation {
    fn as_str(self) -> &'static str {
        match self {
            YearDerivation::FileMtime => "file_mtime",
            YearDerivation::ContextRollover => "context_rollover",
        }
    }
}

/// Crate-local `linux.syslog.*` field names.
mod field {
    pub const FORMAT: &str = "linux.syslog.format";
    pub const RAW: &str = "linux.syslog.raw";
    pub const RAW_HEX: &str = "linux.syslog.raw_hex";
    pub const PROC_ID_RAW: &str = "linux.syslog.proc_id";
    pub const MSG_ID: &str = "linux.syslog.msg_id";
    pub const STRUCTURED_DATA: &str = "linux.syslog.structured_data";
    pub const YEAR_SOURCE: &str = "linux.syslog.year_source";
}

/// Emits one [`ForensicData`] per non-blank line, from every location the run's
/// [`ArtifactCatalog`] locates for [`DEFINITIONS`].
///
/// Stateless (`&self`): per-file state (the [`YearTracker`], the registered [`SourceHandle`])
/// lives inside [`Self::open`]'s closure, never in `self`.
pub struct SyslogParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for SyslogParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> = DEFINITIONS
            .iter()
            .copied()
            .map(Requirement::artifact)
            .collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux syslog (RFC3164/RFC5424) text logs",
                "Emits one record per line from auth.log/syslog/messages/kern.log/daemon.log/\
                 cron.log, wherever the artifact catalog resolves them",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(
                DEFINITIONS
                    .iter()
                    .map(|d| Artifact::Linux(LinuxArtifacts::Log(log_kind(d).to_string())))
                    .collect::<Vec<_>>(),
            )
            .with_requirements(requirements),
        }
    }
}

impl SyslogParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for SyslogParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some() && ctx.sources().catalog().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().cloned().ok_or_else(|| {
            ForensicError::missing_data(
                "FileSystem source required",
                CompactString::const_new(PARSER_ID),
            )
        })?;
        if ctx.sources().catalog().is_none() {
            return Err(ForensicError::missing_data(
                "ArtifactCatalog required: this parser locates syslog files by artifact \
                 definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        let mut targets: std::collections::BTreeMap<FPathBuf, &'static str> =
            std::collections::BTreeMap::new();
        for definition in DEFINITIONS.iter().copied() {
            let resolution = match ctx.resolve_artifact(definition) {
                Ok(resolution) => resolution,
                Err(e) => {
                    head.push(Err(e));
                    continue;
                }
            };
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
                    debug!(
                        "{PARSER_ID}: {definition}: ignoring directory {}",
                        file.path
                    );
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
                let mtime = fs
                    .metadata(path.as_path())
                    .ok()
                    .and_then(|m| m.modified_opt().copied());
                let mut tracker = YearTracker::new(mtime);
                let lines = scan_lines(&bytes);
                let mut total = 0usize;
                let mut failed = 0usize;
                for line in &lines {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    if line.raw.is_empty() {
                        continue;
                    }
                    total += 1;
                    let text = line.text();
                    match parse_line(text.as_ref()) {
                        Ok(parsed) => {
                            let (timestamp, year_derivation) = match parsed.rfc3164_month_day {
                                Some((month, day, hour, minute, second)) => {
                                    match tracker.resolve(month, day, hour, minute, second, mtime) {
                                        Some((ts, derivation)) => (Some(ts), Some(derivation)),
                                        None => (None, None),
                                    }
                                }
                                None => (parsed.timestamp, None),
                            };
                            let data = syslog_to_forensic_data(
                                &host,
                                definition,
                                path.as_path(),
                                &source,
                                acquisition,
                                line.raw,
                                &parsed,
                                timestamp,
                                year_derivation,
                            );
                            if out.emit(Ok(data)).is_stop() {
                                return Ok(());
                            }
                        }
                        Err(reason) => {
                            failed += 1;
                            let e = ForensicError::invalid_format(
                                "syslog line",
                                format!("line {}: {reason}: {text:?}", line.number),
                            )
                            .with_path(path.clone());
                            if out.emit(Err(e)).is_stop() {
                                return Ok(());
                            }
                        }
                    }
                }
                if let Some(e) = systematic_parse_failure(path.as_path(), "syslog", total, failed) {
                    if out.emit(Err(e)).is_stop() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        }))
    }
}

fn read_file(fs: &dyn FileSystem, path: &FPath) -> ForensicResult<Vec<u8>> {
    use std::io::Read;
    let mut file = fs
        .open(path)
        .map_err(|e| e.with_path(FPathBuf::from(path.as_str())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| {
        ForensicError::io_error_with_source(e, format!("{PARSER_ID}: reading {path}"))
    })?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn syslog_to_forensic_data(
    host: &str,
    definition: &'static str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    raw_line: &[u8],
    parsed: &ParsedSyslogLine,
    timestamp: Option<ForensicTimestamp>,
    year_derivation: Option<YearDerivation>,
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(
        host,
        Artifact::Linux(LinuxArtifacts::Log(log_kind(definition).to_string())),
        provenance,
    );
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::FORMAT, parsed.format.as_str());
    data.set(field::RAW, String::from_utf8_lossy(raw_line).into_owned());
    data.set(field::RAW_HEX, hex_encode(raw_line));
    if let Some(ts) = timestamp {
        data.set(TIMESTAMP, ts);
    }
    if let Some(derivation) = year_derivation {
        data.set(field::YEAR_SOURCE, derivation.as_str());
    }
    if let Some(pri) = parsed.priority {
        data.set(LOG_SYSLOG_PRIORITY, pri as i64);
        data.set(LOG_SYSLOG_FACILITY_CODE, (pri / 8) as i64);
        data.set(LOG_SYSLOG_SEVERITY_CODE, (pri % 8) as i64);
    }
    if let Some(hostname) = &parsed.hostname {
        data.set(HOST_HOSTNAME, hostname.clone());
    }
    if let Some(app_name) = &parsed.app_name {
        data.set(PROCESS_NAME, app_name.clone());
    }
    if let Some(proc_id) = &parsed.proc_id {
        data.set(field::PROC_ID_RAW, proc_id.clone());
        if let Ok(pid) = proc_id.parse::<i64>() {
            data.set(PROCESS_PID, pid);
        }
    }
    if let Some(msg_id) = &parsed.msg_id {
        data.set(field::MSG_ID, msg_id.clone());
    }
    if let Some(sd) = &parsed.structured_data {
        data.set(field::STRUCTURED_DATA, sd.clone());
    }
    data.set(MESSAGE, parsed.message.clone());
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3164_with_pid() {
        let parsed = parse_line(
            "<34>Jan 15 08:00:12 fw01 sshd[1234]: Failed password for invalid user admin from \
             203.0.113.7 port 51515 ssh2",
        )
        .unwrap();
        assert_eq!(parsed.format, SyslogFormat::Rfc3164);
        assert_eq!(parsed.priority, Some(34));
        assert_eq!(parsed.hostname.as_deref(), Some("fw01"));
        assert_eq!(parsed.app_name.as_deref(), Some("sshd"));
        assert_eq!(parsed.proc_id.as_deref(), Some("1234"));
        assert_eq!(
            parsed.message,
            "Failed password for invalid user admin from 203.0.113.7 port 51515 ssh2"
        );
        assert_eq!(parsed.rfc3164_month_day, Some((1, 15, 8, 0, 12)));
    }

    #[test]
    fn parses_rfc3164_without_pri_or_pid() {
        // auth.log's own local convention: no <PRI>, and some tags (kernel, sudo) carry no pid.
        let parsed =
            parse_line("Jan 15 08:01:00 fw01 kernel: [12345.678901] eth0: link becomes ready")
                .unwrap();
        assert_eq!(parsed.priority, None);
        assert_eq!(parsed.app_name.as_deref(), Some("kernel"));
        assert_eq!(parsed.proc_id, None);
        assert_eq!(parsed.message, "[12345.678901] eth0: link becomes ready");
    }

    #[test]
    fn a_tag_with_no_colon_at_all_becomes_the_whole_message_not_an_error() {
        let parsed = parse_line("Jan 15 08:01:00 fw01 just some free text with no tag").unwrap();
        assert_eq!(parsed.app_name, None);
        assert_eq!(parsed.proc_id, None);
        assert_eq!(parsed.message, "just some free text with no tag");
    }

    #[test]
    fn sudo_style_messages_keep_their_own_leading_space_beyond_the_tag_separator() {
        let parsed = parse_line(
            "Jan 15 08:05:44 web02 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; \
             COMMAND=/usr/bin/systemctl restart nginx",
        )
        .unwrap();
        assert_eq!(parsed.app_name.as_deref(), Some("sudo"));
        // Only the one mandatory "tag: " separator space is stripped; sudo's own message
        // format starts with further whitespace of its own, which is real content, not
        // syslog framing, and must survive untouched.
        assert!(
            parsed.message.starts_with("  deploy : TTY=pts/0"),
            "{:?}",
            parsed.message
        );
    }

    #[test]
    fn parses_rfc5424_with_structured_data() {
        let parsed = parse_line(
            "<165>1 2026-01-15T08:00:12.345678+00:00 fw01.example.net sshd 1234 ID47 \
             [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] Failed \
             password for invalid user admin from 203.0.113.7 port 51515 ssh2",
        )
        .unwrap();
        assert_eq!(parsed.format, SyslogFormat::Rfc5424);
        assert_eq!(parsed.priority, Some(165));
        assert_eq!(parsed.hostname.as_deref(), Some("fw01.example.net"));
        assert_eq!(parsed.app_name.as_deref(), Some("sshd"));
        assert_eq!(parsed.proc_id.as_deref(), Some("1234"));
        assert_eq!(parsed.msg_id.as_deref(), Some("ID47"));
        assert_eq!(
            parsed.structured_data.as_deref(),
            Some(r#"[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]"#)
        );
        assert_eq!(
            parsed.message,
            "Failed password for invalid user admin from 203.0.113.7 port 51515 ssh2"
        );
        let ts = parsed.timestamp.unwrap();
        assert_eq!(ts.year(), 2026);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
        assert_eq!(ts.hour(), 8);
        assert_eq!(ts.minute(), 0);
        assert_eq!(ts.second(), 12);
    }

    #[test]
    fn parses_rfc5424_nil_structured_data_and_nil_procid_msgid() {
        let parsed = parse_line(
            "<14>1 2026-01-15T08:05:44.000000+00:00 fw01.example.net systemd 1 - - Started \
             nginx.service - A high performance web server.",
        )
        .unwrap();
        assert_eq!(parsed.structured_data, None);
        assert_eq!(
            parsed.message,
            "Started nginx.service - A high performance web server."
        );
    }

    #[test]
    fn rfc5424_nil_timestamp_yields_no_timestamp() {
        let parsed = parse_line("<14>1 - fw01 app - - - nil timestamp case").unwrap();
        assert_eq!(parsed.timestamp, None);
    }

    #[test]
    fn a_garbage_line_is_an_error_not_a_panic() {
        assert!(parse_line("this is not a syslog line at all").is_err());
        assert!(parse_line("").is_err());
        assert!(parse_line("<999>whatever").is_err());
    }

    #[test]
    fn year_tracker_anchors_on_file_mtime() {
        let mtime = ForensicTimestamp::with_ymd_and_hms(2026, 6, 1, 0, 0, 0, 0).unwrap();
        let mut tracker = YearTracker::new(Some(mtime));
        let (ts, derivation) = tracker.resolve(1, 15, 8, 0, 12, Some(mtime)).unwrap();
        assert_eq!(ts.year(), 2026);
        assert_eq!(derivation, YearDerivation::FileMtime);
        assert!(ts.flags().contains(TimestampFlags::INFERRED));
    }

    #[test]
    fn year_tracker_rolls_back_one_year_when_the_first_line_would_be_in_the_future() {
        // mtime says January 2026, but the very first line in the file is December — the file
        // must actually be from December 2025, not a time-traveling December 2026 entry.
        let mtime = ForensicTimestamp::with_ymd_and_hms(2026, 1, 2, 0, 0, 0, 0).unwrap();
        let mut tracker = YearTracker::new(Some(mtime));
        let (ts, _) = tracker.resolve(12, 31, 23, 59, 0, Some(mtime)).unwrap();
        assert_eq!(ts.year(), 2025);
    }

    #[test]
    fn year_tracker_rolls_forward_on_a_december_to_january_transition_within_the_file() {
        let mtime = ForensicTimestamp::with_ymd_and_hms(2026, 1, 15, 0, 0, 0, 0).unwrap();
        let mut tracker = YearTracker::new(Some(mtime));
        let (dec_ts, _) = tracker.resolve(12, 31, 23, 0, 0, Some(mtime)).unwrap();
        assert_eq!(dec_ts.year(), 2025);
        let (jan_ts, derivation) = tracker.resolve(1, 2, 0, 5, 0, Some(mtime)).unwrap();
        assert_eq!(jan_ts.year(), 2026);
        assert_eq!(derivation, YearDerivation::ContextRollover);
    }

    #[test]
    fn year_tracker_with_no_mtime_and_no_context_derives_nothing() {
        let mut tracker = YearTracker::new(None);
        assert!(tracker.resolve(1, 15, 8, 0, 12, None).is_none());
    }

    #[test]
    fn year_tracker_loses_its_anchor_instead_of_underflowing_at_year_zero() {
        // A tampered/corrupt mtime of year 0 combined with a first line that would need to
        // roll back a year (December, while mtime says January) must not wrap a u16 below
        // zero: it must give up the derived year rather than fabricate one.
        let mtime = ForensicTimestamp::with_ymd_and_hms(0, 1, 2, 0, 0, 0, 0).unwrap();
        let mut tracker = YearTracker::new(Some(mtime));
        assert!(tracker.resolve(12, 31, 23, 59, 0, Some(mtime)).is_none());
        // The lost anchor must stick: a later line must not resurrect a stale/bogus year.
        assert!(tracker.resolve(12, 30, 23, 58, 0, Some(mtime)).is_none());
    }

    #[test]
    fn year_tracker_loses_its_anchor_instead_of_overflowing_at_u16_max() {
        // A tampered/corrupt mtime of year u16::MAX, followed by a December-to-January
        // transition within the file (which would need to increment the year), must not
        // wrap back around to year 0: it must give up the derived year instead.
        let mtime = ForensicTimestamp::with_ymd_and_hms(u16::MAX, 12, 31, 0, 0, 0, 0).unwrap();
        let mut tracker = YearTracker::new(Some(mtime));
        let (dec_ts, _) = tracker.resolve(12, 31, 23, 0, 0, Some(mtime)).unwrap();
        assert_eq!(dec_ts.year(), u16::MAX as i64);
        assert!(tracker.resolve(1, 2, 0, 5, 0, Some(mtime)).is_none());
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::*;

    const AUTH_DEF: &str = "LinuxAuthLogs";
    const SYSLOG_DEF: &str = "LinuxSysLogFiles";
    const CRON_DEF: &str = "LinuxCronLogs";
    const DAEMON_DEF: &str = "LinuxDaemonLogFiles";
    const KERNEL_DEF: &str = "LinuxKernelLogFiles";
    const MESSAGES_DEF: &str = "LinuxMessagesLogFiles";

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
            definition(AUTH_DEF, &[Cow::Borrowed("/var/log/auth.log")]),
            definition(CRON_DEF, &[Cow::Borrowed("/var/log/cron.log")]),
            definition(DAEMON_DEF, &[Cow::Borrowed("/var/log/daemon.log")]),
            definition(KERNEL_DEF, &[Cow::Borrowed("/var/log/kern.log")]),
            definition(MESSAGES_DEF, &[Cow::Borrowed("/var/log/messages")]),
            definition(SYSLOG_DEF, &[Cow::Borrowed("/var/log/syslog")]),
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
        let parser = SyslogParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = SyslogParserFactory::new();
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
    }

    #[test]
    fn an_rfc3164_auth_log_emits_ecs_and_raw_fields_with_a_derived_year() {
        let bytes = b"Jan 15 08:00:12 web02 sshd[1234]: Accepted publickey for deploy\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/auth.log", bytes.to_vec());
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(
            items.iter().all(|i| i.is_ok()),
            "unexpected errors: {:?}",
            items
                .iter()
                .filter_map(|i| i.as_ref().err())
                .collect::<Vec<_>>()
        );
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert!(
            matches!(record.artifact(), Artifact::Linux(LinuxArtifacts::Log(k)) if k == "auth")
        );
        assert_eq!(field(record, ARTIFACT_DEFINITION), Some(AUTH_DEF));
        assert_eq!(field(record, HOST_HOSTNAME), Some("web02"));
        assert_eq!(field(record, PROCESS_NAME), Some("sshd"));
        assert_eq!(record.field_as_u64(PROCESS_PID), Some(1234));
        assert_eq!(
            field(record, MESSAGE),
            Some("Accepted publickey for deploy")
        );
        // No file mtime in this in-memory filesystem, so the year cannot be derived; the raw
        // fields are still present either way.
        assert!(record.field_as_date(TIMESTAMP).is_none());
        assert!(field(record, "linux.syslog.raw")
            .unwrap()
            .contains("Accepted publickey"));
    }

    #[test]
    fn an_rfc5424_line_emits_structured_data_and_a_full_timestamp() {
        let bytes = b"<165>1 2026-01-15T08:00:12.345678+00:00 fw01 sshd 1234 ID47 [x@32473 a=\"1\"] hello\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/syslog", bytes.to_vec());
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(
            field(record, "linux.syslog.structured_data"),
            Some(r#"[x@32473 a="1"]"#)
        );
        assert!(record.field_as_date(TIMESTAMP).is_some());
        assert_eq!(record.field_as_u64(LOG_SYSLOG_PRIORITY), Some(165));
    }

    #[test]
    fn a_malformed_line_is_one_err_item_and_the_stream_continues() {
        let bytes = b"Jan 15 08:00:12 web02 sshd[1234]: ok\nnot a syslog line\nJan 15 08:00:13 web02 sshd[1234]: ok again\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/syslog", bytes.to_vec());
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        let errors: Vec<&ForensicError> = items.iter().filter_map(|i| i.as_ref().err()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs =
            InMemoryVirtualFileSystem::new().with_file("var/log/syslog", b"whatever".to_vec());
        let sources = sources(vfs, false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = SyslogParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }
}
