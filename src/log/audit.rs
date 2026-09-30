//! Linux `auditd` log parsing (`/var/log/audit/audit.log`), and [`AuditParserFactory`], the
//! [`ArtifactParserFactory`] that resolves `LinuxAuditLogs` through the run's artifact catalog (no
//! hardcoded paths) and emits `Artifact::Linux(LinuxArtifacts::Audit)` records — one per logical
//! event, on top of the shared [`super::text`] scaffold.
//!
//! # Format
//!
//! Each raw line is `type=TYPE msg=audit(EPOCH.MS:SERIAL): key=value key=value ...`. A value is
//! either a bare token (ends at the next space), a `"double quoted"` string (may contain spaces),
//! or a `'single quoted'` string — the kernel wraps `USER_AUTH`/`USER_LOGIN`'s own `msg=` field
//! this way, and that value's *content* is itself further `key=value` text (`op=... acct="..."
//! ..."`), which this module does not try to re-parse; it is kept as one opaque raw string.
//!
//! The kernel emits several lines with the same `(EPOCH.MS:SERIAL)` for one syscall — typically
//! `SYSCALL`, `CWD`, one or more `PATH`, and for an `execve` an `EXECVE` record carrying the
//! argv. **These are one logical event, not several** (see [`AuditEvent`]): this parser groups
//! every line sharing a serial, assuming — as auditd guarantees — that they are contiguous in the
//! file.
//!
//! `EXECVE`/`PROCTITLE` records hex-encode an argument string instead of quoting it whenever the
//! raw value would otherwise need escaping (embedded spaces, quotes, control bytes). An unquoted,
//! well-formed-hex `a0`/`a1`/.../`proctitle` value in one of those two record types is decoded
//! into a sibling `_decoded` field; the original hex text is never replaced, only supplemented.

use std::collections::{BTreeMap, BTreeSet};

use forensic_rs::prelude::*;

use super::text::{hex_decode, scan_lines, systematic_parse_failure};

/// Registration id of [`AuditParserFactory`].
pub const PARSER_ID: &str = "linux.audit";

/// The ForensicArtifacts definition this parser reads.
pub const DEFINITIONS: &[&str] = &["LinuxAuditLogs"];

/// One raw `type=... msg=audit(...): k=v ...` line, parsed but not yet grouped with its siblings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLine {
    pub event_type: String,
    pub epoch_sec: i64,
    pub epoch_ms: u16,
    pub serial: u64,
    /// In the order read from the line. Duplicate keys within one line (not expected in
    /// practice) are both kept rather than one silently overwriting the other.
    pub fields: Vec<(String, String)>,
    /// The line's line number in its file, kept for provenance-adjacent error messages.
    pub line_number: usize,
}

/// One logical audit event: every [`AuditLine`] sharing a `(epoch, serial)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub epoch_sec: i64,
    pub epoch_ms: u16,
    pub serial: u64,
    pub lines: Vec<AuditLine>,
}

/// Splits `s` into `(key, value)` pairs, respecting `"..."`/`'...'` quoting so a quoted value's
/// internal spaces and `=` signs do not get mistaken for the next pair's delimiter. Stops
/// (keeping whatever was already found) at the first token that is not a well-formed `key=...`
/// pair, rather than erroring the whole line over a trailing oddity.
fn tokenize_kv(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s;
    loop {
        let trimmed = rest.trim_start_matches(' ');
        if trimmed.is_empty() {
            break;
        }
        rest = trimmed;
        let eq = match rest.find('=') {
            Some(i) => i,
            None => break,
        };
        let key = match rest.get(..eq) {
            Some(k) if !k.is_empty() && !k.contains(' ') => k,
            _ => break,
        };
        let after_eq = match rest.get(eq + 1..) {
            Some(a) => a,
            None => break,
        };
        let (value, remainder) = match after_eq.as_bytes().first() {
            Some(b'"') => quoted_value(after_eq, '"'),
            Some(b'\'') => quoted_value(after_eq, '\''),
            _ => match after_eq.find(' ') {
                Some(i) => (after_eq.get(..i).unwrap_or(after_eq), after_eq.get(i..).unwrap_or("")),
                None => (after_eq, ""),
            },
        };
        out.push((key.to_string(), value.to_string()));
        rest = remainder;
    }
    out
}

/// `after_eq` starts with `quote`; returns the quoted span (delimiters included) and whatever
/// follows. An unterminated quote takes the rest of the string as the value rather than erroring.
fn quoted_value(after_eq: &str, quote: char) -> (&str, &str) {
    match after_eq.get(quote.len_utf8()..).and_then(|t| t.find(quote)) {
        Some(end) => {
            let close = quote.len_utf8() + end + quote.len_utf8();
            (after_eq.get(..close).unwrap_or(after_eq), after_eq.get(close..).unwrap_or(""))
        }
        None => (after_eq, ""),
    }
}

/// Strips one layer of matching `"..."`/`'...'` delimiters, for display/ECS-mapping convenience.
/// The raw field (quotes included) is always kept separately — this is never the only copy.
fn dequote(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return s.get(1..s.len() - 1).unwrap_or(s);
        }
    }
    s
}

/// Parses one raw audit line. `line_number` is only for the returned [`AuditLine`]'s own
/// bookkeeping (error messages built by the caller use their own copy).
pub fn parse_line(text: &str, line_number: usize) -> Result<AuditLine, &'static str> {
    let rest = text.strip_prefix("type=").ok_or("missing type=")?;
    let space = rest.find(' ').ok_or("missing space after type")?;
    let event_type = rest.get(..space).ok_or("malformed type")?;
    if event_type.is_empty() {
        return Err("empty type");
    }
    let rest = rest.get(space + 1..).ok_or("malformed type")?;
    let rest = rest.strip_prefix("msg=audit(").ok_or("missing msg=audit(")?;
    let dot = rest.find('.').ok_or("missing epoch separator")?;
    let epoch_sec: i64 = rest
        .get(..dot)
        .ok_or("malformed epoch")?
        .parse()
        .map_err(|_| "malformed epoch seconds")?;
    let rest = rest.get(dot + 1..).ok_or("malformed epoch")?;
    let colon = rest.find(':').ok_or("missing serial separator")?;
    let epoch_ms: u16 = rest
        .get(..colon)
        .ok_or("malformed epoch ms")?
        .parse()
        .map_err(|_| "malformed epoch milliseconds")?;
    let rest = rest.get(colon + 1..).ok_or("malformed serial")?;
    let close = rest.find(')').ok_or("missing serial close paren")?;
    let serial: u64 = rest.get(..close).ok_or("malformed serial")?.parse().map_err(|_| "malformed serial")?;
    let rest = rest.get(close + 1..).ok_or("malformed tail")?;
    let rest = rest.strip_prefix(':').ok_or("missing colon after audit head")?;
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    Ok(AuditLine {
        event_type: event_type.to_string(),
        epoch_sec,
        epoch_ms,
        serial,
        fields: tokenize_kv(rest),
        line_number,
    })
}

fn event_timestamp(epoch_sec: i64, epoch_ms: u16) -> Option<ForensicTimestamp> {
    let millis = epoch_sec.checked_mul(1000)?.checked_add(epoch_ms as i64)?;
    Some(ForensicTimestamp::from_unix_millis(millis))
}

fn first_field<'a>(event: &'a AuditEvent, key: &str) -> Option<&'a str> {
    event.lines.iter().find_map(|l| l.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()))
}

/// Whether hex-decoding `key`'s unquoted value is worth attempting: only `a0..aN` and
/// `proctitle`, and only inside the two record types that actually use this hex-or-quote
/// encoding for argv-like strings.
fn is_hex_arg_field(event_type: &str, key: &str) -> bool {
    if !matches!(event_type, "EXECVE" | "PROCTITLE") {
        return false;
    }
    key == "proctitle" || (key.starts_with('a') && key.get(1..).is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())))
}

/// Crate-local `linux.audit.*` field names not already covered by the per-record-type flattened
/// `linux.audit.<type>.<key>` fields built in [`event_to_forensic_data`].
mod field {
    pub const SERIAL: &str = "linux.audit.serial";
    pub const TYPES: &str = "linux.audit.types";
    pub const RAW: &str = "linux.audit.raw";
}

#[allow(clippy::too_many_arguments)]
fn event_to_forensic_data(
    host: &str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    event: &AuditEvent,
    raw_lines: &[String],
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Audit), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, DEFINITIONS[0]);
    data.set(field::SERIAL, event.serial);
    if let Some(ts) = event_timestamp(event.epoch_sec, event.epoch_ms) {
        data.set(TIMESTAMP, ts);
    }
    let types: BTreeSet<&str> = event.lines.iter().map(|l| l.event_type.as_str()).collect();
    data.set(
        field::TYPES,
        types.iter().map(|t| Text::Owned(t.to_string())).collect::<Vec<Text>>(),
    );
    data.set(EVENT_ACTION, types.into_iter().collect::<Vec<_>>().join(","));
    data.set(field::RAW, raw_lines.join("\n"));

    if let Some(uid) = first_field(event, "uid") {
        data.set(USER_ID, dequote(uid).to_string());
    }
    if let Some(pid) = first_field(event, "pid") {
        if let Ok(pid) = dequote(pid).parse::<i64>() {
            data.set(PROCESS_PID, pid);
        }
    }
    if let Some(exe) = first_field(event, "exe") {
        data.set(PROCESS_EXECUTABLE, dequote(exe).to_string());
    }

    // One flattened field per (record type, key): raw value untouched, exactly as read. A
    // duplicate key across different record types in the same event (e.g. two PATH lines) is
    // disambiguated with a trailing index so neither silently overwrites the other.
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for line in &event.lines {
        let type_lower = line.event_type.to_lowercase();
        for (key, value) in &line.fields {
            let count = seen.entry((type_lower.clone(), key.clone())).or_insert(0);
            let field_name = if *count == 0 {
                format!("linux.audit.{type_lower}.{key}")
            } else {
                format!("linux.audit.{type_lower}.{key}.{count}")
            };
            *count += 1;
            data.insert(Text::Owned(field_name), Field::Text(Text::Owned(value.clone())));
            if is_hex_arg_field(&line.event_type, key) && !value.starts_with('"') && !value.starts_with('\'') {
                if let Some(bytes) = hex_decode(value) {
                    let decoded_name = format!("linux.audit.{type_lower}.{key}_decoded");
                    data.insert(
                        Text::Owned(decoded_name),
                        Field::Text(Text::Owned(String::from_utf8_lossy(&bytes).into_owned())),
                    );
                }
            }
        }
    }
    data
}

/// Emits one [`ForensicData`] per logical audit event (grouped by serial — see the module docs),
/// from every location the run's [`ArtifactCatalog`] locates for [`DEFINITIONS`].
pub struct AuditParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for AuditParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> = DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux auditd log",
                "Emits one record per logical audit event (kernel records sharing a serial \
                 grouped together), wherever the artifact catalog resolves LinuxAuditLogs",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Linux(LinuxArtifacts::Audit)])
            .with_requirements(requirements),
        }
    }
}

impl AuditParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for AuditParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some() && ctx.sources().catalog().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().cloned().ok_or_else(|| {
            ForensicError::missing_data("FileSystem source required", CompactString::const_new(PARSER_ID))
        })?;
        if ctx.sources().catalog().is_none() {
            return Err(ForensicError::missing_data(
                "ArtifactCatalog required: this parser locates audit files by artifact \
                 definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        let mut targets: std::collections::BTreeMap<FPathBuf, &'static str> = std::collections::BTreeMap::new();
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
                    format!("{definition}: source {:?} was not searched: {}", u.source, u.reason),
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
                targets.entry(file.path).or_insert(definition);
            }
        }

        let targets: Vec<(FPathBuf, SourceHandle)> = targets
            .into_keys()
            .map(|path| {
                let source = ctx.register_source(SourceKey::Path(path.as_str().to_string()));
                (path, source)
            })
            .collect();

        Ok(ParserRun::push(move |out| {
            for item in head {
                if out.emit(item).is_stop() {
                    return Ok(());
                }
            }
            for (path, source) in targets {
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
                let lines = scan_lines(&bytes);
                let mut total = 0usize;
                let mut failed = 0usize;
                let mut current: Option<AuditEvent> = None;
                let mut current_raw: Vec<String> = Vec::new();
                macro_rules! flush {
                    () => {
                        if let Some(event) = current.take() {
                            let data =
                                event_to_forensic_data(&host, path.as_path(), &source, acquisition, &event, &current_raw);
                            current_raw.clear();
                            if out.emit(Ok(data)).is_stop() {
                                return Ok(());
                            }
                        }
                    };
                }
                for line in &lines {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    if line.raw.is_empty() {
                        continue;
                    }
                    total += 1;
                    let text = line.text();
                    match parse_line(text.as_ref(), line.number) {
                        Ok(parsed) => {
                            let same_event = current.as_ref().is_some_and(|e| e.serial == parsed.serial);
                            if !same_event {
                                flush!();
                                current = Some(AuditEvent {
                                    epoch_sec: parsed.epoch_sec,
                                    epoch_ms: parsed.epoch_ms,
                                    serial: parsed.serial,
                                    lines: Vec::new(),
                                });
                            }
                            current_raw.push(text.into_owned());
                            if let Some(event) = current.as_mut() {
                                event.lines.push(parsed);
                            }
                        }
                        Err(reason) => {
                            failed += 1;
                            let e = ForensicError::invalid_format(
                                "audit line",
                                format!("line {}: {reason}: {text:?}", line.number),
                            )
                            .with_path(path.clone());
                            if out.emit(Err(e)).is_stop() {
                                return Ok(());
                            }
                        }
                    }
                }
                flush!();
                if let Some(e) = systematic_parse_failure(path.as_path(), "audit", total, failed) {
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
    let mut file = fs.open(path).map_err(|e| e.with_path(FPathBuf::from(path.as_str())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| ForensicError::io_error_with_source(e, format!("{PARSER_ID}: reading {path}")))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::text::hex_encode;

    #[test]
    fn parses_a_user_auth_line_with_a_single_quoted_nested_kv_blob() {
        let line = parse_line(
            "type=USER_AUTH msg=audit(1768464012.345:1001): pid=1234 uid=0 auid=1001 ses=5 \
             subj=unconfined msg='op=PAM:authentication grantors=pam_unix acct=\"deploy\" \
             exe=\"/usr/sbin/sshd\" hostname=? addr=198.51.100.23 terminal=ssh res=success'",
            1,
        )
        .unwrap();
        assert_eq!(line.event_type, "USER_AUTH");
        assert_eq!(line.epoch_sec, 1768464012);
        assert_eq!(line.epoch_ms, 345);
        assert_eq!(line.serial, 1001);
        let msg = line.fields.iter().find(|(k, _)| k == "msg").unwrap();
        assert!(msg.1.starts_with('\''));
        assert!(msg.1.contains("acct=\"deploy\""));
        let pid = line.fields.iter().find(|(k, _)| k == "pid").unwrap();
        assert_eq!(pid.1, "1234");
    }

    #[test]
    fn a_line_missing_the_audit_head_is_an_error_not_a_panic() {
        assert!(parse_line("not an audit line", 1).is_err());
        assert!(parse_line("", 1).is_err());
        assert!(parse_line("type=X msg=audit(bad", 1).is_err());
    }

    #[test]
    fn hex_decodes_execve_argv_but_keeps_the_raw_hex_too() {
        let hex_ls = hex_encode(b"/bin/ls");
        let text = format!("type=EXECVE msg=audit(1700000000.000:55): argc=1 a0={hex_ls}");
        let line = parse_line(&text, 1).unwrap();
        let a0 = line.fields.iter().find(|(k, _)| k == "a0").unwrap();
        assert_eq!(a0.1, hex_ls);
        assert!(is_hex_arg_field("EXECVE", "a0"));
        assert!(!is_hex_arg_field("SYSCALL", "a0"), "a0 in a SYSCALL record is a raw kernel arg, not argv hex");
    }

    #[test]
    fn quoted_execve_argv_is_not_treated_as_hex() {
        let text = "type=EXECVE msg=audit(1700000000.000:56): argc=1 a0=\"/bin/ls\"";
        let line = parse_line(text, 1).unwrap();
        let a0 = line.fields.iter().find(|(k, _)| k == "a0").unwrap();
        assert_eq!(a0.1, "\"/bin/ls\"");
    }

    #[test]
    fn dequote_strips_one_layer_only() {
        assert_eq!(dequote("\"abc\""), "abc");
        assert_eq!(dequote("'abc'"), "abc");
        assert_eq!(dequote("abc"), "abc");
        assert_eq!(dequote("\""), "\"");
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::*;

    const AUDIT_DEF: &str = "LinuxAuditLogs";

    fn definition(name: &'static str, paths: &'static [Text]) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::File { paths: Cow::Borrowed(paths), separator: Separator::Slash },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Linux]),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn catalog() -> Arc<dyn ArtifactCatalog> {
        let defs = vec![definition(AUDIT_DEF, &[Cow::Borrowed("/var/log/audit/audit.log")])];
        Arc::new(SliceCatalog::new(defs).unwrap())
    }

    fn sources(vfs: InMemoryVirtualFileSystem, with_catalog: bool) -> TriageSources {
        let mut builder = TriageSources::builder().vfs(Arc::new(vfs)).acquisition(Acquisition::ImageRead);
        if with_catalog {
            builder = builder.catalog(catalog());
        }
        builder.build()
    }

    fn run(sources: &TriageSources) -> Vec<ForensicResult<ForensicData>> {
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(sources, &triage, &cancellation);
        let parser = AuditParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = AuditParserFactory::new();
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
    fn lines_sharing_a_serial_are_grouped_into_one_event() {
        let bytes = b"type=SYSCALL msg=audit(1700000000.100:42): pid=100 uid=0 exe=\"/bin/ls\"\n\
                      type=CWD msg=audit(1700000000.100:42): cwd=\"/root\"\n\
                      type=USER_AUTH msg=audit(1700000100.200:43): pid=200 uid=1000\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/audit/audit.log", bytes.to_vec());
        let items = run(&sources(vfs, true));
        assert!(items.iter().all(|i| i.is_ok()), "unexpected errors: {:?}", items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>());
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2, "serial 42's two lines are one event; serial 43 is another");
        let first = records[0];
        assert_eq!(first.field_as_u64(field::SERIAL), Some(42));
        assert_eq!(first.field_as_str(EVENT_ACTION), Some("CWD,SYSCALL"));
        assert_eq!(first.field_as_str(PROCESS_EXECUTABLE), Some("/bin/ls"));
        assert_eq!(first.field_as_str("linux.audit.syscall.pid"), Some("100"));
        assert_eq!(first.field_as_str("linux.audit.cwd.cwd"), Some("\"/root\""));
        let second = records[1];
        assert_eq!(second.field_as_u64(field::SERIAL), Some(43));
        assert_eq!(second.field_as_str(USER_ID), Some("1000"));
    }

    #[test]
    fn a_malformed_line_is_one_err_item_and_the_stream_continues() {
        let bytes = b"type=SYSCALL msg=audit(1700000000.100:1): pid=1\nnot an audit line\ntype=SYSCALL msg=audit(1700000000.100:2): pid=2\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/audit/audit.log", bytes.to_vec());
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        let errors: Vec<&ForensicError> = items.iter().filter_map(|i| i.as_ref().err()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/audit/audit.log", b"whatever".to_vec());
        let sources = sources(vfs, false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = AuditParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }
}
