//! Package-manager timeline and repository-configuration parsing, and [`PackagesParserFactory`],
//! the [`ArtifactParserFactory`] that resolves `DebianPackagesLogFiles`/`DebianPackagesStatus`/
//! `AptitudeLogFiles`/`APTSources`/`YumSources` through the run's artifact catalog (no hardcoded
//! paths) and emits `Artifact::Linux(LinuxArtifacts::Packages)` records, on top of the shared
//! [`crate::log::text`] scaffold.
//!
//! Five sources, five shapes — this module deliberately does not force them into one record
//! layout, only one artifact tag and one crate-local field namespace (`linux.packages.*`):
//!
//! * **`DebianPackagesLogFiles`** (`dpkg.log`) — a real install/remove/configure timeline, one
//!   line per state transition: `YYYY-MM-DD HH:MM:SS action pkg:arch old-version new-version`
//!   (`<none>` stands in for "no version", e.g. a fresh install's old version).
//! * **`DebianPackagesStatus`** (`/var/lib/dpkg/status`) — **not** a log: an RFC822-style
//!   snapshot of every known package's current state, blank-line-separated stanzas of
//!   `Key: Value` (with `Description`'s continuation lines indented by one space).
//! * **`AptitudeLogFiles`** — session-grouped `[ACTION] pkg (old -> new)` / `[ACTION] pkg
//!   (version)` lines; each session's own timestamp line (`Www, Mon DD YYYY HH:MM:SS ±ZZZZ`)
//!   gives the action lines that follow it their `@timestamp`, carried forward the same
//!   surrounding-context way [`crate::log::syslog::YearTracker`] carries an RFC3164 year.
//! * **`APTSources`** (`sources.list`-style) — `deb`/`deb-src [options] URI distribution
//!   component...` lines; `#`-comments and blank lines are not data.
//! * **`YumSources`** (`.repo` files) — INI: `[repo-id]` sections of `key=value` lines.

use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use crate::log::text::{scan_lines, TextLine};

/// Registration id of [`PackagesParserFactory`].
pub const PARSER_ID: &str = "linux.packages";

/// The ForensicArtifacts definitions this parser reads, sorted for deterministic requirement
/// order. The catalog is the source of truth for *where* these files live.
pub const DEFINITIONS: &[&str] = &["APTSources", "AptitudeLogFiles", "DebianPackagesLogFiles", "DebianPackagesStatus", "YumSources"];

/// Which of the five shapes a [`DEFINITIONS`] entry is parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackagesFormat {
    DpkgLog,
    DpkgStatus,
    AptitudeLog,
    AptSources,
    YumRepo,
}

fn format_for_definition(definition: &str) -> PackagesFormat {
    match definition {
        "DebianPackagesLogFiles" => PackagesFormat::DpkgLog,
        "DebianPackagesStatus" => PackagesFormat::DpkgStatus,
        "AptitudeLogFiles" => PackagesFormat::AptitudeLog,
        "APTSources" => PackagesFormat::AptSources,
        "YumSources" => PackagesFormat::YumRepo,
        // Every DEFINITIONS entry has an arm above; this is unreachable in practice but must not
        // panic if the two lists ever drift.
        _ => PackagesFormat::AptSources,
    }
}

impl PackagesFormat {
    fn as_str(self) -> &'static str {
        match self {
            PackagesFormat::DpkgLog => "dpkg_log",
            PackagesFormat::DpkgStatus => "dpkg_status",
            PackagesFormat::AptitudeLog => "aptitude_log",
            PackagesFormat::AptSources => "apt_sources",
            PackagesFormat::YumRepo => "yum_repo",
        }
    }
}

/// One package-related record, in whichever shape its source format produced. `raw` is always
/// the exact source text this record came from — a whole dpkg.log line, a whole dpkg/status
/// stanza, an aptitude action line, a sources.list line, or a yum repo section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageRecord {
    pub timestamp: Option<i64>, // unix seconds; kept as an option of a plain value so callers can build a ForensicTimestamp without this module depending on its flag-tagging choices
    pub action: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub package_version_old: Option<String>,
    pub package_architecture: Option<String>,
    /// Extra fields specific to a format (dpkg/status's other headers, a yum repo's other ini
    /// keys), as `(key, value)` in source order.
    pub extra: Vec<(String, String)>,
    pub raw: String,
}

fn none_token(s: &str) -> Option<String> {
    if s == "<none>" {
        None
    } else {
        Some(s.to_string())
    }
}

fn split_pkg_arch(token: &str) -> (Option<String>, Option<String>) {
    match token.rfind(':') {
        Some(i) => (token.get(..i).map(str::to_string), token.get(i + 1..).map(str::to_string)),
        None => (Some(token.to_string()), None),
    }
}

fn parse_dpkg_timestamp(date: &str, time: &str) -> Option<i64> {
    let d = date.as_bytes();
    if d.len() != 10 || d.get(4)? != &b'-' || d.get(7)? != &b'-' {
        return None;
    }
    let year: u16 = date.get(0..4)?.parse().ok()?;
    let month: u8 = date.get(5..7)?.parse().ok()?;
    let day: u8 = date.get(8..10)?.parse().ok()?;
    let t = time.as_bytes();
    if t.len() != 8 || t.get(2)? != &b':' || t.get(5)? != &b':' {
        return None;
    }
    let hour: u8 = time.get(0..2)?.parse().ok()?;
    let minute: u8 = time.get(3..5)?.parse().ok()?;
    let second: u8 = time.get(6..8)?.parse().ok()?;
    let ts = ForensicTimestamp::with_ymd_and_hms(year, month, day, hour, minute, second, 0).ok()?;
    Some(ts.to_unix_secs())
}

/// Parses one `dpkg.log` line. Unrecognized actions are kept (their package/version fields stay
/// `None` rather than guessing a shape) instead of erroring the line.
fn parse_dpkg_log_line(text: &str) -> Result<PackageRecord, &'static str> {
    let mut tokens = text.split_whitespace();
    let date = tokens.next().ok_or("missing date")?;
    let time = tokens.next().ok_or("missing time")?;
    let action = tokens.next().ok_or("missing action")?;
    let rest: Vec<&str> = tokens.collect();
    let timestamp = parse_dpkg_timestamp(date, time);
    let mut record = PackageRecord {
        timestamp,
        action: Some(action.to_string()),
        raw: text.to_string(),
        ..Default::default()
    };
    match action {
        "startup" => {}
        "status" => {
            // status <pkg-status> <pkg:arch> <version>
            if let Some(pkg_arch) = rest.get(1) {
                let (name, arch) = split_pkg_arch(pkg_arch);
                record.package_name = name;
                record.package_architecture = arch;
            }
            record.package_version = rest.last().map(|v| v.to_string());
        }
        _ => {
            // install/upgrade/configure/remove/disappear/trigproc: <pkg:arch> <old> <new>
            if let Some(pkg_arch) = rest.first() {
                let (name, arch) = split_pkg_arch(pkg_arch);
                record.package_name = name;
                record.package_architecture = arch;
            }
            record.package_version_old = rest.get(1).and_then(|v| none_token(v));
            record.package_version = rest.get(2).and_then(|v| none_token(v));
        }
    }
    Ok(record)
}

/// Parses one blank-line-separated `dpkg/status` stanza (already split into its non-blank lines,
/// in order). `Description`'s indented continuation lines are folded into the same value with a
/// `\n`; any other indented continuation is folded the same way, on the assumption RFC822 folding
/// applies uniformly rather than only to fields we specifically expect it on.
fn parse_dpkg_status_stanza(lines: &[String]) -> PackageRecord {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = &last_key {
                if let Some(value) = fields.get_mut(key) {
                    value.push('\n');
                    value.push_str(line.trim_start());
                }
            }
            continue;
        }
        if let Some(colon) = line.find(':') {
            let key = line.get(..colon).unwrap_or("").to_string();
            let value = line.get(colon + 1..).unwrap_or("").trim_start().to_string();
            fields.insert(key.clone(), value);
            last_key = Some(key);
        } else {
            last_key = None;
        }
    }
    let package_name = fields.get("Package").cloned();
    let package_version = fields.get("Version").cloned();
    let package_architecture = fields.get("Architecture").cloned();
    let action = fields.get("Status").cloned();
    let extra: Vec<(String, String)> = fields
        .into_iter()
        .filter(|(k, _)| !matches!(k.as_str(), "Package" | "Version" | "Architecture" | "Status"))
        .collect();
    PackageRecord {
        timestamp: None,
        action,
        package_name,
        package_version,
        package_version_old: None,
        package_architecture,
        extra,
        raw: lines.join("\n"),
    }
}

const MONTH_ABBREVS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

fn month_index(name: &str) -> Option<u8> {
    MONTH_ABBREVS.iter().position(|m| m.eq_ignore_ascii_case(name)).map(|i| (i + 1) as u8)
}

/// Parses an aptitude session header (`"Www, Mon DD YYYY HH:MM:SS ±ZZZZ"`) into unix seconds.
fn parse_aptitude_session_timestamp(text: &str) -> Option<i64> {
    let comma = text.find(", ")?;
    let rest = text.get(comma + 2..)?;
    let mut parts = rest.split_whitespace();
    let month = month_index(parts.next()?)?;
    let day: u8 = parts.next()?.parse().ok()?;
    let year: u16 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let tz = parts.next()?;
    let time_bytes = time.as_bytes();
    if time_bytes.len() != 8 || time_bytes.get(2)? != &b':' || time_bytes.get(5)? != &b':' {
        return None;
    }
    let hour: u8 = time.get(0..2)?.parse().ok()?;
    let minute: u8 = time.get(3..5)?.parse().ok()?;
    let second: u8 = time.get(6..8)?.parse().ok()?;
    if tz.len() != 5 {
        return None;
    }
    let sign: i16 = match tz.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let oh: i16 = tz.get(1..3)?.parse().ok()?;
    let om: i16 = tz.get(3..5)?.parse().ok()?;
    let offset = sign * (oh * 60 + om);
    let ts = ForensicTimestamp::try_with_ymd_and_hms_nanos(year as i64, month, day, hour, minute, second, 0, Some(offset)).ok()?;
    Some(ts.to_unix_secs())
}

/// Parses one aptitude `[ACTION] pkg (old -> new)` / `[ACTION] pkg (version)` line.
fn parse_aptitude_action_line(text: &str) -> Option<PackageRecord> {
    let trimmed = text.trim_start();
    let rest = trimmed.strip_prefix('[')?;
    let close = rest.find(']')?;
    let action = rest.get(..close)?.to_string();
    let after = rest.get(close + 1..)?.trim_start();
    let paren_open = after.find('(')?;
    let pkg = after.get(..paren_open)?.trim();
    if pkg.is_empty() {
        return None;
    }
    let after_paren = after.get(paren_open + 1..)?;
    let paren_close = after_paren.find(')')?;
    let inner = after_paren.get(..paren_close)?;
    let (old, new) = match inner.find(" -> ") {
        Some(arrow) => (
            inner.get(..arrow).map(|s| s.trim().to_string()),
            inner.get(arrow + 4..).map(|s| s.trim().to_string()),
        ),
        None => (None, Some(inner.trim().to_string())),
    };
    Some(PackageRecord {
        timestamp: None,
        action: Some(action),
        package_name: Some(pkg.to_string()),
        package_version: new,
        package_version_old: old,
        package_architecture: None,
        extra: Vec::new(),
        raw: text.to_string(),
    })
}

/// Parses one `sources.list`-style `deb`/`deb-src` line. `#`-comments and blank lines are not
/// data and are filtered by the caller before this is reached.
fn parse_apt_sources_line(text: &str) -> Option<PackageRecord> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut tokens = trimmed.split_whitespace();
    let kind = tokens.next()?;
    if kind != "deb" && kind != "deb-src" {
        return None;
    }
    let mut rest: Vec<&str> = tokens.collect();
    let mut options = None;
    if rest.first().is_some_and(|t| t.starts_with('[') && t.ends_with(']')) {
        options = Some(rest.remove(0).to_string());
    }
    if rest.is_empty() {
        return None;
    }
    let uri = rest.remove(0).to_string();
    let distribution = if rest.is_empty() { None } else { Some(rest.remove(0).to_string()) };
    let mut extra = vec![("kind".to_string(), kind.to_string()), ("uri".to_string(), uri)];
    if let Some(options) = options {
        extra.push(("options".to_string(), options));
    }
    if let Some(distribution) = distribution {
        extra.push(("distribution".to_string(), distribution));
    }
    if !rest.is_empty() {
        extra.push(("components".to_string(), rest.join(" ")));
    }
    Some(PackageRecord { raw: text.to_string(), extra, ..Default::default() })
}

/// One `[repo-id]` INI section from a yum/dnf `.repo` file.
fn parse_yum_repo_section(header: &str, lines: &[String]) -> Option<PackageRecord> {
    let id = header.strip_prefix('[')?.strip_suffix(']')?;
    if id.is_empty() {
        return None;
    }
    let mut extra = vec![("id".to_string(), id.to_string())];
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(eq) = trimmed.find('=') {
            let key = trimmed.get(..eq).unwrap_or("").trim().to_string();
            let value = trimmed.get(eq + 1..).unwrap_or("").trim().to_string();
            if !key.is_empty() {
                extra.push((key, value));
            }
        }
    }
    let mut raw = vec![header.to_string()];
    raw.extend(lines.iter().cloned());
    Some(PackageRecord { raw: raw.join("\n"), extra, ..Default::default() })
}

fn lossy_text_lines(lines: &[TextLine<'_>]) -> Vec<String> {
    lines.iter().map(|l| l.text().into_owned()).collect()
}

/// Splits `lines` into blank-line-separated, non-empty groups (dpkg/status stanzas).
fn split_stanzas(lines: &[String]) -> Vec<Vec<String>> {
    let mut stanzas = Vec::new();
    let mut current = Vec::new();
    for line in lines {
        if line.is_empty() {
            if !current.is_empty() {
                stanzas.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(line.clone());
    }
    if !current.is_empty() {
        stanzas.push(current);
    }
    stanzas
}

/// Parses a whole file's lines into [`PackageRecord`]s according to `format`. Returns the
/// records plus how many non-blank input lines failed to parse (only meaningful for the two
/// line-per-record formats; stanza/section-based formats either produce a record or skip
/// something that was never a record to begin with, so their `failed` is always 0).
fn parse_records(format: PackagesFormat, lines: &[TextLine<'_>]) -> (Vec<PackageRecord>, usize, usize) {
    match format {
        PackagesFormat::DpkgLog => {
            let mut records = Vec::new();
            let mut total = 0usize;
            let mut failed = 0usize;
            for line in lines {
                if line.raw.is_empty() {
                    continue;
                }
                total += 1;
                let text = line.text();
                match parse_dpkg_log_line(text.as_ref()) {
                    Ok(record) => records.push(record),
                    Err(_) => failed += 1,
                }
            }
            (records, total, failed)
        }
        PackagesFormat::DpkgStatus => {
            let text_lines = lossy_text_lines(lines);
            let stanzas = split_stanzas(&text_lines);
            let records = stanzas.iter().map(|s| parse_dpkg_status_stanza(s)).collect();
            (records, 0, 0)
        }
        PackagesFormat::AptitudeLog => {
            let mut records = Vec::new();
            let mut session_timestamp: Option<i64> = None;
            for line in lines {
                if line.raw.is_empty() {
                    continue;
                }
                let text = line.text();
                if let Some(ts) = parse_aptitude_session_timestamp(text.as_ref()) {
                    session_timestamp = Some(ts);
                    continue;
                }
                if let Some(mut record) = parse_aptitude_action_line(text.as_ref()) {
                    record.timestamp = session_timestamp;
                    records.push(record);
                }
            }
            (records, 0, 0)
        }
        PackagesFormat::AptSources => {
            let records = lines
                .iter()
                .filter(|l| !l.raw.is_empty())
                .filter_map(|l| parse_apt_sources_line(l.text().as_ref()))
                .collect();
            (records, 0, 0)
        }
        PackagesFormat::YumRepo => {
            let text_lines = lossy_text_lines(lines);
            let mut records = Vec::new();
            let mut header: Option<String> = None;
            let mut body: Vec<String> = Vec::new();
            for line in &text_lines {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    if let Some(h) = header.take() {
                        if let Some(record) = parse_yum_repo_section(&h, &body) {
                            records.push(record);
                        }
                    }
                    header = Some(trimmed.to_string());
                    body = Vec::new();
                } else if header.is_some() {
                    body.push(line.clone());
                }
            }
            if let Some(h) = header {
                if let Some(record) = parse_yum_repo_section(&h, &body) {
                    records.push(record);
                }
            }
            (records, 0, 0)
        }
    }
}

/// Crate-local `linux.packages.*` field names not already covered by [`PACKAGE_NAME`] /
/// [`PACKAGE_VERSION`] / [`PACKAGE_ARCHITECTURE`].
mod field {
    pub const SOURCE_FORMAT: &str = "linux.packages.source_format";
    pub const VERSION_OLD: &str = "linux.packages.version_old";
    pub const RAW: &str = "linux.packages.raw";
    pub const EXTRA_PREFIX: &str = "linux.packages.";
}

fn record_to_forensic_data(
    host: &str,
    definition: &'static str,
    format: PackagesFormat,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    record: &PackageRecord,
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Packages), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::SOURCE_FORMAT, format.as_str());
    data.set(field::RAW, record.raw.clone());
    if let Some(secs) = record.timestamp {
        data.set(TIMESTAMP, ForensicTimestamp::from_unix_secs(secs));
    }
    if let Some(action) = &record.action {
        data.set(EVENT_ACTION, action.clone());
    }
    if let Some(name) = &record.package_name {
        data.set(PACKAGE_NAME, name.clone());
    }
    if let Some(version) = &record.package_version {
        data.set(PACKAGE_VERSION, version.clone());
    }
    if let Some(old) = &record.package_version_old {
        data.set(field::VERSION_OLD, old.clone());
    }
    if let Some(arch) = &record.package_architecture {
        data.set(PACKAGE_ARCHITECTURE, arch.clone());
    }
    for (key, value) in &record.extra {
        data.insert(Text::Owned(format!("{}{key}", field::EXTRA_PREFIX)), Field::Text(Text::Owned(value.clone())));
    }
    data
}

/// Emits one [`ForensicData`] per package record, from every location the run's
/// [`ArtifactCatalog`] locates for [`DEFINITIONS`].
pub struct PackagesParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for PackagesParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> = DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux package manager timeline and repository configuration",
                "Emits one record per dpkg.log/aptitude-log action, dpkg/status stanza, or apt/yum \
                 repository entry, wherever the artifact catalog resolves them",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Linux(LinuxArtifacts::Packages)])
            .with_requirements(requirements),
        }
    }
}

impl PackagesParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for PackagesParserFactory {
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
                "ArtifactCatalog required: this parser locates package-manager files by artifact \
                 definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        let mut targets: BTreeMap<FPathBuf, &'static str> = BTreeMap::new();
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
                let format = format_for_definition(definition);
                let lines = scan_lines(&bytes);
                let (records, total, failed) = parse_records(format, &lines);
                for record in &records {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    let data =
                        record_to_forensic_data(&host, definition, format, path.as_path(), &source, acquisition, record);
                    if out.emit(Ok(data)).is_stop() {
                        return Ok(());
                    }
                }
                if let Some(e) = crate::log::text::systematic_parse_failure(path.as_path(), format.as_str(), total, failed) {
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

    fn lines_of(bytes: &[u8]) -> Vec<TextLine<'_>> {
        scan_lines(bytes)
    }

    #[test]
    fn dpkg_log_install_and_status_lines() {
        let bytes = b"2023-08-01 10:15:21 install curl:amd64 <none> 7.81.0-1ubuntu1.4\n\
                      2023-08-01 10:15:23 status installed curl:amd64 7.81.0-1ubuntu1.4\n";
        let lines = lines_of(bytes);
        let (records, total, failed) = parse_records(PackagesFormat::DpkgLog, &lines);
        assert_eq!(total, 2);
        assert_eq!(failed, 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].action.as_deref(), Some("install"));
        assert_eq!(records[0].package_name.as_deref(), Some("curl"));
        assert_eq!(records[0].package_architecture.as_deref(), Some("amd64"));
        assert_eq!(records[0].package_version_old, None);
        assert_eq!(records[0].package_version.as_deref(), Some("7.81.0-1ubuntu1.4"));
        assert_eq!(records[1].action.as_deref(), Some("status"));
        assert_eq!(records[1].package_name.as_deref(), Some("curl"));
    }

    #[test]
    fn dpkg_status_stanza_with_description_continuation() {
        let bytes = b"Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 7.81.0-1ubuntu1.4\nDescription: command line tool\n a longer explanation\n\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.1-6ubuntu1\n";
        let lines = lines_of(bytes);
        let (records, _, _) = parse_records(PackagesFormat::DpkgStatus, &lines);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].package_name.as_deref(), Some("curl"));
        assert_eq!(records[0].action.as_deref(), Some("install ok installed"));
        let description = records[0].extra.iter().find(|(k, _)| k == "Description").unwrap();
        assert!(description.1.contains("a longer explanation"));
        assert_eq!(records[1].package_name.as_deref(), Some("bash"));
    }

    #[test]
    fn aptitude_actions_inherit_the_preceding_session_timestamp() {
        let bytes = b"Aptitude 0.8.13: log report\nTue, Aug 01 2023 10:15:23 +0000\n[INSTALL] curl (7.81.0-1ubuntu1.4)\n[UPGRADE] bash (5.1-6ubuntu1 -> 5.1-6ubuntu1.1)\n";
        let lines = lines_of(bytes);
        let (records, _, _) = parse_records(PackagesFormat::AptitudeLog, &lines);
        assert_eq!(records.len(), 2);
        assert!(records[0].timestamp.is_some());
        assert_eq!(records[0].action.as_deref(), Some("INSTALL"));
        assert_eq!(records[0].package_version_old, None);
        assert_eq!(records[0].package_version.as_deref(), Some("7.81.0-1ubuntu1.4"));
        assert_eq!(records[1].action.as_deref(), Some("UPGRADE"));
        assert_eq!(records[1].package_version_old.as_deref(), Some("5.1-6ubuntu1"));
        assert_eq!(records[1].package_version.as_deref(), Some("5.1-6ubuntu1.1"));
        assert_eq!(records[0].timestamp, records[1].timestamp);
    }

    #[test]
    fn aptitude_actions_before_any_session_header_have_no_timestamp() {
        let bytes = b"[INSTALL] curl (7.81.0-1ubuntu1.4)\n";
        let lines = lines_of(bytes);
        let (records, _, _) = parse_records(PackagesFormat::AptitudeLog, &lines);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].timestamp, None);
    }

    #[test]
    fn apt_sources_parses_deb_and_skips_comments_and_blanks() {
        let bytes = b"# a comment\n\ndeb http://archive.ubuntu.com/ubuntu focal main restricted\ndeb-src [arch=amd64] http://archive.ubuntu.com/ubuntu focal main\n";
        let lines = lines_of(bytes);
        let (records, _, _) = parse_records(PackagesFormat::AptSources, &lines);
        assert_eq!(records.len(), 2);
        let first: BTreeMap<_, _> = records[0].extra.iter().cloned().collect();
        assert_eq!(first.get("kind").map(String::as_str), Some("deb"));
        assert_eq!(first.get("uri").map(String::as_str), Some("http://archive.ubuntu.com/ubuntu"));
        assert_eq!(first.get("distribution").map(String::as_str), Some("focal"));
        assert_eq!(first.get("components").map(String::as_str), Some("main restricted"));
        let second: BTreeMap<_, _> = records[1].extra.iter().cloned().collect();
        assert_eq!(second.get("options").map(String::as_str), Some("[arch=amd64]"));
    }

    #[test]
    fn yum_sources_parses_ini_sections() {
        let bytes = b"[base]\nname=CentOS - Base\nbaseurl=http://mirror.example/centos/\nenabled=1\ngpgcheck=1\n\n[updates]\nname=CentOS - Updates\nenabled=0\n";
        let lines = lines_of(bytes);
        let (records, _, _) = parse_records(PackagesFormat::YumRepo, &lines);
        assert_eq!(records.len(), 2);
        let first: BTreeMap<_, _> = records[0].extra.iter().cloned().collect();
        assert_eq!(first.get("id").map(String::as_str), Some("base"));
        assert_eq!(first.get("enabled").map(String::as_str), Some("1"));
        let second: BTreeMap<_, _> = records[1].extra.iter().cloned().collect();
        assert_eq!(second.get("id").map(String::as_str), Some("updates"));
        assert_eq!(second.get("enabled").map(String::as_str), Some("0"));
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::*;

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
        let defs = vec![
            definition("APTSources", &[Cow::Borrowed("/etc/apt/sources.list")]),
            definition("AptitudeLogFiles", &[Cow::Borrowed("/var/log/aptitude")]),
            definition("DebianPackagesLogFiles", &[Cow::Borrowed("/var/log/dpkg.log")]),
            definition("DebianPackagesStatus", &[Cow::Borrowed("/var/lib/dpkg/status")]),
            definition("YumSources", &[Cow::Borrowed("/etc/yum.repos.d/*.repo")]),
        ];
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
        let parser = PackagesParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = PackagesParserFactory::new();
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
    fn dpkg_log_emits_ecs_package_fields_with_per_file_provenance() {
        let bytes = b"2023-08-01 10:15:21 install curl:amd64 <none> 7.81.0-1ubuntu1.4\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/dpkg.log", bytes.to_vec());
        let items = run(&sources(vfs, true));
        assert!(items.iter().all(|i| i.is_ok()));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(record.artifact(), &Artifact::Linux(LinuxArtifacts::Packages));
        assert_eq!(record.field_as_str(PACKAGE_NAME), Some("curl"));
        assert_eq!(record.field_as_str(PACKAGE_ARCHITECTURE), Some("amd64"));
        assert_eq!(record.field_as_str(PACKAGE_VERSION), Some("7.81.0-1ubuntu1.4"));
        assert_eq!(record.field_as_str(EVENT_ACTION), Some("install"));
        assert!(record.field_as_date(TIMESTAMP).is_some());
    }

    #[test]
    fn yum_repo_sections_emit_one_record_per_section() {
        let bytes = b"[base]\nname=Base\nenabled=1\n\n[updates]\nname=Updates\nenabled=0\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/yum.repos.d/base.repo", bytes.to_vec());
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].field_as_str("linux.packages.id"), Some("base"));
        assert_eq!(records[1].field_as_str("linux.packages.id"), Some("updates"));
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/log/dpkg.log", b"whatever".to_vec());
        let sources = sources(vfs, false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = PackagesParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }
}
