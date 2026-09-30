//! [`JournalParserFactory`]: the [`ArtifactParserFactory`] that resolves
//! `LinuxSystemdJournalLogs` through the run's artifact catalog (no hardcoded paths — a real
//! persistent journal is a *directory* of files: the current `system.journal`, rotated
//! `system@<seqnum>-<realtime>-<boot>.journal~`, and one `user-<uid>.journal` per user, all
//! resolved independently) and emits `Artifact::Linux(LinuxArtifacts::Journal)` records.
//!
//! Structurally this mirrors `crate::unix::utmp::UtmpParserFactory` (eager catalog resolution in
//! [`ArtifactParserFactory::open`], one [`SourceHandle`] per real file, `head` errors emitted
//! before any record so catalog-level problems are not buried) rather than layering on top of
//! [`crate::journal::factory::JournalFormatFactory`]'s [`forensic_rs::traits::format::Mounted`]
//! machinery the way `frnsc-winevt`'s `EvtxParserFactory` does — a `.journal` file is located
//! directly by artifact definition and read directly via [`FileSystem::open`], the same as every
//! other `frnsc-linux` parser; going through `Mounted` would add a layer of indirection with no
//! benefit here.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::prelude::*;

use crate::journal::header;
use crate::journal::reader::{JournalFile, ResolvedEntry};

pub const PARSER_ID: &str = "linux.journal";

pub const DEFINITIONS: &[&str] = &["LinuxSystemdJournalLogs"];

/// Crate-local `linux.journal.*` field names, following `unix::utmp`'s `mod field` precedent for
/// anything with no home in [`forensic_rs::dictionary`]. Every resolved field is stored under
/// [`field::raw`] regardless of whether it also gets an ECS-mapped copy — see
/// [`crate::journal::reader`]'s module docs on why raw values are never dropped in favor of a
/// mapped one.
mod field {
    pub const SEQNUM: &str = "linux.journal.seqnum";
    pub const MONOTONIC_TIMESTAMP: &str = "linux.journal.monotonic_timestamp";
    pub const BOOT_ID: &str = "linux.journal.boot_id";
    pub const RECOVERY_ONLY: &str = "linux.journal.recovery_only";
    pub const TRUSTED_FIELDS: &str = "linux.journal.trusted_fields";
    pub const FORGEABLE_FIELDS: &str = "linux.journal.forgeable_fields";
    pub const MESSAGE: &str = "linux.journal.message";
    /// `linux.journal.field.<RAW_NAME>` — built with [`super::raw_field_name`].
    pub const FIELD_PREFIX: &str = "linux.journal.field.";
}

fn raw_field_name(raw_name: &str) -> String {
    format!("{}{}", field::FIELD_PREFIX, raw_name)
}

/// journald prefixes the fields it sets itself with `_` (see the module docs on trusted vs.
/// client-forgeable fields in `crate::journal::reader`).
fn is_trusted(raw_name: &str) -> bool {
    raw_name.starts_with('_')
}

/// Maps a handful of well-known journald field names onto an ECS name from
/// [`forensic_rs::dictionary`], for the fields with an obvious, unambiguous home there.
/// Everything else — the overwhelming majority of journal fields, since they are largely
/// journald/application-specific — is reachable only via [`raw_field_name`], which is not a gap:
/// every field is always stored there regardless of whether it also appears here.
fn ecs_field_name(raw_name: &str) -> Option<&'static str> {
    match raw_name {
        "_PID" => Some(PROCESS_PID),
        "_EXE" => Some(PROCESS_EXECUTABLE),
        "_COMM" => Some(PROCESS_NAME),
        "_HOSTNAME" => Some(HOST_HOSTNAME),
        "_SYSTEMD_UNIT" => Some(SERVICE_NAME),
        "_UID" => Some(USER_ID),
        "SYSLOG_FACILITY" => Some(LOG_SYSLOG_FACILITY_CODE),
        "PRIORITY" => Some(LOG_SYSLOG_SEVERITY_CODE),
        "MESSAGE" => Some(field::MESSAGE),
        _ => None,
    }
}

/// Numeric ECS fields worth parsing rather than copying as text — a parse failure just means the
/// ECS-mapped copy is skipped; the raw field is always present regardless (never invented).
fn ecs_field_is_numeric(ecs_name: &str) -> bool {
    matches!(
        ecs_name,
        PROCESS_PID | USER_ID | LOG_SYSLOG_FACILITY_CODE | LOG_SYSLOG_SEVERITY_CODE
    )
}

fn entry_timestamp(realtime_micros: u64) -> Option<ForensicTimestamp> {
    i64::try_from(realtime_micros)
        .ok()
        .map(ForensicTimestamp::from_unix_micros)
}

fn entry_to_forensic_data(
    host: &str,
    definition: &'static str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    entry: &ResolvedEntry,
) -> ForensicData {
    let recovery = if entry.recovery_only {
        Recovery::Carved
    } else {
        Recovery::Allocated
    };
    let provenance = source.mint(acquisition, recovery);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Journal), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::SEQNUM, entry.seqnum);
    data.set(field::MONOTONIC_TIMESTAMP, entry.monotonic);
    data.set(field::BOOT_ID, header::hex_encode(&entry.boot_id));
    data.set(field::RECOVERY_ONLY, entry.recovery_only);
    if let Some(ts) = entry_timestamp(entry.realtime) {
        data.set(TIMESTAMP, ts);
    }

    let mut trusted_fields: Vec<Text> = Vec::new();
    let mut forgeable_fields: Vec<Text> = Vec::new();
    for f in &entry.fields {
        if is_trusted(&f.raw_name) {
            trusted_fields.push(Text::Owned(f.raw_name.clone()));
        } else {
            forgeable_fields.push(Text::Owned(f.raw_name.clone()));
        }

        let raw_key = raw_field_name(&f.raw_name);
        match &f.value_utf8 {
            Some(text) => data.insert(Text::Owned(raw_key), Field::Text(Text::Owned(text.clone()))),
            None => {
                // Non-UTF-8: keep the exact bytes (lossy-decoded for display only), per the
                // crate-wide hostile-input rule.
                data.insert(
                    Text::Owned(format!("{raw_key}_raw")),
                    Field::Text(Text::Owned(hex_encode(&f.value_raw))),
                );
                data.insert(
                    Text::Owned(raw_key),
                    Field::Text(Text::Owned(String::from_utf8_lossy(&f.value_raw).into_owned())),
                );
            }
        }

        if let Some(ecs_name) = ecs_field_name(&f.raw_name) {
            let text = f
                .value_utf8
                .clone()
                .unwrap_or_else(|| String::from_utf8_lossy(&f.value_raw).into_owned());
            if ecs_field_is_numeric(ecs_name) {
                if let Ok(n) = text.parse::<i64>() {
                    data.set(ecs_name, n);
                }
                // A non-numeric value for a normally-numeric field is left unmapped rather than
                // guessed at; the raw field above still carries it verbatim.
            } else {
                data.set(ecs_name, text);
            }
        }
    }
    trusted_fields.sort();
    forgeable_fields.sort();
    data.insert(Text::Borrowed(field::TRUSTED_FIELDS), Field::Array(trusted_fields));
    data.insert(Text::Borrowed(field::FORGEABLE_FIELDS), Field::Array(forgeable_fields));
    data
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

pub struct JournalParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for JournalParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> =
            DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux systemd-journald binary journal logs",
                "Emits one record per journal entry (indexed, then recovery-scan-only entries \
                 tagged as such) from every location the artifact catalog resolves for \
                 LinuxSystemdJournalLogs, with file-level integrity findings surfaced as errors",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Linux(LinuxArtifacts::Journal)])
            .with_requirements(requirements),
        }
    }
}

impl JournalParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for JournalParserFactory {
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
                "ArtifactCatalog required: this parser locates journal files by artifact \
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
                let journal = match JournalFile::parse(bytes) {
                    Ok(j) => j,
                    Err(e) => {
                        if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                let result = journal.read_all(crate::journal::compress::MAX_DECOMPRESSED_SIZE);
                for finding in result.findings {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    if out.emit(Err(finding.with_path(path.clone()))).is_stop() {
                        return Ok(());
                    }
                }
                for item in result.entries {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    match item {
                        Ok(entry) => {
                            let data = entry_to_forensic_data(
                                &host,
                                definition,
                                path.as_path(),
                                &source,
                                acquisition,
                                &entry,
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
            }
            Ok(())
        }))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_vs_forgeable_matches_the_underscore_convention() {
        assert!(is_trusted("_PID"));
        assert!(is_trusted("_HOSTNAME"));
        assert!(!is_trusted("MESSAGE"));
        assert!(!is_trusted("PRIORITY"));
    }

    #[test]
    fn ecs_mapping_covers_the_documented_fields() {
        assert_eq!(ecs_field_name("_PID"), Some(PROCESS_PID));
        assert_eq!(ecs_field_name("_HOSTNAME"), Some(HOST_HOSTNAME));
        assert_eq!(ecs_field_name("SOME_RANDOM_APP_FIELD"), None);
    }

    #[test]
    fn raw_field_name_is_deterministic() {
        assert_eq!(raw_field_name("MESSAGE"), "linux.journal.field.MESSAGE");
    }
}
