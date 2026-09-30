//! systemd, SysV, LSB and xinetd service definitions, and [`UnitsParserFactory`], the
//! [`ArtifactParserFactory`] that resolves `LinuxSystemdServices`/`LinuxServices`/
//! `LinuxSysVInit`/`LinuxLSBInit`/`LinuxXinetd` through the run's artifact catalog (no hardcoded
//! paths) and emits `Artifact::Linux(LinuxArtifacts::Service(_))` records.
//!
//! # `LinuxServices` is a router, not a fifth format
//!
//! Like `linux.schedule`'s `LinuxScheduleFiles`, `LinuxServices` is a *group* definition in the
//! KB — it re-resolves the other four and contributes no files of its own. Every file this
//! module sees is classified by its real, resolved leaf definition
//! ([`ResolvedFile::artifact`]), never by `"LinuxServices"` directly; see [`classify`].
//!
//! # A known KB gap: systemd drop-ins are not resolved today
//!
//! [`is_dropin`] correctly recognizes the `<unit>.service.d/<name>.conf` shape and reports it as
//! an override (never merged with the base unit's own keys) — but the upstream
//! `LinuxSystemdServices` definition's glob list has no `*.service.d/*.conf` pattern, so no
//! drop-in file is ever resolved through the catalog as of this writing. This module does not
//! work around that with a local hardcoded glob (the task this module was written for is
//! explicit: no hardcoded paths); the gap is recorded in the workspace `FINDINGS.md` instead, so
//! fixing it is a deliberate upstream KB change, not a silent local patch.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::prelude::*;

use crate::ini;
use crate::text;

/// Registration id of [`UnitsParserFactory`].
pub const PARSER_ID: &str = "linux.units";

/// The ForensicArtifacts definitions this parser declares, in the order the issue lists them.
pub const DEFINITIONS: &[&str] =
    &["LinuxSystemdServices", "LinuxServices", "LinuxSysVInit", "LinuxLSBInit", "LinuxXinetd"];

mod field {
    pub const KIND: &str = "linux.units.kind";
    pub const LINE_NUMBER: &str = "linux.units.line_number";
    pub const RAW_LINE: &str = "linux.units.raw_line";
    pub const UNIT_KEY: &str = "linux.units.systemd.key";
    pub const UNIT_VALUE: &str = "linux.units.systemd.value";
    pub const IS_DROPIN: &str = "linux.units.systemd.is_dropin";
    pub const DROPIN_TARGET: &str = "linux.units.systemd.dropin_target_unit";
    pub const SCRIPT_NAME: &str = "linux.units.script_name";
    pub const RC_ACTION: &str = "linux.units.rc.action";
    pub const RC_SEQUENCE: &str = "linux.units.rc.sequence";
    pub const LSB_HAS_HEADER: &str = "linux.units.lsb.has_header";
    pub const LSB_PROVIDES: &str = "linux.units.lsb.provides";
    pub const LSB_REQUIRED_START: &str = "linux.units.lsb.required_start";
    pub const LSB_REQUIRED_STOP: &str = "linux.units.lsb.required_stop";
    pub const LSB_DEFAULT_START: &str = "linux.units.lsb.default_start";
    pub const LSB_DEFAULT_STOP: &str = "linux.units.lsb.default_stop";
    pub const LSB_SHORT_DESCRIPTION: &str = "linux.units.lsb.short_description";
    pub const XINETD_BLOCK_TYPE: &str = "linux.units.xinetd.block_type";
    pub const XINETD_KEY: &str = "linux.units.xinetd.key";
    pub const XINETD_OPERATOR: &str = "linux.units.xinetd.operator";
    pub const XINETD_VALUE: &str = "linux.units.xinetd.value";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Systemd,
    SysV,
    Lsb,
    Xinetd,
}

fn classify(definition: &str) -> Option<Kind> {
    match definition {
        "LinuxSystemdServices" => Some(Kind::Systemd),
        "LinuxSysVInit" => Some(Kind::SysV),
        "LinuxLSBInit" => Some(Kind::Lsb),
        "LinuxXinetd" => Some(Kind::Xinetd),
        _ => None,
    }
}

fn linux_service(kind: Kind) -> LinuxService {
    match kind {
        Kind::Systemd => LinuxService::SystemD,
        Kind::SysV => LinuxService::SysV,
        Kind::Lsb => LinuxService::InitD,
        Kind::Xinetd => LinuxService::Other("xinetd".to_string()),
    }
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Systemd => "systemd",
        Kind::SysV => "sysv_init",
        Kind::Lsb => "lsb_init",
        Kind::Xinetd => "xinetd",
    }
}

fn new_record(host: &str, kind: Kind, source: &SourceHandle, acquisition: Acquisition) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Service(linux_service(kind))), provenance)
}

fn base_fields(data: &mut ForensicData, path: &FPath, definition: &str, kind: Kind) {
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition.to_string());
    data.set(field::KIND, kind_label(kind));
}

/// `<unit>.service.d/<name>.conf` -> `Some("<unit>.service")`. See the module docs for why this
/// is never reached through the catalog today.
fn is_dropin(path: &FPath) -> Option<String> {
    let parent = path.parent()?;
    let dir_name = parent.file_name()?;
    let base = dir_name.strip_suffix(".service.d")?;
    Some(format!("{base}.service"))
}

fn systemd_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let (entries, unparsed) = ini::parse(bytes);
    let dropin_target = is_dropin(path);
    let service_name = dropin_target.clone().unwrap_or_else(|| {
        path.file_name().and_then(|n| n.strip_suffix(".service")).unwrap_or("").to_string()
    });
    let mut out = Vec::new();
    for entry in &entries {
        let mut data = new_record(host, Kind::Systemd, source, acquisition);
        base_fields(&mut data, path, definition, Kind::Systemd);
        data.set(field::LINE_NUMBER, entry.line as u64);
        data.set(field::UNIT_KEY, format!("{}.{}", entry.section, entry.key));
        data.set(field::UNIT_VALUE, entry.value.clone());
        if !service_name.is_empty() {
            data.set(SERVICE_NAME, service_name.clone());
        }
        data.set(field::IS_DROPIN, dropin_target.is_some());
        if let Some(target) = &dropin_target {
            data.set(field::DROPIN_TARGET, target.clone());
        }
        out.push(Ok(data));
    }
    for bad in unparsed {
        out.push(Err(ForensicError::invalid_format(
            "systemd unit file",
            format!("line {}: not a [Section] header or key=value line: {:?}", bad.line, bad.text),
        )
        .with_path(path.to_owned())));
    }
    out
}

/// `S20apache2` -> `('S', 20, "apache2")`, `K80apache2` -> `('K', 80, "apache2")`. `None` for a
/// name that doesn't follow the `rc*.d` priority-prefix convention (a plain `/etc/init.d/*`
/// script, for instance).
fn parse_rcd_filename(name: &str) -> Option<(char, u32, &str)> {
    let action = name.chars().next()?;
    if action != 'S' && action != 'K' {
        return None;
    }
    let rest = &name[1..];
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let seq: u32 = rest[..digits].parse().ok()?;
    let target = &rest[digits..];
    if target.is_empty() {
        None
    } else {
        Some((action, seq, target))
    }
}

/// The `### BEGIN INIT INFO` / `### END INIT INFO` LSB header block, as its raw `Key: value`
/// pairs (in file order — `Provides`, `Required-Start`, `Required-Stop`, `Default-Start`,
/// `Default-Stop`, `Short-Description`, ... keep whatever keys the script actually has). `None`
/// when the script has no such block, which is common for plain SysV scripts.
fn parse_lsb_header(text: &str) -> Option<BTreeMap<String, String>> {
    let start = text.find("### BEGIN INIT INFO")?;
    let end_marker = text[start..].find("### END INIT INFO")?;
    let block = &text[start..start + end_marker];
    let mut map = BTreeMap::new();
    for line in block.lines() {
        let line = line.trim_start_matches('#').trim();
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Some(map)
}

fn rc_script_record(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    kind: Kind,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicData {
    let mut data = new_record(host, kind, source, acquisition);
    base_fields(&mut data, path, definition, kind);
    let filename = path.file_name().unwrap_or("");
    data.set(field::SCRIPT_NAME, filename.to_string());

    let mut service_name = filename.to_string();
    if let Some((action, seq, target)) = parse_rcd_filename(filename) {
        data.set(field::RC_ACTION, if action == 'S' { "start" } else { "stop" });
        data.set(field::RC_SEQUENCE, seq as u64);
        service_name = target.to_string();
    }

    let text = String::from_utf8_lossy(bytes);
    match parse_lsb_header(&text) {
        Some(header) => {
            data.set(field::LSB_HAS_HEADER, true);
            if let Some(provides) = header.get("Provides") {
                service_name = provides.clone();
                data.set(
                    field::LSB_PROVIDES,
                    text_owned_list(provides),
                );
            }
            if let Some(v) = header.get("Required-Start") {
                data.set(field::LSB_REQUIRED_START, text_owned_list(v));
            }
            if let Some(v) = header.get("Required-Stop") {
                data.set(field::LSB_REQUIRED_STOP, text_owned_list(v));
            }
            if let Some(v) = header.get("Default-Start") {
                data.set(field::LSB_DEFAULT_START, text_owned_list(v));
            }
            if let Some(v) = header.get("Default-Stop") {
                data.set(field::LSB_DEFAULT_STOP, text_owned_list(v));
            }
            if let Some(v) = header.get("Short-Description") {
                data.set(field::LSB_SHORT_DESCRIPTION, v.clone());
            }
        }
        None => {
            data.set(field::LSB_HAS_HEADER, false);
        }
    }
    data.set(SERVICE_NAME, service_name);
    data
}

fn text_owned_list(whitespace_separated: &str) -> Vec<Text> {
    whitespace_separated
        .split_whitespace()
        .map(|s| text_owned(s.to_string()))
        .collect()
}

/// One `key op value` line inside an xinetd `service <name> { ... }` or `defaults { ... }`
/// block, or a top-level directive (`includedir ...`) outside any block.
fn xinetd_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let lines: Vec<text::Line<'_>> = text::lines(bytes)
        .into_iter()
        .filter(|l| {
            let t = l.text();
            let t = t.trim();
            !(t.is_empty() || t.starts_with('#'))
        })
        .collect();
    let mut out = Vec::new();
    let mut block: Option<(String, Option<String>)> = None; // (block_type, block_name)
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let raw = line.text();
        let trimmed = raw.trim();
        if block.is_none() {
            // The opening brace may share the header's line (`service ssh {`) or follow it on
            // its own (the more common real-world xinetd style: header, then a lone `{`).
            let (header, brace_here) = match trimmed.strip_suffix('{') {
                Some(h) => (Some(h.trim()), true),
                None => (None, false),
            };
            let opens_next = !brace_here && lines.get(i + 1).map(|l| l.text().trim() == "{").unwrap_or(false);
            if brace_here || opens_next {
                let header_text = header.unwrap_or(trimmed);
                let tokens: Vec<&str> = header_text.split_whitespace().collect();
                let block_type = tokens.first().map(|s| s.to_string()).unwrap_or_default();
                let block_name = tokens.get(1).map(|s| s.to_string());
                block = Some((block_type, block_name));
                i += if opens_next { 2 } else { 1 };
                continue;
            }
            // A top-level directive outside any block (e.g. `includedir /etc/xinetd.d`): kept,
            // not dropped, but not modeled further.
            let mut data = new_record(host, Kind::Xinetd, source, acquisition);
            base_fields(&mut data, path, definition, Kind::Xinetd);
            data.set(field::LINE_NUMBER, line.number as u64);
            data.set(field::RAW_LINE, trimmed.to_string());
            out.push(Ok(data));
            i += 1;
            continue;
        }
        if trimmed == "}" {
            block = None;
            i += 1;
            continue;
        }
        let (block_type, block_name) = block.clone().unwrap_or_default();
        let (key, op, value) = if let Some((k, v)) = trimmed.split_once("+=") {
            (k.trim(), "+=", v.trim())
        } else if let Some((k, v)) = trimmed.split_once("-=") {
            (k.trim(), "-=", v.trim())
        } else if let Some((k, v)) = trimmed.split_once('=') {
            (k.trim(), "=", v.trim())
        } else {
            out.push(Err(ForensicError::invalid_format(
                "xinetd line",
                format!("line {}: expected key = value inside a block, got {trimmed:?}", line.number),
            )
            .with_path(path.to_owned())));
            i += 1;
            continue;
        };
        let mut data = new_record(host, Kind::Xinetd, source, acquisition);
        base_fields(&mut data, path, definition, Kind::Xinetd);
        data.set(field::LINE_NUMBER, line.number as u64);
        data.set(field::XINETD_BLOCK_TYPE, block_type.clone());
        if let Some(name) = &block_name {
            data.set(SERVICE_NAME, name.clone());
        }
        data.set(field::XINETD_KEY, key.to_string());
        data.set(field::XINETD_OPERATOR, op);
        data.set(field::XINETD_VALUE, value.to_string());
        out.push(Ok(data));
        i += 1;
    }
    out
}

/// Emits one [`ForensicData`] per systemd unit directive, SysV/LSB init script and xinetd
/// service directive the run's [`ArtifactCatalog`] locates for [`DEFINITIONS`]. Follows
/// [`crate::unix::utmp::UtmpParserFactory`]'s pattern: stateless (`&self`), deduped by path, one
/// [`SourceHandle`] per real file, never panics on evidence.
pub struct UnitsParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for UnitsParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> =
            DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux service definitions: systemd, SysV, LSB and xinetd",
                "Emits one record per systemd unit directive, SysV/LSB init script and xinetd \
                 service directive, from every location the artifact catalog resolves for \
                 LinuxSystemdServices, LinuxServices, LinuxSysVInit, LinuxLSBInit and \
                 LinuxXinetd. Reports systemd drop-ins as overrides rather than merging them.",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![
                Artifact::Linux(LinuxArtifacts::Service(LinuxService::SystemD)),
                Artifact::Linux(LinuxArtifacts::Service(LinuxService::SysV)),
                Artifact::Linux(LinuxArtifacts::Service(LinuxService::InitD)),
                Artifact::Linux(LinuxArtifacts::Service(LinuxService::Other("xinetd".to_string()))),
            ])
            .with_requirements(requirements),
        }
    }
}

impl UnitsParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

struct Target {
    path: FPathBuf,
    definition: String,
    kind: Kind,
    source: SourceHandle,
}

impl ArtifactParserFactory for UnitsParserFactory {
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
                "ArtifactCatalog required: this parser locates service files by artifact \
                 definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        let mut targets: BTreeMap<FPathBuf, (String, Kind)> = BTreeMap::new();
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
                if file.directory || targets.contains_key(&file.path) {
                    continue;
                }
                let leaf = file.artifact.as_ref();
                let Some(kind) = classify(leaf) else {
                    debug!("{PARSER_ID}: {}: unrecognized leaf definition {leaf}", file.path);
                    continue;
                };
                targets.insert(file.path.clone(), (leaf.to_string(), kind));
            }
        }

        let targets: Vec<Target> = targets
            .into_iter()
            .map(|(path, (definition, kind))| {
                let source = ctx.register_source(SourceKey::Path(path.as_str().to_string()));
                Target { path, definition, kind, source }
            })
            .collect();

        Ok(ParserRun::push(move |out| {
            for item in head {
                if out.emit(item).is_stop() {
                    return Ok(());
                }
            }
            for target in targets {
                if cancellation.is_cancelled() {
                    return Ok(());
                }
                let bytes = match read_file(fs.as_ref(), target.path.as_path()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        if out.emit(Err(e)).is_stop() {
                            return Ok(());
                        }
                        continue;
                    }
                };
                let items: Vec<ForensicResult<ForensicData>> = match target.kind {
                    Kind::Systemd => systemd_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    ),
                    Kind::SysV | Kind::Lsb => vec![Ok(rc_script_record(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        target.kind,
                        &target.source,
                        acquisition,
                    ))],
                    Kind::Xinetd => xinetd_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    ),
                };
                for item in items {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    if out.emit(item).is_stop() {
                        return Ok(());
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
    fn dropin_paths_are_recognized_and_resolve_their_target_unit() {
        assert_eq!(
            is_dropin(FPath::new("etc/systemd/system/sshd.service.d/override.conf")),
            Some("sshd.service".to_string())
        );
        assert_eq!(is_dropin(FPath::new("etc/systemd/system/sshd.service")), None);
    }

    #[test]
    fn rcd_filenames_decode_action_and_sequence() {
        assert_eq!(parse_rcd_filename("S20apache2"), Some(('S', 20, "apache2")));
        assert_eq!(parse_rcd_filename("K80apache2"), Some(('K', 80, "apache2")));
        assert_eq!(parse_rcd_filename("apache2"), None);
    }

    #[test]
    fn lsb_header_block_is_parsed_into_key_value_pairs() {
        let script = "#!/bin/sh\n### BEGIN INIT INFO\n# Provides:          apache2\n# Required-Start:    $local_fs $network\n# Default-Start:      2 3 4 5\n# Short-Description:  Apache2 web server\n### END INIT INFO\necho hi\n";
        let header = parse_lsb_header(script).unwrap();
        assert_eq!(header.get("Provides"), Some(&"apache2".to_string()));
        assert_eq!(header.get("Required-Start"), Some(&"$local_fs $network".to_string()));
        assert_eq!(header.get("Default-Start"), Some(&"2 3 4 5".to_string()));
    }

    #[test]
    fn a_script_without_a_header_is_still_reported_with_has_header_false() {
        assert!(parse_lsb_header("#!/bin/sh\necho hi\n").is_none());
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::*;

    fn definition(name: &'static str, source: ArtifactSource) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry { source, supported_os: Cow::Borrowed(&[]) }]),
            supported_os: Cow::Borrowed(&[Os::Linux]),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn file_def(name: &'static str, paths: &'static [Text]) -> ArtifactDefinition {
        definition(
            name,
            ArtifactSource::File { paths: Cow::Borrowed(paths), separator: Separator::Slash },
        )
    }

    fn catalog() -> Arc<dyn ArtifactCatalog> {
        let defs = vec![
            file_def("LinuxSystemdServices", &[Cow::Borrowed("/etc/systemd/system/*.service")]),
            definition(
                "LinuxServices",
                ArtifactSource::Group {
                    names: Cow::Borrowed(&[
                        Cow::Borrowed("LinuxXinetd"),
                        Cow::Borrowed("LinuxLSBInit"),
                        Cow::Borrowed("LinuxSysVInit"),
                        Cow::Borrowed("LinuxSystemdServices"),
                    ]),
                },
            ),
            file_def(
                "LinuxSysVInit",
                &[Cow::Borrowed("/etc/rc.local"), Cow::Borrowed("/etc/rc*.d/*"), Cow::Borrowed("/etc/rc.d/init.d/*")],
            ),
            file_def("LinuxLSBInit", &[Cow::Borrowed("/etc/init.d/*")]),
            file_def(
                "LinuxXinetd",
                &[Cow::Borrowed("/etc/xinetd.conf"), Cow::Borrowed("/etc/xinetd.d/*")],
            ),
        ];
        Arc::new(SliceCatalog::new(defs).unwrap())
    }

    fn sources(vfs: InMemoryVirtualFileSystem) -> TriageSources {
        TriageSources::builder()
            .vfs(Arc::new(vfs))
            .acquisition(Acquisition::ImageRead)
            .catalog(catalog())
            .build()
    }

    fn run(sources: &TriageSources) -> Vec<ForensicResult<ForensicData>> {
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(sources, &triage, &cancellation);
        let parser = UnitsParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = UnitsParserFactory::new();
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
    fn a_systemd_service_unit_emits_one_record_per_directive() {
        let bytes = b"[Unit]\nDescription=Example\n\n[Service]\nExecStart=/usr/bin/example\nUser=nobody\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/systemd/system/example.service", bytes.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(items.iter().all(|i| i.is_ok()));
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.artifact() == &Artifact::Linux(LinuxArtifacts::Service(LinuxService::SystemD))));
        assert!(records.iter().all(|r| field(r, SERVICE_NAME) == Some("example")));
        assert!(records.iter().any(|r| field(r, field::UNIT_KEY) == Some("Service.ExecStart")));
    }

    #[test]
    fn an_lsb_init_script_header_is_parsed() {
        let script = b"#!/bin/sh\n### BEGIN INIT INFO\n# Provides:          apache2\n# Default-Start:     2 3 4 5\n### END INIT INFO\nexit 0\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/init.d/apache2", script.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], SERVICE_NAME), Some("apache2"));
        assert_eq!(records[0].artifact(), &Artifact::Linux(LinuxArtifacts::Service(LinuxService::InitD)));
    }

    #[test]
    fn a_sysv_rcd_symlink_decodes_start_stop_sequence_from_its_filename() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/rc2.d/S20apache2", b"#!/bin/sh\nexit 0\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::RC_ACTION), Some("start"));
        assert_eq!(records[0].field_as_u64(field::RC_SEQUENCE), Some(20));
        assert_eq!(records[0].artifact(), &Artifact::Linux(LinuxArtifacts::Service(LinuxService::SysV)));
    }

    #[test]
    fn xinetd_service_blocks_emit_one_record_per_key() {
        let bytes = b"service ssh\n{\n    disable = no\n    server = /usr/sbin/sshd\n}\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/xinetd.d/ssh", bytes.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(items.iter().all(|i| i.is_ok()));
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| field(r, SERVICE_NAME) == Some("ssh")));
        assert!(records.iter().any(|r| field(r, field::XINETD_KEY) == Some("server")
            && field(r, field::XINETD_VALUE) == Some("/usr/sbin/sshd")));
        assert!(records
            .iter()
            .all(|r| r.artifact() == &Artifact::Linux(LinuxArtifacts::Service(LinuxService::Other("xinetd".to_string())))));
    }

    #[test]
    fn a_malformed_xinetd_line_inside_a_block_is_an_err_item() {
        let bytes = b"service ssh\n{\n    not a valid directive\n}\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/xinetd.d/ssh", bytes.to_vec());
        let items = run(&sources(vfs));
        assert!(items.iter().any(|i| i.is_err()));
    }

    #[test]
    fn a_file_reached_only_through_the_group_definition_is_still_classified_precisely() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/init.d/cron", b"#!/bin/sh\nexit 0\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], ARTIFACT_DEFINITION), Some("LinuxLSBInit"));
    }
}
