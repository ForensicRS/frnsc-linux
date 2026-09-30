//! OS release metadata, hostname, timezone and fstab, and [`IdentityParserFactory`], the
//! [`ArtifactParserFactory`] that resolves `LinuxReleaseInfo`/`LinuxDistributionRelease`/
//! `LinuxHostnameFile`/`LinuxTimezoneFile`/`LinuxFstab`/`LinuxSystemdOSRelease` (plus
//! `LinuxLocalTime`, see below) through the run's artifact catalog (no hardcoded paths) and
//! emits `Artifact::Linux(LinuxArtifacts::Other(_))` records.
//!
//! # `LinuxReleaseInfo` is a router, not a fourth file format
//!
//! `LinuxReleaseInfo` is a *group* definition in the KB: it re-resolves
//! `LinuxDistributionRelease`, `LinuxLSBRelease` and `LinuxSystemdOSRelease` and contributes no
//! files of its own. Every file this module sees is classified by its real, resolved leaf
//! definition ([`ResolvedFile::artifact`]), never by `"LinuxReleaseInfo"` directly — the same
//! discipline [`crate::schedule`] and [`crate::units`] use for their own group definitions.
//! `LinuxLSBRelease` (`/etc/lsb-release`) reaches this module only through that group: it is not
//! independently declared, because the issue's own definition list does not name it, but its
//! format is the same `KEY=value` shell-sourceable shape as `os-release`, so [`classify`] routes
//! it to the same reader.
//!
//! # `LinuxLocalTime` is declared even though the issue's table does not name it
//!
//! The issue's own format notes require resolving `/etc/timezone` **vs** `/etc/localtime` ("the
//! latter is a binary tzfile or a symlink — resolve and report which"), but `/etc/localtime` has
//! no entry in this module's six-name table — only `LinuxTimezoneFile` (`/etc/timezone`, plain
//! text) does. The KB has a real definition for it, `LinuxLocalTime`, so it is declared here too
//! rather than either skipping half of an explicit requirement or reaching for a hardcoded path
//! (which the issue rules out just as firmly). See `timezone_records` for how the two are told
//! apart once resolved.
//!
//! # A real gap: this VFS abstraction has no way to read a symlink's target
//!
//! [`forensic_rs::traits::vfs::VMetadata::is_symlink`] says *whether* `/etc/localtime` is a
//! symlink, but neither [`forensic_rs::traits::vfs::FileSystem`] nor its `PathAttributes`
//! extension exposes the link target text, and the in-memory test double
//! (`InMemoryVirtualFileSystem`) has no symlink support to probe the question against either.
//! So a symlinked `/etc/localtime` is reported as `format: "symlink"` with no target field —
//! never a guessed path — and this is recorded as a `frnsc-linux`/forensic-rs gap in the
//! workspace `FINDINGS.md`, not worked around locally.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::prelude::*;

/// Registration id of [`IdentityParserFactory`].
pub const PARSER_ID: &str = "linux.identity";

/// The ForensicArtifacts definitions this parser declares. The first six are the issue's own
/// list, in its order; `LinuxLocalTime` is appended — see the module docs for why.
pub const DEFINITIONS: &[&str] = &[
    "LinuxReleaseInfo",
    "LinuxDistributionRelease",
    "LinuxHostnameFile",
    "LinuxTimezoneFile",
    "LinuxFstab",
    "LinuxSystemdOSRelease",
    "LinuxLocalTime",
];

mod field {
    pub const KIND: &str = "linux.identity.kind";
    pub const LINE_NUMBER: &str = "linux.identity.line_number";
    pub const KEY: &str = "linux.identity.key";
    pub const VALUE: &str = "linux.identity.value";
    pub const RAW_LINE: &str = "linux.identity.raw_line";
    pub const RELEASE_TEXT: &str = "linux.identity.release_text";
    pub const TIMEZONE_FORMAT: &str = "linux.identity.timezone.format";
    pub const TIMEZONE_NAME: &str = "linux.identity.timezone.name";
    pub const TIMEZONE_TZIF_VERSION: &str = "linux.identity.timezone.tzif_version";
    pub const FSTAB_DEVICE: &str = "linux.identity.fstab.device";
    pub const FSTAB_MOUNTPOINT: &str = "linux.identity.fstab.mountpoint";
    pub const FSTAB_FSTYPE: &str = "linux.identity.fstab.fstype";
    pub const FSTAB_OPTIONS: &str = "linux.identity.fstab.options";
    pub const FSTAB_DUMP: &str = "linux.identity.fstab.dump";
    pub const FSTAB_PASS: &str = "linux.identity.fstab.pass";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    OsRelease,
    DistributionRelease,
    Hostname,
    Timezone,
    Fstab,
}

fn classify(definition: &str) -> Option<Kind> {
    match definition {
        "LinuxSystemdOSRelease" | "LinuxLSBRelease" => Some(Kind::OsRelease),
        "LinuxDistributionRelease" => Some(Kind::DistributionRelease),
        "LinuxHostnameFile" => Some(Kind::Hostname),
        "LinuxTimezoneFile" | "LinuxLocalTime" => Some(Kind::Timezone),
        "LinuxFstab" => Some(Kind::Fstab),
        _ => None,
    }
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::OsRelease => "os_release",
        Kind::DistributionRelease => "distribution_release",
        Kind::Hostname => "hostname",
        Kind::Timezone => "timezone",
        Kind::Fstab => "fstab",
    }
}

fn new_record(host: &str, kind: Kind, source: &SourceHandle, acquisition: Acquisition) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    ForensicData::new(
        host,
        Artifact::Linux(LinuxArtifacts::Other(kind_label(kind).to_string())),
        provenance,
    )
}

fn base_fields(data: &mut ForensicData, path: &FPath, definition: &str, kind: Kind) {
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition.to_string());
    data.set(field::KIND, kind_label(kind));
}

/// Parses a `KEY=value` shell-sourceable line (`os-release`, `lsb-release`): `KEY` is a bare
/// identifier, `value` may be `"double"`- or `'single'`-quoted (the quotes are stripped) or
/// bare. `None` for anything else — a comment, a blank line, or a line that just isn't this
/// shape.
fn parse_shell_kv(trimmed: &str) -> Option<(String, String)> {
    let (k, v) = trimmed.split_once('=')?;
    let k = k.trim();
    if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let v = v.trim();
    let unquoted = if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        &v[1..v.len() - 1]
    } else {
        v
    };
    Some((k.to_string(), unquoted.to_string()))
}

fn os_release_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let mut out = Vec::new();
    for line in crate::text::lines(bytes) {
        let raw = line.text();
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_shell_kv(trimmed) {
            Some((key, value)) => {
                let mut data = new_record(host, Kind::OsRelease, source, acquisition);
                base_fields(&mut data, path, definition, Kind::OsRelease);
                data.set(field::LINE_NUMBER, line.number as u64);
                data.set(field::KEY, key);
                data.set(field::VALUE, value);
                out.push(Ok(data));
            }
            None => out.push(Err(ForensicError::invalid_format(
                "os-release line",
                format!("line {}: expected KEY=value, got {trimmed:?}", line.number),
            )
            .with_path(path.to_owned()))),
        }
    }
    out
}

fn distribution_release_record(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicData {
    let mut data = new_record(host, Kind::DistributionRelease, source, acquisition);
    base_fields(&mut data, path, definition, Kind::DistributionRelease);
    data.set(field::RELEASE_TEXT, String::from_utf8_lossy(bytes).trim().to_string());
    data
}

fn hostname_record(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicData {
    let mut data = new_record(host, Kind::Hostname, source, acquisition);
    base_fields(&mut data, path, definition, Kind::Hostname);
    data.set(HOST_HOSTNAME, String::from_utf8_lossy(bytes).trim().to_string());
    data
}

/// `/etc/timezone` (text) vs `/etc/localtime` (symlink or binary `TZif`), told apart by which
/// definition actually matched — never by guessing from content alone. See the module docs for
/// why the symlink case cannot carry a target.
fn timezone_records(
    host: &str,
    definition: &str,
    path: &FPath,
    fs: &dyn FileSystem,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    if definition == "LinuxTimezoneFile" {
        let bytes = match read_file(fs, path) {
            Ok(b) => b,
            Err(e) => return vec![Err(e)],
        };
        let mut data = new_record(host, Kind::Timezone, source, acquisition);
        base_fields(&mut data, path, definition, Kind::Timezone);
        data.set(field::TIMEZONE_FORMAT, "text");
        data.set(field::TIMEZONE_NAME, String::from_utf8_lossy(&bytes).trim().to_string());
        return vec![Ok(data)];
    }

    // `LinuxLocalTime` (`/etc/localtime`): check the metadata before touching content, so a
    // symlink is reported as one without assuming `open()` follows or refuses it.
    let meta = match fs.metadata(path) {
        Ok(m) => m,
        Err(e) => return vec![Err(e)],
    };
    if meta.is_symlink() {
        let mut data = new_record(host, Kind::Timezone, source, acquisition);
        base_fields(&mut data, path, definition, Kind::Timezone);
        data.set(field::TIMEZONE_FORMAT, "symlink");
        return vec![Ok(data)];
    }
    let bytes = match read_file(fs, path) {
        Ok(b) => b,
        Err(e) => return vec![Err(e)],
    };
    let mut data = new_record(host, Kind::Timezone, source, acquisition);
    base_fields(&mut data, path, definition, Kind::Timezone);
    if bytes.len() >= 5 && &bytes[0..4] == b"TZif" {
        data.set(field::TIMEZONE_FORMAT, "binary_tzfile");
        data.set(field::TIMEZONE_TZIF_VERSION, (bytes[4] as char).to_string());
    } else {
        data.set(field::TIMEZONE_FORMAT, "unknown");
    }
    vec![Ok(data)]
}

fn fstab_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let mut out = Vec::new();
    for line in crate::text::lines(bytes) {
        let raw = line.text();
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 4 {
            out.push(Err(ForensicError::invalid_format(
                "fstab line",
                format!(
                    "line {}: expected at least device, mountpoint, fstype and options, got {} token(s)",
                    line.number,
                    tokens.len()
                ),
            )
            .with_path(path.to_owned())));
            continue;
        }
        let mut data = new_record(host, Kind::Fstab, source, acquisition);
        base_fields(&mut data, path, definition, Kind::Fstab);
        data.set(field::LINE_NUMBER, line.number as u64);
        data.set(field::RAW_LINE, trimmed.to_string());
        data.set(field::FSTAB_DEVICE, tokens[0].to_string());
        data.set(field::FSTAB_MOUNTPOINT, tokens[1].to_string());
        data.set(field::FSTAB_FSTYPE, tokens[2].to_string());
        data.set(field::FSTAB_OPTIONS, tokens[3].to_string());

        // A present-but-unparseable dump/pass token is not the same evidence as a legitimately
        // short line: the field is left unset either way, but only the former is worth a
        // `Finding` — see the module's "keep what was read" convention (raw_line above records
        // the exact text regardless).
        let mut token_errors = Vec::new();
        if let Some(token) = tokens.get(4) {
            match token.parse::<i64>() {
                Ok(dump) => data.set(field::FSTAB_DUMP, dump),
                Err(_) => token_errors.push(
                    ForensicError::invalid_format(
                        "fstab line",
                        format!("line {}: dump field {token:?} is present but not an integer", line.number),
                    )
                    .with_path(path.to_owned()),
                ),
            }
        }
        if let Some(token) = tokens.get(5) {
            match token.parse::<i64>() {
                Ok(pass) => data.set(field::FSTAB_PASS, pass),
                Err(_) => token_errors.push(
                    ForensicError::invalid_format(
                        "fstab line",
                        format!("line {}: pass field {token:?} is present but not an integer", line.number),
                    )
                    .with_path(path.to_owned()),
                ),
            }
        }
        out.push(Ok(data));
        out.extend(token_errors.into_iter().map(Err));
    }
    out
}

/// Emits one [`ForensicData`] per `os-release`/`lsb-release` key, distribution-release file,
/// hostname, timezone resolution and fstab row the run's [`ArtifactCatalog`] locates for
/// [`DEFINITIONS`]. Follows [`crate::unix::utmp::UtmpParserFactory`]'s pattern: stateless
/// (`&self`), deduped by path, one [`SourceHandle`] per real file, never panics on evidence.
pub struct IdentityParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for IdentityParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> =
            DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux host identity: OS release, hostname, timezone and fstab",
                "Emits one record per os-release/lsb-release key, distribution-release file, \
                 hostname, timezone resolution and fstab row, from every location the artifact \
                 catalog resolves for LinuxReleaseInfo, LinuxDistributionRelease, \
                 LinuxHostnameFile, LinuxTimezoneFile, LinuxFstab, LinuxSystemdOSRelease and \
                 LinuxLocalTime.",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![
                Artifact::Linux(LinuxArtifacts::Other("os_release".to_string())),
                Artifact::Linux(LinuxArtifacts::Other("distribution_release".to_string())),
                Artifact::Linux(LinuxArtifacts::Other("hostname".to_string())),
                Artifact::Linux(LinuxArtifacts::Other("timezone".to_string())),
                Artifact::Linux(LinuxArtifacts::Other("fstab".to_string())),
            ])
            .with_requirements(requirements),
        }
    }
}

impl IdentityParserFactory {
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

impl ArtifactParserFactory for IdentityParserFactory {
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
                "ArtifactCatalog required: this parser locates identity files by artifact \
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
                let items: Vec<ForensicResult<ForensicData>> = if target.kind == Kind::Timezone {
                    timezone_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        fs.as_ref(),
                        &target.source,
                        acquisition,
                    )
                } else {
                    let bytes = match read_file(fs.as_ref(), target.path.as_path()) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            if out.emit(Err(e)).is_stop() {
                                return Ok(());
                            }
                            continue;
                        }
                    };
                    match target.kind {
                        Kind::OsRelease => os_release_records(
                            &host,
                            &target.definition,
                            target.path.as_path(),
                            &bytes,
                            &target.source,
                            acquisition,
                        ),
                        Kind::DistributionRelease => vec![Ok(distribution_release_record(
                            &host,
                            &target.definition,
                            target.path.as_path(),
                            &bytes,
                            &target.source,
                            acquisition,
                        ))],
                        Kind::Hostname => vec![Ok(hostname_record(
                            &host,
                            &target.definition,
                            target.path.as_path(),
                            &bytes,
                            &target.source,
                            acquisition,
                        ))],
                        Kind::Fstab => fstab_records(
                            &host,
                            &target.definition,
                            target.path.as_path(),
                            &bytes,
                            &target.source,
                            acquisition,
                        ),
                        Kind::Timezone => unreachable!("handled above"),
                    }
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
    fn parses_bare_and_quoted_shell_kv_lines() {
        assert_eq!(parse_shell_kv(r#"NAME="Ubuntu""#), Some(("NAME".to_string(), "Ubuntu".to_string())));
        assert_eq!(parse_shell_kv("ID=ubuntu"), Some(("ID".to_string(), "ubuntu".to_string())));
        assert_eq!(parse_shell_kv("VERSION_ID='22.04'"), Some(("VERSION_ID".to_string(), "22.04".to_string())));
        assert_eq!(parse_shell_kv("not a kv line"), None);
    }

    #[test]
    fn classifies_lsb_release_the_same_as_os_release() {
        assert_eq!(classify("LinuxSystemdOSRelease"), Some(Kind::OsRelease));
        assert_eq!(classify("LinuxLSBRelease"), Some(Kind::OsRelease));
        assert_eq!(classify("LinuxReleaseInfo"), None);
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
            definition(
                "LinuxReleaseInfo",
                ArtifactSource::Group {
                    names: Cow::Borrowed(&[
                        Cow::Borrowed("LinuxDistributionRelease"),
                        Cow::Borrowed("LinuxLSBRelease"),
                        Cow::Borrowed("LinuxSystemdOSRelease"),
                    ]),
                },
            ),
            file_def("LinuxDistributionRelease", &[Cow::Borrowed("/etc/redhat-release")]),
            file_def("LinuxHostnameFile", &[Cow::Borrowed("/etc/hostname")]),
            file_def("LinuxTimezoneFile", &[Cow::Borrowed("/etc/timezone")]),
            file_def("LinuxFstab", &[Cow::Borrowed("/etc/fstab")]),
            file_def(
                "LinuxSystemdOSRelease",
                &[Cow::Borrowed("/etc/os-release"), Cow::Borrowed("/usr/lib/os-release")],
            ),
            file_def("LinuxLocalTime", &[Cow::Borrowed("/etc/localtime")]),
            file_def("LinuxLSBRelease", &[Cow::Borrowed("/etc/lsb-release")]),
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
        let parser = IdentityParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = IdentityParserFactory::new();
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
    fn os_release_emits_one_record_per_key() {
        let bytes = b"NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/os-release", bytes.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(items.iter().all(|i| i.is_ok()));
        assert_eq!(records.len(), 3);
        assert!(records.iter().any(|r| field(r, field::KEY) == Some("NAME") && field(r, field::VALUE) == Some("Ubuntu")));
    }

    #[test]
    fn lsb_release_reached_only_through_the_group_is_parsed_as_os_release_shape() {
        let bytes = b"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/lsb-release", bytes.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(field(records[0], ARTIFACT_DEFINITION), Some("LinuxLSBRelease"));
    }

    #[test]
    fn hostname_file_sets_ecs_host_hostname() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/hostname", b"web-01\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], HOST_HOSTNAME), Some("web-01"));
    }

    #[test]
    fn timezone_text_file_is_reported_as_text_with_its_name() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/timezone", b"America/New_York\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::TIMEZONE_FORMAT), Some("text"));
        assert_eq!(field(records[0], field::TIMEZONE_NAME), Some("America/New_York"));
    }

    #[test]
    fn a_binary_localtime_file_is_recognized_by_its_tzif_magic() {
        let mut bytes = b"TZif".to_vec();
        bytes.push(b'2');
        bytes.extend_from_slice(&[0u8; 40]);
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/localtime", bytes);
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::TIMEZONE_FORMAT), Some("binary_tzfile"));
        assert_eq!(field(records[0], field::TIMEZONE_TZIF_VERSION), Some("2"));
    }

    #[test]
    fn fstab_rows_are_split_into_their_six_fields() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/fstab", b"/dev/sda1 / ext4 defaults 0 1\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::FSTAB_DEVICE), Some("/dev/sda1"));
        assert_eq!(field(records[0], field::FSTAB_MOUNTPOINT), Some("/"));
        assert_eq!(field(records[0], field::FSTAB_FSTYPE), Some("ext4"));
        assert_eq!(records[0].field_as_u64(field::FSTAB_PASS), Some(1));
    }

    #[test]
    fn a_malformed_fstab_line_is_an_err_item() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/fstab", b"a b c\n".to_vec());
        let items = run(&sources(vfs));
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }

    #[test]
    fn fstab_rows_keep_the_raw_line() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/fstab", b"/dev/sda1 / ext4 defaults 0 1\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::RAW_LINE), Some("/dev/sda1 / ext4 defaults 0 1"));
    }

    #[test]
    fn a_present_but_unparseable_fstab_pass_token_is_an_err_item_not_a_silently_dropped_field() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/fstab", b"/dev/sda1 / ext4 defaults 0 X\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        // The row is still emitted with everything that did parse; the malformed `pass` token is
        // indistinguishable from an absent one in the field itself, but the raw line is kept and
        // an Err item surfaces the malformed token rather than silently dropping it.
        assert!(records[0].field_as_u64(field::FSTAB_PASS).is_none());
        assert_eq!(field(records[0], field::RAW_LINE), Some("/dev/sda1 / ext4 defaults 0 X"));
        assert!(items.iter().any(|i| i.is_err()));
    }
}
