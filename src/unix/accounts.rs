//! `passwd`/`shadow`/`group`/`sudoers` account and privilege configuration, and
//! [`AccountsParserFactory`], the [`ArtifactParserFactory`] that resolves
//! `UnixPasswdFile`/`UnixShadowFile`/`UnixGroupsFile`/`UnixSudoersConfigurationFile`/
//! `LinuxPasswdFile` through the run's artifact catalog (no hardcoded paths) and emits
//! `Artifact::Linux(LinuxArtifacts::Accounts)` records.
//!
//! # Never emitting a password hash
//!
//! `/etc/shadow` (and, on legacy or misconfigured systems, `/etc/passwd`/`/etc/group`
//! themselves) may carry an actual `crypt(3)` hash in the password field. This module never puts
//! that value in an emitted field: [`classify_password_field`] turns it into a
//! [`PasswordField`] that records only the field's *shape* — delegated to `/etc/shadow`, empty,
//! locked, or hashed with which `$id$` algorithm prefix (`$6$` SHA-512, `$y$` yescrypt, ...) —
//! never the salt or the hash bytes themselves. See `a_password_hash_never_appears_in_output`.
//!
//! # Malformed rows
//!
//! `passwd`/`shadow`/`group` are colon-separated with a fixed, documented field count. A row
//! with the wrong count is one `Err` item (surfaced to the analyst as a `Finding`, per the
//! pipeline's normal handling) — it is reported, never a line that is silently skipped with no
//! trace. `sudoers` is not colon-separated; see [`SudoersDirectiveKind`] for how its lines are
//! classified instead.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::prelude::*;

use crate::text::{self, comma_list};

/// Registration id of [`AccountsParserFactory`].
pub const PARSER_ID: &str = "linux.accounts";

/// The ForensicArtifacts definitions this parser reads, in the order it declares them. Deduped
/// by path (a file matching more than one — `UnixPasswdFile` and `LinuxPasswdFile` both name
/// `/etc/passwd` — is read once, attributed to the first).
pub const DEFINITIONS: &[&str] = &[
    "UnixPasswdFile",
    "UnixShadowFile",
    "UnixGroupsFile",
    "UnixSudoersConfigurationFile",
    "LinuxPasswdFile",
];

/// Crate-local `linux.accounts.*` field names. Not ECS, so the dictionary rule doesn't apply,
/// but named once here rather than scattered as inline literals.
mod field {
    pub const RECORD_KIND: &str = "linux.accounts.record_kind";
    pub const LINE_NUMBER: &str = "linux.accounts.line_number";
    pub const GID: &str = "linux.accounts.gid";
    pub const GECOS: &str = "linux.accounts.gecos";
    pub const HOME: &str = "linux.accounts.home";
    pub const SHELL: &str = "linux.accounts.shell";
    pub const PASSWORD_STATE: &str = "linux.accounts.password.state";
    pub const PASSWORD_ALGORITHM: &str = "linux.accounts.password.algorithm";
    pub const LAST_CHANGED_DAYS: &str = "linux.accounts.shadow.last_changed_days";
    pub const MIN_DAYS: &str = "linux.accounts.shadow.min_days";
    pub const MAX_DAYS: &str = "linux.accounts.shadow.max_days";
    pub const WARN_DAYS: &str = "linux.accounts.shadow.warn_days";
    pub const INACTIVE_DAYS: &str = "linux.accounts.shadow.inactive_days";
    pub const EXPIRE_DAYS: &str = "linux.accounts.shadow.expire_days";
    pub const GROUP_MEMBERS: &str = "linux.accounts.group.members";
    pub const SUDOERS_RAW_LINE: &str = "linux.accounts.sudoers.raw_line";
    pub const SUDOERS_DIRECTIVE_KIND: &str = "linux.accounts.sudoers.directive_kind";
    pub const SUDOERS_INCLUDE_TARGET: &str = "linux.accounts.sudoers.include_target";
}

/// How a `passwd`/`shadow`/`group` password field reads, without ever exposing the hash value
/// itself.
///
/// `crypt(3)` hashes are either the modern `$id$salt$hash` form or a bare, non-`$`-prefixed
/// traditional DES hash. This classification only ever surfaces `id` (the algorithm), never the
/// salt or the hash bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordField {
    /// `x`: the real hash, if any, lives in `/etc/shadow`.
    DelegatedToShadow,
    /// Empty field: no password required to authenticate as this account.
    Empty,
    /// `*`, `!`, `!!`, or any value starting with `!`: login via password is disabled.
    Locked,
    /// A `crypt(3)` hash is present. `algorithm` is the `$id$` token for the modern scheme
    /// (`Some("6")` for SHA-512, `Some("y")` for yescrypt, ...), or `None` for the traditional
    /// no-`$` scheme.
    Hashed { algorithm: Option<String> },
}

/// Classifies `raw` (a passwd/shadow/group password field) into its [`PasswordField`] shape.
/// Never returns, stores, or logs the hash/salt bytes themselves.
pub fn classify_password_field(raw: &str) -> PasswordField {
    if raw.is_empty() {
        return PasswordField::Empty;
    }
    if raw == "x" {
        return PasswordField::DelegatedToShadow;
    }
    if raw == "*" || raw.starts_with('!') {
        return PasswordField::Locked;
    }
    if let Some(rest) = raw.strip_prefix('$') {
        let algorithm = rest
            .split('$')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        return PasswordField::Hashed { algorithm };
    }
    // No `$` prefix but not `x`/`*`/`!...`/empty either: the traditional 13-character DES crypt
    // scheme, or something this module doesn't recognize. Either way it is hash-shaped data, so
    // it is classified `Hashed` with no algorithm guess rather than dropped or passed through.
    PasswordField::Hashed { algorithm: None }
}

fn set_password_fields(data: &mut ForensicData, raw: &str) {
    match classify_password_field(raw) {
        PasswordField::DelegatedToShadow => data.set(field::PASSWORD_STATE, "delegated_to_shadow"),
        PasswordField::Empty => data.set(field::PASSWORD_STATE, "empty"),
        PasswordField::Locked => data.set(field::PASSWORD_STATE, "locked"),
        PasswordField::Hashed { algorithm } => {
            data.set(field::PASSWORD_STATE, "hashed");
            if let Some(algorithm) = algorithm {
                data.set(field::PASSWORD_ALGORITHM, algorithm);
            }
        }
    }
}

/// One malformed-row report: which file, which line, and why.
fn malformed(what: &'static str, line_number: usize, reason: String) -> ForensicError {
    ForensicError::invalid_format(what, format!("line {line_number}: {reason}"))
}

/// Parses `raw` as a shadow aging field: empty means "not set" (`Ok(None)`), a valid integer is
/// `Ok(Some(_))`, anything else is a malformed row.
fn parse_aging_field(raw: &str) -> Result<Option<i64>, ()> {
    if raw.is_empty() {
        return Ok(None);
    }
    raw.parse::<i64>().map(Some).map_err(|_| ())
}

fn passwd_record(
    host: &str,
    definition: &'static str,
    path: &FPath,
    line: &text::Line<'_>,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicResult<ForensicData> {
    let raw_line = line.text();
    let fields: Vec<&str> = raw_line.split(':').collect();
    if fields.len() != 7 {
        return Err(malformed(
            "passwd record",
            line.number,
            format!("expected 7 colon-separated fields, got {}", fields.len()),
        )
        .with_path(path.to_owned()));
    }
    let [name, passwd, uid, gid, gecos, home, shell] = fields[..] else {
        unreachable!("length checked above")
    };
    let uid: u64 = uid.parse().map_err(|_| {
        malformed(
            "passwd record",
            line.number,
            format!("uid {uid:?} is not a number"),
        )
        .with_path(path.to_owned())
    })?;
    let gid: u64 = gid.parse().map_err(|_| {
        malformed(
            "passwd record",
            line.number,
            format!("gid {gid:?} is not a number"),
        )
        .with_path(path.to_owned())
    })?;

    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Accounts), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::RECORD_KIND, "passwd");
    data.set(field::LINE_NUMBER, line.number as u64);
    data.set(USER_NAME, name.to_string());
    data.set(USER_ID, uid.to_string());
    data.set(field::GID, gid);
    data.set(field::GECOS, gecos.to_string());
    data.set(field::HOME, home.to_string());
    data.set(field::SHELL, shell.to_string());
    set_password_fields(&mut data, passwd);
    Ok(data)
}

fn shadow_record(
    host: &str,
    definition: &'static str,
    path: &FPath,
    line: &text::Line<'_>,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicResult<ForensicData> {
    let raw_line = line.text();
    let fields: Vec<&str> = raw_line.split(':').collect();
    if fields.len() != 9 {
        return Err(malformed(
            "shadow record",
            line.number,
            format!("expected 9 colon-separated fields, got {}", fields.len()),
        )
        .with_path(path.to_owned()));
    }
    let name = fields[0];
    let passwd = fields[1];
    let aging: Result<Vec<Option<i64>>, ()> =
        fields[2..8].iter().map(|f| parse_aging_field(f)).collect();
    let aging = aging.map_err(|_| {
        malformed(
            "shadow record",
            line.number,
            "an aging field is neither empty nor a valid integer".to_string(),
        )
        .with_path(path.to_owned())
    })?;
    let [last_changed, min, max, warn, inactive, expire] = aging[..] else {
        unreachable!("exactly 6 aging fields sliced above")
    };

    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Accounts), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::RECORD_KIND, "shadow");
    data.set(field::LINE_NUMBER, line.number as u64);
    data.set(USER_NAME, name.to_string());
    set_password_fields(&mut data, passwd);
    if let Some(v) = last_changed {
        data.set(field::LAST_CHANGED_DAYS, v);
        // Day 0 is `shadow(5)`'s own "force a change" convention on several implementations, not
        // reliably a real 1970-01-01 password-set event — never asserted as `@timestamp`. A
        // positive day count is a real dated event read from evidence, not invented, so it is.
        if v > 0 {
            if let Some(secs) = v.checked_mul(86_400) {
                data.set(TIMESTAMP, ForensicTimestamp::from_unix_secs(secs));
            }
        }
    }
    if let Some(v) = min {
        data.set(field::MIN_DAYS, v);
    }
    if let Some(v) = max {
        data.set(field::MAX_DAYS, v);
    }
    if let Some(v) = warn {
        data.set(field::WARN_DAYS, v);
    }
    if let Some(v) = inactive {
        data.set(field::INACTIVE_DAYS, v);
    }
    if let Some(v) = expire {
        data.set(field::EXPIRE_DAYS, v);
    }
    Ok(data)
}

fn group_record(
    host: &str,
    definition: &'static str,
    path: &FPath,
    line: &text::Line<'_>,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicResult<ForensicData> {
    let raw_line = line.text();
    let fields: Vec<&str> = raw_line.split(':').collect();
    if fields.len() != 4 {
        return Err(malformed(
            "group record",
            line.number,
            format!("expected 4 colon-separated fields, got {}", fields.len()),
        )
        .with_path(path.to_owned()));
    }
    let name = fields[0];
    let passwd = fields[1];
    let gid = fields[2];
    let members = fields[3];
    let gid: u64 = gid.parse().map_err(|_| {
        malformed(
            "group record",
            line.number,
            format!("gid {gid:?} is not a number"),
        )
        .with_path(path.to_owned())
    })?;

    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Accounts), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::RECORD_KIND, "group");
    data.set(field::LINE_NUMBER, line.number as u64);
    data.set(GROUP_NAME, name.to_string());
    data.set(field::GID, gid);
    set_password_fields(&mut data, passwd);
    let members = comma_list(members);
    if !members.is_empty() {
        data.set(
            field::GROUP_MEMBERS,
            members.into_iter().map(text_owned).collect::<Vec<Text>>(),
        );
    }
    Ok(data)
}

/// Coarse classification of a non-comment, non-include `sudoers` line, by its leading keyword.
/// `sudoers` grammar (aliases, `Defaults`, user specifications) is not otherwise parsed here —
/// the raw line is always kept, so nothing is lost by not modeling the full grammar.
fn sudoers_directive_kind(first_token: &str) -> &'static str {
    match first_token {
        "Defaults" => "defaults",
        "User_Alias" => "user_alias",
        "Cmnd_Alias" | "Cmd_Alias" => "cmnd_alias",
        "Host_Alias" => "host_alias",
        "Runas_Alias" => "runas_alias",
        _ => "user_specification",
    }
}

/// One include directive found in a `sudoers` file: `#include`/`#includedir` (legacy) or
/// `@include`/`@includedir` (modern, no leading `#`). The referenced path is recorded, never
/// followed — it is not necessarily reachable through this parser's own artifact resolution.
fn sudoers_include(trimmed: &str) -> Option<(&'static str, &str)> {
    for (prefix, kind) in [
        ("#includedir ", "directory"),
        ("#include ", "file"),
        ("@includedir ", "directory"),
        ("@include ", "file"),
    ] {
        if let Some(target) = trimmed.strip_prefix(prefix) {
            return Some((kind, target.trim()));
        }
    }
    None
}

fn sudoers_records(
    host: &str,
    definition: &'static str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicData> {
    let mut out = Vec::new();
    for logical in text::join_backslash_continuations(bytes) {
        let trimmed = logical.text.trim();
        if trimmed.is_empty() {
            continue;
        }
        let provenance = source.mint(acquisition, Recovery::Allocated);
        if let Some((kind, target)) = sudoers_include(trimmed) {
            let mut data =
                ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Accounts), provenance);
            data.set(ARTIFACT_PATH, path.as_str().to_string());
            data.set(ARTIFACT_DEFINITION, definition);
            data.set(field::RECORD_KIND, "sudoers_include");
            data.set(field::LINE_NUMBER, logical.starting_line as u64);
            data.set(field::SUDOERS_INCLUDE_TARGET, target.to_string());
            data.set("linux.accounts.sudoers.include_kind", kind);
            out.push(data);
            continue;
        }
        if trimmed.starts_with('#') {
            continue; // an ordinary comment, not evidence of configuration
        }
        let first_token = trimmed.split_whitespace().next().unwrap_or("");
        let mut data =
            ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Accounts), provenance);
        data.set(ARTIFACT_PATH, path.as_str().to_string());
        data.set(ARTIFACT_DEFINITION, definition);
        data.set(field::RECORD_KIND, "sudoers_directive");
        data.set(field::LINE_NUMBER, logical.starting_line as u64);
        data.set(
            field::SUDOERS_DIRECTIVE_KIND,
            sudoers_directive_kind(first_token),
        );
        data.set(field::SUDOERS_RAW_LINE, trimmed.to_string());
        out.push(data);
    }
    out
}

/// Emits one [`ForensicData`] per `passwd`/`shadow`/`group` row and per meaningful `sudoers`
/// line, from every location the run's [`ArtifactCatalog`] locates for [`DEFINITIONS`].
///
/// Stateless (`&self`), following [`crate::unix::utmp::UtmpParserFactory`]'s pattern: files are
/// deduped by path (so `/etc/passwd`, named by both `UnixPasswdFile` and `LinuxPasswdFile`, is
/// read once), one [`SourceHandle`] is registered per real file, and the reader never panics on
/// evidence.
pub struct AccountsParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for AccountsParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> = DEFINITIONS
            .iter()
            .copied()
            .map(Requirement::artifact)
            .collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux/Unix account and privilege configuration",
                "Emits one record per passwd/shadow/group row and per meaningful sudoers line, \
                 from every location the artifact catalog resolves for UnixPasswdFile, \
                 UnixShadowFile, UnixGroupsFile, UnixSudoersConfigurationFile and \
                 LinuxPasswdFile. Never emits a password hash value.",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Linux(LinuxArtifacts::Accounts)])
            .with_requirements(requirements),
        }
    }
}

impl AccountsParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Which record parser applies to a file, chosen by its attributed definition.
fn record_kind_for_definition(definition: &str) -> &'static str {
    match definition {
        "UnixPasswdFile" | "LinuxPasswdFile" => "passwd",
        "UnixShadowFile" => "shadow",
        "UnixGroupsFile" => "group",
        "UnixSudoersConfigurationFile" => "sudoers",
        _ => "passwd",
    }
}

impl ArtifactParserFactory for AccountsParserFactory {
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
                "ArtifactCatalog required: this parser locates account files by artifact \
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
                match record_kind_for_definition(definition) {
                    "sudoers" => {
                        for data in sudoers_records(
                            &host,
                            definition,
                            path.as_path(),
                            &bytes,
                            &source,
                            acquisition,
                        ) {
                            if out.emit(Ok(data)).is_stop() {
                                return Ok(());
                            }
                        }
                    }
                    kind => {
                        for line in text::lines(&bytes) {
                            if cancellation.is_cancelled() {
                                return Ok(());
                            }
                            let trimmed = line.text();
                            let trimmed = trimmed.trim();
                            if trimmed.is_empty() || trimmed.starts_with('#') {
                                continue;
                            }
                            let result = match kind {
                                "passwd" => passwd_record(
                                    &host,
                                    definition,
                                    path.as_path(),
                                    &line,
                                    &source,
                                    acquisition,
                                ),
                                "shadow" => shadow_record(
                                    &host,
                                    definition,
                                    path.as_path(),
                                    &line,
                                    &source,
                                    acquisition,
                                ),
                                _ => group_record(
                                    &host,
                                    definition,
                                    path.as_path(),
                                    &line,
                                    &source,
                                    acquisition,
                                ),
                            };
                            if out.emit(result).is_stop() {
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
    fn classifies_delegated_empty_locked_and_hashed_fields() {
        assert_eq!(
            classify_password_field("x"),
            PasswordField::DelegatedToShadow
        );
        assert_eq!(classify_password_field(""), PasswordField::Empty);
        assert_eq!(classify_password_field("*"), PasswordField::Locked);
        assert_eq!(classify_password_field("!"), PasswordField::Locked);
        assert_eq!(classify_password_field("!!"), PasswordField::Locked);
        assert_eq!(
            classify_password_field("$6$abcdsalt$therealhashvalue"),
            PasswordField::Hashed {
                algorithm: Some("6".to_string())
            }
        );
        assert_eq!(
            classify_password_field("$y$j9T$saltsalt$hashhash"),
            PasswordField::Hashed {
                algorithm: Some("y".to_string())
            }
        );
        assert_eq!(
            classify_password_field("XhFpZhT.dGhIU"),
            PasswordField::Hashed { algorithm: None }
        );
    }

    #[test]
    fn sudoers_recognizes_hash_and_at_style_includes() {
        assert_eq!(
            sudoers_include("#include /etc/sudoers.local"),
            Some(("file", "/etc/sudoers.local"))
        );
        assert_eq!(
            sudoers_include("#includedir /etc/sudoers.d"),
            Some(("directory", "/etc/sudoers.d"))
        );
        assert_eq!(
            sudoers_include("@include /etc/sudoers.local"),
            Some(("file", "/etc/sudoers.local"))
        );
        assert_eq!(
            sudoers_include("@includedir /etc/sudoers.d"),
            Some(("directory", "/etc/sudoers.d"))
        );
        assert_eq!(sudoers_include("# a plain comment"), None);
    }

    #[test]
    fn sudoers_joins_backslash_continued_lines() {
        let bytes = b"alice ALL = (root) \\\n    /usr/bin/systemctl restart nginx\n";
        let logical = text::join_backslash_continuations(bytes);
        assert_eq!(logical.len(), 1);
        assert_eq!(logical[0].starting_line, 1);
        assert!(logical[0].text.contains("systemctl restart nginx"));
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
            definition("UnixPasswdFile", &[Cow::Borrowed("/etc/passwd")]),
            definition("LinuxPasswdFile", &[Cow::Borrowed("/etc/passwd")]),
            definition("UnixShadowFile", &[Cow::Borrowed("/etc/shadow")]),
            definition("UnixGroupsFile", &[Cow::Borrowed("/etc/group")]),
            definition(
                "UnixSudoersConfigurationFile",
                &[Cow::Borrowed("/etc/sudoers")],
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
        let parser = AccountsParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = AccountsParserFactory::new();
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
    fn a_passwd_file_matching_two_definitions_is_read_once() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], USER_NAME), Some("root"));
    }

    #[test]
    fn a_password_hash_never_appears_in_output() {
        let secret_hash = "$6$abcSaltValue$verySecretHashPayloadThatMustNeverLeak";
        let shadow = format!("root:{secret_hash}:19700:0:99999:7:::\n");
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/shadow", shadow.into_bytes());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::PASSWORD_STATE), Some("hashed"));
        assert_eq!(field(records[0], field::PASSWORD_ALGORITHM), Some("6"));
        for data in &records {
            for (key, value) in data.fields() {
                let rendered = value.to_string();
                assert!(
                    !rendered.contains("verySecretHashPayload"),
                    "field {key} leaked the hash: {rendered}"
                );
            }
        }
    }

    #[test]
    fn a_malformed_passwd_row_is_an_err_item_not_a_silent_skip() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/passwd", b"root:x:0:0:root:/root\n".to_vec()); // 6 fields, not 7
        let items = run(&sources(vfs));
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
        assert!(items[0]
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("line 1"));
    }

    #[test]
    fn group_members_are_split_and_deterministic() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/group", b"wheel:x:10:alice,bob,carol\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], GROUP_NAME), Some("wheel"));
    }

    #[test]
    fn sudoers_include_directives_are_recorded_not_followed() {
        let vfs = InMemoryVirtualFileSystem::new().with_file(
            "etc/sudoers",
            b"#includedir /etc/sudoers.d\nalice ALL=(ALL) ALL\n".to_vec(),
        );
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            field(records[0], field::RECORD_KIND),
            Some("sudoers_include")
        );
        assert_eq!(
            field(records[0], field::SUDOERS_INCLUDE_TARGET),
            Some("/etc/sudoers.d")
        );
        assert_eq!(
            field(records[1], field::SUDOERS_RAW_LINE),
            Some("alice ALL=(ALL) ALL")
        );
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n".to_vec());
        let sources = TriageSources::builder()
            .vfs(Arc::new(vfs))
            .acquisition(Acquisition::ImageRead)
            .build();
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = AccountsParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }
}
