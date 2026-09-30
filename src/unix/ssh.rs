//! `authorized_keys`, `known_hosts` and host public key files, and [`SshParserFactory`], the
//! [`ArtifactParserFactory`] that resolves `SSHAuthorizedKeysFiles`/`SSHKnownHostsFiles`/
//! `SSHHostPubKeys` through the run's artifact catalog (no hardcoded paths) and emits
//! `Artifact::Linux(LinuxArtifacts::Ssh)` records.
//!
//! # Per-user identity without a per-user catalog binding
//!
//! `SSHAuthorizedKeysFiles`/`SSHKnownHostsFiles` are declared in the ForensicArtifacts KB with a
//! `%%users.homedir%%` placeholder, but on this platform that placeholder expands to a plain
//! glob (`/home/*/.ssh/...`, `/root/.ssh/...`) rather than a per-user binding — see
//! `forensic_rs::catalog::expand`'s `Style::PosixPath` branch, which returns before touching the
//! per-user `sid` logic at all. So [`ResolvedFile::sid`] is `None` here, and the owning user is
//! instead derived from the path itself (the directory two levels up from the file, e.g.
//! `/home/alice/.ssh/authorized_keys` -> `alice`). [`field::USER_SOURCE`] records which case
//! applied, so a future catalog that *does* bind a `sid` is visibly more authoritative than this
//! path guess, never silently indistinguishable from it.
//!
//! # Trust is not re-derived here
//!
//! This module keeps the key type, comment, options and a SHA-256 fingerprint (the same
//! algorithm `ssh-keygen -l` uses) of every key, and the full raw line besides. It never decides
//! whether a key, host or option is legitimate — that is an analyst judgment, not a parse step.
//! A `known_hosts` host field may be **hashed** (`|1|salt|hash`, HMAC-SHA1 of the hostname); this
//! is reported as hashed and the salt/hash are kept verbatim, never guessed at or "resolved".

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;
use forensic_rs::prelude::*;
use sha2::{Digest as _, Sha256};

use crate::text;

/// Registration id of [`SshParserFactory`].
pub const PARSER_ID: &str = "linux.ssh";

/// The ForensicArtifacts definitions this parser reads, in the order it declares them.
pub const DEFINITIONS: &[&str] = &["SSHAuthorizedKeysFiles", "SSHKnownHostsFiles", "SSHHostPubKeys"];

/// Recognized SSH public-key algorithm identifiers (plain and `-cert-v01@openssh.com` forms). A
/// token outside this set is never assumed to be a key type — see [`is_known_keytype`].
const KEY_TYPES: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
];

fn is_known_keytype(token: &str) -> bool {
    KEY_TYPES.contains(&token)
}

mod field {
    pub const RECORD_KIND: &str = "linux.ssh.record_kind";
    pub const LINE_NUMBER: &str = "linux.ssh.line_number";
    pub const RAW_LINE: &str = "linux.ssh.raw_line";
    pub const KEY_TYPE: &str = "linux.ssh.key.type";
    pub const KEY_COMMENT: &str = "linux.ssh.key.comment";
    pub const KEY_FINGERPRINT: &str = "linux.ssh.key.fingerprint";
    pub const OPTIONS: &str = "linux.ssh.authorized_key.options";
    pub const OPTION_COMMAND: &str = "linux.ssh.authorized_key.command";
    pub const OPTION_FROM: &str = "linux.ssh.authorized_key.from";
    pub const OPTION_NO_PTY: &str = "linux.ssh.authorized_key.no_pty";
    pub const USER_SOURCE: &str = "linux.ssh.user.source";
    pub const HOST_MARKER: &str = "linux.ssh.known_hosts.marker";
    pub const HOST_HASHED: &str = "linux.ssh.known_hosts.hashed";
    pub const HOST_PATTERNS: &str = "linux.ssh.known_hosts.host_patterns";
    pub const HOST_RAW: &str = "linux.ssh.known_hosts.host_field_raw";
}

/// Splits `s` on whitespace, treating a `"..."` span (escaped `\"` inside it) as one token even
/// if it contains whitespace — the same convention `sshd` uses for quoted option values.
fn split_respecting_quotes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_quotes && chars.peek() == Some(&'"') => {
                current.push(chars.next().unwrap());
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Splits an `authorized_keys` options blob on `,`, respecting `"..."` spans the same way
/// [`split_respecting_quotes`] does for whitespace.
fn split_options(options: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in options.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn option_value<'a>(options: &'a [String], key_eq: &str) -> Option<&'a str> {
    options
        .iter()
        .find_map(|o| o.strip_prefix(key_eq))
        .map(|v| v.trim_matches('"'))
}

/// The common `[options] keytype base64-key [comment]` shape shared by `authorized_keys` and
/// host public key files (`allow_options = false` for the latter, which never carries one).
fn parse_pubkey_tokens(
    trimmed: &str,
    allow_options: bool,
) -> Result<(Option<String>, String, String, String), String> {
    let tokens = split_respecting_quotes(trimmed);
    let mut idx = 0;
    let mut options = None;
    if allow_options {
        if let Some(first) = tokens.first() {
            if !is_known_keytype(first) {
                options = Some(first.clone());
                idx = 1;
            }
        }
    }
    let keytype = tokens.get(idx).ok_or_else(|| "missing key type".to_string())?.clone();
    if !is_known_keytype(&keytype) {
        return Err(format!("unrecognized key type {keytype:?}"));
    }
    let key = tokens
        .get(idx + 1)
        .ok_or_else(|| "missing key data".to_string())?
        .clone();
    let comment = tokens.get(idx + 2..).map(|c| c.join(" ")).unwrap_or_default();
    Ok((options, keytype, key, comment))
}

/// SHA-256 fingerprint of the decoded key blob, formatted the way `ssh-keygen -l` reports it
/// (`SHA256:` + unpadded base64). `None` when `base64_key` does not even decode as base64 — the
/// caller still keeps the raw line, so nothing is lost by not fingerprinting it.
fn key_fingerprint(base64_key: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(base64_key).ok()?;
    let digest = Sha256::digest(&decoded);
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    Some(format!("SHA256:{encoded}"))
}

/// The user a `.ssh/<file>` path belongs to: the directory two levels up (`.../<user>/.ssh/...`)
/// — general enough to cover both `/home/<user>/.ssh/...` and `/root/.ssh/...` without hardcoding
/// `/home`.
fn derive_user_from_ssh_path(path: &FPath) -> Option<String> {
    let ssh_dir = path.parent()?;
    if ssh_dir.file_name()? != ".ssh" {
        return None;
    }
    ssh_dir.parent()?.file_name().map(str::to_string)
}

/// Resolves the owning user for a per-user SSH file: the catalog's own `sid` binding when
/// present (authoritative), otherwise a path-derived guess (see the module docs), otherwise
/// neither.
fn resolve_user(sid: Option<&str>, path: &FPath) -> (Option<String>, Option<&'static str>) {
    if let Some(sid) = sid {
        return (Some(sid.to_string()), Some("catalog"));
    }
    match derive_user_from_ssh_path(path) {
        Some(user) => (Some(user), Some("path")),
        None => (None, None),
    }
}

fn set_key_fields(data: &mut ForensicData, keytype: &str, key: &str, comment: &str) {
    data.set(field::KEY_TYPE, keytype.to_string());
    if !comment.is_empty() {
        data.set(field::KEY_COMMENT, comment.to_string());
    }
    if let Some(fp) = key_fingerprint(key) {
        data.set(field::KEY_FINGERPRINT, fp);
    }
}

fn authorized_key_record(
    host: &str,
    path: &FPath,
    line: &text::Line<'_>,
    user: (Option<String>, Option<&'static str>),
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicResult<ForensicData> {
    let raw = line.text();
    let trimmed = raw.trim();
    let (options, keytype, key, comment) = parse_pubkey_tokens(trimmed, true).map_err(|reason| {
        ForensicError::invalid_format(
            "authorized_keys line",
            format!("line {}: {reason}", line.number),
        )
        .with_path(path.to_owned())
    })?;

    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Ssh), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, "SSHAuthorizedKeysFiles");
    data.set(field::RECORD_KIND, "authorized_key");
    data.set(field::LINE_NUMBER, line.number as u64);
    data.set(field::RAW_LINE, trimmed.to_string());
    if let (Some(user), Some(source)) = &user {
        data.set(USER_NAME, user.clone());
        data.set(field::USER_SOURCE, *source);
    }
    set_key_fields(&mut data, &keytype, &key, &comment);
    if let Some(options) = options {
        let opts = split_options(&options);
        if let Some(cmd) = option_value(&opts, "command=") {
            data.set(field::OPTION_COMMAND, cmd.to_string());
        }
        if let Some(from) = option_value(&opts, "from=") {
            data.set(field::OPTION_FROM, from.to_string());
        }
        data.set(field::OPTION_NO_PTY, opts.iter().any(|o| o == "no-pty"));
        if !opts.is_empty() {
            data.set(
                field::OPTIONS,
                opts.into_iter().map(text_owned).collect::<Vec<Text>>(),
            );
        }
    }
    Ok(data)
}

fn known_hosts_record(
    host: &str,
    path: &FPath,
    line: &text::Line<'_>,
    user: (Option<String>, Option<&'static str>),
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicResult<ForensicData> {
    let raw = line.text();
    let trimmed = raw.trim();
    let tokens = split_respecting_quotes(trimmed);
    let mut idx = 0;
    let marker = match tokens.first().map(String::as_str) {
        Some("@cert-authority") => {
            idx = 1;
            Some("cert-authority")
        }
        Some("@revoked") => {
            idx = 1;
            Some("revoked")
        }
        _ => None,
    };
    let host_field = tokens.get(idx).cloned().ok_or_else(|| {
        ForensicError::invalid_format(
            "known_hosts line",
            format!("line {}: missing host field", line.number),
        )
        .with_path(path.to_owned())
    })?;
    idx += 1;
    let keytype = tokens.get(idx).cloned().ok_or_else(|| {
        ForensicError::invalid_format(
            "known_hosts line",
            format!("line {}: missing key type", line.number),
        )
        .with_path(path.to_owned())
    })?;
    if !is_known_keytype(&keytype) {
        return Err(ForensicError::invalid_format(
            "known_hosts line",
            format!("line {}: unrecognized key type {keytype:?}", line.number),
        )
        .with_path(path.to_owned()));
    }
    idx += 1;
    let key = tokens.get(idx).cloned().ok_or_else(|| {
        ForensicError::invalid_format(
            "known_hosts line",
            format!("line {}: missing key data", line.number),
        )
        .with_path(path.to_owned())
    })?;
    idx += 1;
    let comment = tokens.get(idx..).map(|c| c.join(" ")).unwrap_or_default();
    let hashed = host_field.starts_with("|1|");

    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Ssh), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, "SSHKnownHostsFiles");
    data.set(field::RECORD_KIND, "known_host");
    data.set(field::LINE_NUMBER, line.number as u64);
    data.set(field::RAW_LINE, trimmed.to_string());
    if let (Some(user), Some(source)) = &user {
        data.set(USER_NAME, user.clone());
        data.set(field::USER_SOURCE, *source);
    }
    if let Some(marker) = marker {
        data.set(field::HOST_MARKER, marker);
    }
    data.set(field::HOST_HASHED, hashed);
    data.set(field::HOST_RAW, host_field.clone());
    if !hashed {
        let patterns = text::comma_list(&host_field);
        if !patterns.is_empty() {
            data.set(
                field::HOST_PATTERNS,
                patterns.into_iter().map(text_owned).collect::<Vec<Text>>(),
            );
        }
    }
    set_key_fields(&mut data, &keytype, &key, &comment);
    Ok(data)
}

fn host_pub_key_record(
    host: &str,
    path: &FPath,
    line: &text::Line<'_>,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicResult<ForensicData> {
    let raw = line.text();
    let trimmed = raw.trim();
    let (_, keytype, key, comment) = parse_pubkey_tokens(trimmed, false).map_err(|reason| {
        ForensicError::invalid_format("ssh host public key", format!("line {}: {reason}", line.number))
            .with_path(path.to_owned())
    })?;

    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(host, Artifact::Linux(LinuxArtifacts::Ssh), provenance);
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, "SSHHostPubKeys");
    data.set(field::RECORD_KIND, "host_pub_key");
    data.set(field::LINE_NUMBER, line.number as u64);
    data.set(field::RAW_LINE, trimmed.to_string());
    set_key_fields(&mut data, &keytype, &key, &comment);
    Ok(data)
}

/// Emits one [`ForensicData`] per SSH public-key line found through the run's [`ArtifactCatalog`]
/// for [`DEFINITIONS`]. Follows [`crate::unix::utmp::UtmpParserFactory`]'s pattern: stateless
/// (`&self`), one [`SourceHandle`] per real file, never panics on evidence.
pub struct SshParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for SshParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> =
            DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "SSH authorized_keys, known_hosts and host public keys",
                "Emits one record per public-key line from every location the artifact catalog \
                 resolves for SSHAuthorizedKeysFiles, SSHKnownHostsFiles and SSHHostPubKeys. \
                 Never re-derives trust in a key or host; records a fingerprint instead of \
                 re-deriving it.",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Linux(LinuxArtifacts::Ssh)])
            .with_requirements(requirements),
        }
    }
}

impl SshParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

/// One resolved target file, with everything the push closure needs baked in — no `ResolvedFile`
/// or catalog reference is held past `open`.
struct Target {
    path: FPathBuf,
    definition: &'static str,
    sid: Option<String>,
    source: SourceHandle,
}

impl ArtifactParserFactory for SshParserFactory {
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
                "ArtifactCatalog required: this parser locates SSH files by artifact definition \
                 name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        // Keyed by path; value carries the sid seen for it, so two globs naming the same file
        // with different sid knowledge keep whichever arrived first, same dedup discipline as
        // `unix::utmp`.
        let mut targets: BTreeMap<FPathBuf, (&'static str, Option<String>)> = BTreeMap::new();
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
                if targets.contains_key(&file.path) {
                    continue;
                }
                targets.insert(file.path.clone(), (definition, file.sid.clone()));
            }
        }

        let targets: Vec<Target> = targets
            .into_iter()
            .map(|(path, (definition, sid))| {
                let source = ctx.register_source(SourceKey::Path(path.as_str().to_string()));
                Target { path, definition, sid, source }
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
                let user = resolve_user(target.sid.as_deref(), target.path.as_path());
                for line in text::lines(&bytes) {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    let trimmed_owned = line.text();
                    let trimmed = trimmed_owned.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let result = match target.definition {
                        "SSHAuthorizedKeysFiles" => authorized_key_record(
                            &host,
                            target.path.as_path(),
                            &line,
                            user.clone(),
                            &target.source,
                            acquisition,
                        ),
                        "SSHKnownHostsFiles" => known_hosts_record(
                            &host,
                            target.path.as_path(),
                            &line,
                            user.clone(),
                            &target.source,
                            acquisition,
                        ),
                        _ => host_pub_key_record(&host, target.path.as_path(), &line, &target.source, acquisition),
                    };
                    if out.emit(result).is_stop() {
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
    fn parses_an_authorized_keys_line_without_options() {
        let (options, keytype, key, comment) =
            parse_pubkey_tokens("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI bob@example.com", true).unwrap();
        assert!(options.is_none());
        assert_eq!(keytype, "ssh-ed25519");
        assert_eq!(key, "AAAAC3NzaC1lZDI1NTE5AAAAI");
        assert_eq!(comment, "bob@example.com");
    }

    #[test]
    fn parses_an_authorized_keys_line_with_quoted_options() {
        let line = r#"command="/usr/bin/rrsync /backup",from="10.0.0.0/8",no-pty ssh-rsa AAAAB3NzaC1yc2E backup"#;
        let (options, keytype, key, comment) = parse_pubkey_tokens(line, true).unwrap();
        let options = options.unwrap();
        let opts = split_options(&options);
        assert_eq!(option_value(&opts, "command="), Some("/usr/bin/rrsync /backup"));
        assert_eq!(option_value(&opts, "from="), Some("10.0.0.0/8"));
        assert!(opts.iter().any(|o| o == "no-pty"));
        assert_eq!(keytype, "ssh-rsa");
        assert_eq!(key, "AAAAB3NzaC1yc2E");
        assert_eq!(comment, "backup");
    }

    #[test]
    fn rejects_an_unrecognized_key_type_instead_of_guessing() {
        assert!(parse_pubkey_tokens("not-a-keytype AAAA comment", true).is_err());
    }

    #[test]
    fn host_pub_keys_never_parse_an_options_field() {
        let (options, keytype, _, _) = parse_pubkey_tokens("ssh-rsa AAAAB3NzaC1yc2E", false).unwrap();
        assert!(options.is_none());
        assert_eq!(keytype, "ssh-rsa");
    }

    #[test]
    fn derives_the_user_from_home_and_root_ssh_paths() {
        assert_eq!(
            derive_user_from_ssh_path(FPath::new("/home/alice/.ssh/authorized_keys")),
            Some("alice".to_string())
        );
        assert_eq!(
            derive_user_from_ssh_path(FPath::new("/root/.ssh/authorized_keys")),
            Some("root".to_string())
        );
        assert_eq!(derive_user_from_ssh_path(FPath::new("/etc/ssh/ssh_host_rsa_key.pub")), None);
    }

    #[test]
    fn a_real_sid_binding_beats_the_path_guess() {
        let (user, source) = resolve_user(Some("alice"), FPath::new("/home/alice/.ssh/authorized_keys"));
        assert_eq!(user.as_deref(), Some("alice"));
        assert_eq!(source, Some("catalog"));
        let (user, source) = resolve_user(None, FPath::new("/home/bob/.ssh/authorized_keys"));
        assert_eq!(user.as_deref(), Some("bob"));
        assert_eq!(source, Some("path"));
    }

    #[test]
    fn fingerprint_is_none_for_invalid_base64_but_does_not_panic() {
        assert!(key_fingerprint("not valid base64!!").is_none());
        assert!(key_fingerprint("QUJD").is_some());
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::*;

    const AUTH_KEYS_DEF: &str = "SSHAuthorizedKeysFiles";
    const KNOWN_HOSTS_DEF: &str = "SSHKnownHostsFiles";
    const HOST_PUB_KEYS_DEF: &str = "SSHHostPubKeys";

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
                AUTH_KEYS_DEF,
                &[Cow::Borrowed("/home/*/.ssh/authorized_keys"), Cow::Borrowed("/root/.ssh/authorized_keys")],
            ),
            definition(
                KNOWN_HOSTS_DEF,
                &[Cow::Borrowed("/home/*/.ssh/known_hosts"), Cow::Borrowed("/etc/ssh/known_hosts")],
            ),
            definition(HOST_PUB_KEYS_DEF, &[Cow::Borrowed("/etc/ssh/ssh_host_*_key.pub")]),
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
        let parser = SshParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = SshParserFactory::new();
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
    fn an_authorized_keys_entry_gets_a_path_derived_user_and_a_fingerprint() {
        let vfs = InMemoryVirtualFileSystem::new().with_file(
            "home/alice/.ssh/authorized_keys",
            b"ssh-ed25519 QUJDRA== alice@laptop\n".to_vec(),
        );
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(
            items.iter().all(|i| i.is_ok()),
            "unexpected errors: {:?}",
            items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>()
        );
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], USER_NAME), Some("alice"));
        assert_eq!(field(records[0], field::USER_SOURCE), Some("path"));
        assert!(field(records[0], field::KEY_FINGERPRINT).unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn authorized_key_persistence_relevant_options_are_extracted() {
        let line = r#"command="/bin/false",no-pty ssh-rsa QUJDRA== restricted"#;
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("root/.ssh/authorized_keys", format!("{line}\n").into_bytes());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], USER_NAME), Some("root"));
        assert_eq!(field(records[0], field::OPTION_COMMAND), Some("/bin/false"));
        assert_eq!(records[0].field_as_u64(field::OPTION_NO_PTY), Some(1)); // bool fields are U64(0|1)
    }

    #[test]
    fn a_hashed_known_hosts_entry_is_reported_as_hashed_not_resolved() {
        let hashed_host = "|1|Y2xlYXJzYWx0|aGFzaHZhbHVlaGFzaHZhbHVlaGFzaA==";
        let line = format!("{hashed_host} ssh-rsa QUJDRA==\n");
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/ssh/known_hosts", line.into_bytes());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::HOST_RAW), Some(hashed_host));
        assert!(field(records[0], field::HOST_PATTERNS).is_none(), "a hashed entry is not split as patterns");
    }

    #[test]
    fn an_unhashed_known_hosts_entry_splits_comma_host_patterns() {
        let vfs = InMemoryVirtualFileSystem::new().with_file(
            "etc/ssh/known_hosts",
            b"host1,host2,10.0.0.1 ssh-ed25519 QUJDRA==\n".to_vec(),
        );
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].field_as_u64(field::HOST_HASHED), Some(0)); // bool fields are U64(0|1)
    }

    #[test]
    fn a_host_public_key_has_no_user_and_no_options() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/ssh/ssh_host_ed25519_key.pub", b"ssh-ed25519 QUJDRA== root@host\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert!(field(records[0], USER_NAME).is_none());
        assert_eq!(field(records[0], field::RECORD_KIND), Some("host_pub_key"));
    }

    #[test]
    fn a_malformed_line_is_an_err_item_not_a_silent_skip() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("root/.ssh/authorized_keys", b"this-is-not-a-key-line\n".to_vec());
        let items = run(&sources(vfs));
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }
}
