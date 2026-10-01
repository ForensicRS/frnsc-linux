//! Shell history parsing — bash, zsh, fish, and the plain "one command per line" shells (sh,
//! Python's REPL, the MySQL client, `less`) — and [`ShellHistoryParserFactory`], the
//! [`ArtifactParserFactory`] that resolves `BashShellHistoryFile`/`ZShellHistoryFile`/
//! `FishShellHistoryFile`/`BourneShellHistoryFile`/`RootUserShellHistory`/`ShellHistoryFile`/
//! `PythonHistoryFile`/`MySQLHistoryFile`/`LessHistoryFile` through the run's artifact catalog (no
//! hardcoded paths) and emits `Artifact::Linux(LinuxArtifacts::ShellHistory(..))` records, on top
//! of the shared [`crate::log::text`] scaffold.
//!
//! # Formats
//!
//! * **bash** — one command per line. With `HISTTIMEFORMAT` set, each command is preceded by a
//!   `#<unix-epoch>` comment line carrying its timestamp; without it, there is no timestamp at
//!   all. Both are handled by the same [`parse_bash`]: a `#<digits>` line attaches its epoch to
//!   whatever line follows, and any other line is a command with no timestamp.
//! * **zsh** (`EXTENDED_HISTORY`) — `: <epoch>:<elapsed>;<command>`. A command containing a real
//!   newline is written across multiple physical lines, each but the last ending in a literal
//!   `\` continuation. Without `EXTENDED_HISTORY`, zsh history is plain lines like bash, which
//!   [`parse_zsh`] falls back to per line.
//! * **fish** — a YAML-like format: `- cmd: <command>` starts an entry, `  when: <epoch>` gives
//!   its timestamp, and any other indented line (`  paths:`, `    - /some/path`) belongs to the
//!   entry too but is kept only in its raw text, not otherwise interpreted.
//! * **plain** — `BourneShellHistoryFile`, `PythonHistoryFile`, `MySQLHistoryFile`,
//!   `LessHistoryFile`, and any `RootUserShellHistory`/`ShellHistoryFile` file that isn't
//!   recognizably one of the above by its resolved filename: one command per line, never a
//!   fabricated timestamp.
//!
//! An entry with no timestamp gets no timestamp — never a parse time, never an invented one.
//!
//! `RootUserShellHistory` and `ShellHistoryFile` are themselves multi-format (a `Group`/explicit
//! path list spanning several shells), so the sub-format is picked from the *resolved* file's
//! name (`shell_kind_from_filename`) rather than the definition alone; every other definition
//! names exactly one shell and its format follows directly.

use std::collections::BTreeMap;

use forensic_rs::prelude::*;

use crate::log::text::scan_lines;

/// Registration id of [`ShellHistoryParserFactory`].
pub const PARSER_ID: &str = "linux.shell_history";

/// The ForensicArtifacts definitions this parser reads, sorted for deterministic requirement
/// order. The catalog is the source of truth for *where* these files live.
pub const DEFINITIONS: &[&str] = &[
    "BashShellHistoryFile",
    "BourneShellHistoryFile",
    "FishShellHistoryFile",
    "LessHistoryFile",
    "MySQLHistoryFile",
    "PythonHistoryFile",
    "RootUserShellHistory",
    "ShellHistoryFile",
    "ZShellHistoryFile",
];

/// Every `Linux(ShellHistory(..))` sub-artifact tag this parser can emit, regardless of which
/// definition led to it — used to build [`ShellHistoryParserFactory`]'s declared artifact set.
const KINDS: &[&str] = &[
    "bash", "zsh", "fish", "sh", "python", "mysql", "less", "unknown",
];

/// Resolves the shell-history sub-format for a file matched under `definition`. Single-shell
/// definitions map directly; the two multi-shell definitions fall back to the resolved filename.
fn shell_kind(definition: &str, path: &FPath) -> &'static str {
    match definition {
        "BashShellHistoryFile" => "bash",
        "ZShellHistoryFile" => "zsh",
        "FishShellHistoryFile" => "fish",
        "BourneShellHistoryFile" => "sh",
        "PythonHistoryFile" => "python",
        "MySQLHistoryFile" => "mysql",
        "LessHistoryFile" => "less",
        _ => shell_kind_from_filename(path),
    }
}

fn shell_kind_from_filename(path: &FPath) -> &'static str {
    let name = path.as_str();
    if name.ends_with("fish_history") {
        "fish"
    } else if name.ends_with(".zsh_history") || name.ends_with(".zhistory") {
        "zsh"
    } else if name.ends_with(".bash_history") {
        "bash"
    } else if name.ends_with(".sh_history") {
        "sh"
    } else {
        "unknown"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellVariant {
    Bash,
    Zsh,
    Fish,
    Plain,
}

fn variant_for_kind(kind: &str) -> ShellVariant {
    match kind {
        "bash" => ShellVariant::Bash,
        "zsh" => ShellVariant::Zsh,
        "fish" => ShellVariant::Fish,
        _ => ShellVariant::Plain,
    }
}

/// One shell history entry. `timestamp` is `None` whenever the source line(s) carried no
/// timestamp of their own — never filled in with a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellHistoryEntry {
    pub command: String,
    pub timestamp: Option<ForensicTimestamp>,
    /// zsh extended history only: seconds the command took to run, if recorded.
    pub elapsed_seconds: Option<u64>,
    /// The exact raw line(s) this entry came from, newline-joined when it spanned more than one
    /// (a zsh `\`-continued command, or a fish entry's `when`/`paths` lines).
    pub raw: String,
}

fn bash_epoch_marker(text: &str) -> Option<i64> {
    let digits = text.strip_prefix('#')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// `#<epoch>` lines attach a timestamp to whichever line follows; every other line is a command.
/// Works whether or not `HISTTIMEFORMAT` markers are present at all.
pub fn parse_bash(lines: &[crate::log::text::TextLine<'_>]) -> Vec<ShellHistoryEntry> {
    let mut out = Vec::new();
    let mut pending_epoch: Option<i64> = None;
    for line in lines {
        if line.raw.is_empty() {
            continue;
        }
        let text = line.text().into_owned();
        if let Some(epoch) = bash_epoch_marker(&text) {
            pending_epoch = Some(epoch);
            continue;
        }
        let timestamp = pending_epoch.take().map(ForensicTimestamp::from_unix_secs);
        out.push(ShellHistoryEntry {
            command: text.clone(),
            timestamp,
            elapsed_seconds: None,
            raw: text,
        });
    }
    out
}

fn zsh_extended(text: &str) -> Option<(i64, u64, &str)> {
    let rest = text.strip_prefix(": ")?;
    let colon = rest.find(':')?;
    let epoch: i64 = rest.get(..colon)?.parse().ok()?;
    let rest = rest.get(colon + 1..)?;
    let semi = rest.find(';')?;
    let elapsed: u64 = rest.get(..semi)?.parse().ok()?;
    let cmd = rest.get(semi + 1..)?;
    Some((epoch, elapsed, cmd))
}

/// `: epoch:elapsed;cmd` (`EXTENDED_HISTORY`), with `\`-continued multi-line commands. A file
/// without `EXTENDED_HISTORY` is just plain lines, which fall through to the plain-command arm.
pub fn parse_zsh(lines: &[crate::log::text::TextLine<'_>]) -> Vec<ShellHistoryEntry> {
    let mut out: Vec<ShellHistoryEntry> = Vec::new();
    let mut continuing = false;
    for line in lines {
        if line.raw.is_empty() {
            continuing = false;
            continue;
        }
        let text = line.text().into_owned();
        if continuing {
            let ends_backslash = text.ends_with('\\');
            let content = if ends_backslash {
                text.get(..text.len() - 1).unwrap_or("")
            } else {
                text.as_str()
            };
            if let Some(last) = out.last_mut() {
                last.command.push('\n');
                last.command.push_str(content);
                last.raw.push('\n');
                last.raw.push_str(&text);
            }
            continuing = ends_backslash;
            continue;
        }
        match zsh_extended(&text) {
            Some((epoch, elapsed, cmd)) => {
                let ends_backslash = cmd.ends_with('\\');
                let command = if ends_backslash {
                    cmd.get(..cmd.len() - 1).unwrap_or(cmd)
                } else {
                    cmd
                };
                out.push(ShellHistoryEntry {
                    command: command.to_string(),
                    timestamp: Some(ForensicTimestamp::from_unix_secs(epoch)),
                    elapsed_seconds: Some(elapsed),
                    raw: text,
                });
                continuing = ends_backslash;
            }
            None => {
                out.push(ShellHistoryEntry {
                    command: text.clone(),
                    timestamp: None,
                    elapsed_seconds: None,
                    raw: text,
                });
                continuing = false;
            }
        }
    }
    out
}

/// `- cmd: <command>` starts an entry; `  when: <epoch>` sets its timestamp; anything else
/// indented (`  paths:`, `    - /x`) is kept in the entry's raw text but not otherwise
/// interpreted. Content before the first `- cmd:` line (should not normally occur) has nowhere to
/// attach and is dropped rather than fabricating an entry for it.
pub fn parse_fish(lines: &[crate::log::text::TextLine<'_>]) -> Vec<ShellHistoryEntry> {
    let mut out: Vec<ShellHistoryEntry> = Vec::new();
    let mut raw_lines: Vec<String> = Vec::new();
    for line in lines {
        if line.raw.is_empty() {
            continue;
        }
        let text = line.text().into_owned();
        if let Some(cmd) = text.strip_prefix("- cmd: ") {
            if let Some(last) = out.last_mut() {
                last.raw = raw_lines.join("\n");
            }
            raw_lines = vec![text.clone()];
            out.push(ShellHistoryEntry {
                command: cmd.to_string(),
                timestamp: None,
                elapsed_seconds: None,
                raw: String::new(),
            });
            continue;
        }
        if let Some(rest) = text.strip_prefix("  when: ") {
            raw_lines.push(text.clone());
            if let Some(last) = out.last_mut() {
                if let Ok(epoch) = rest.trim().parse::<i64>() {
                    last.timestamp = Some(ForensicTimestamp::from_unix_secs(epoch));
                }
            }
            continue;
        }
        raw_lines.push(text);
    }
    if let Some(last) = out.last_mut() {
        last.raw = raw_lines.join("\n");
    }
    out
}

pub fn parse_plain(lines: &[crate::log::text::TextLine<'_>]) -> Vec<ShellHistoryEntry> {
    lines
        .iter()
        .filter(|l| !l.raw.is_empty())
        .map(|l| {
            let text = l.text().into_owned();
            ShellHistoryEntry {
                command: text.clone(),
                timestamp: None,
                elapsed_seconds: None,
                raw: text,
            }
        })
        .collect()
}

fn parse_entries(
    variant: ShellVariant,
    lines: &[crate::log::text::TextLine<'_>],
) -> Vec<ShellHistoryEntry> {
    match variant {
        ShellVariant::Bash => parse_bash(lines),
        ShellVariant::Zsh => parse_zsh(lines),
        ShellVariant::Fish => parse_fish(lines),
        ShellVariant::Plain => parse_plain(lines),
    }
}

/// Best-effort username from the resolved path's own layout (`home/<user>/...`, `root/...`) —
/// never guessed beyond what the path itself says.
fn username_from_path(path: &FPath) -> Option<String> {
    let s = path.as_str();
    let mut segments = s.split('/');
    let first = segments.next()?;
    if first == "root" {
        return Some("root".to_string());
    }
    if first == "home" {
        let user = segments.next()?;
        if !user.is_empty() {
            return Some(user.to_string());
        }
    }
    None
}

/// Crate-local `linux.shell_history.*` field names.
mod field {
    pub const KIND: &str = "linux.shell_history.kind";
    pub const COMMAND: &str = "linux.shell_history.command";
    pub const RAW: &str = "linux.shell_history.raw";
    pub const ELAPSED_SECONDS: &str = "linux.shell_history.elapsed_seconds";
}

#[allow(clippy::too_many_arguments)]
fn entry_to_forensic_data(
    host: &str,
    definition: &'static str,
    kind: &'static str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
    user: Option<&str>,
    entry: &ShellHistoryEntry,
) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(
        host,
        Artifact::Linux(LinuxArtifacts::ShellHistory(kind.to_string())),
        provenance,
    );
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition);
    data.set(field::KIND, kind);
    data.set(field::COMMAND, entry.command.clone());
    data.set(field::RAW, entry.raw.clone());
    if let Some(user) = user {
        data.set(USER_NAME, user.to_string());
    }
    if let Some(ts) = entry.timestamp {
        data.set(TIMESTAMP, ts);
    }
    if let Some(elapsed) = entry.elapsed_seconds {
        data.set(field::ELAPSED_SECONDS, elapsed);
    }
    data
}

/// Emits one [`ForensicData`] per history entry, from every location the run's
/// [`ArtifactCatalog`] locates for [`DEFINITIONS`].
pub struct ShellHistoryParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for ShellHistoryParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> = DEFINITIONS
            .iter()
            .copied()
            .map(Requirement::artifact)
            .collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Unix shell history (bash/zsh/fish/sh/python/mysql/less)",
                "Emits one record per shell history entry, wherever the artifact catalog \
                 resolves a shell history file; a command with no recorded timestamp is emitted \
                 with none",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(
                KINDS
                    .iter()
                    .map(|k| Artifact::Linux(LinuxArtifacts::ShellHistory(k.to_string())))
                    .collect::<Vec<_>>(),
            )
            .with_requirements(requirements),
        }
    }
}

impl ShellHistoryParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for ShellHistoryParserFactory {
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
                "ArtifactCatalog required: this parser locates shell history files by artifact \
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
                let kind = shell_kind(definition, path.as_path());
                let variant = variant_for_kind(kind);
                let user = username_from_path(path.as_path());
                let lines = scan_lines(&bytes);
                for entry in parse_entries(variant, &lines) {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    let data = entry_to_forensic_data(
                        &host,
                        definition,
                        kind,
                        path.as_path(),
                        &source,
                        acquisition,
                        user.as_deref(),
                        &entry,
                    );
                    if out.emit(Ok(data)).is_stop() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::text::scan_lines;

    #[test]
    fn bash_plain_has_no_timestamps() {
        let bytes = b"ls -la\ncd /var/log\nhistory -c\n";
        let lines = scan_lines(bytes);
        let entries = parse_bash(&lines);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.timestamp.is_none()));
        assert_eq!(entries[0].command, "ls -la");
    }

    #[test]
    fn bash_histtimeformat_attaches_the_epoch_to_the_following_command() {
        let bytes = b"#1768464012\nls -la\n#1768464030\ncd /var/log\n";
        let lines = scan_lines(bytes);
        let entries = parse_bash(&lines);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "ls -la");
        assert_eq!(entries[0].timestamp.unwrap().to_unix_secs(), 1768464012);
        assert_eq!(entries[1].command, "cd /var/log");
    }

    #[test]
    fn an_orphan_trailing_marker_produces_no_entry() {
        let bytes = b"ls -la\n#1768464012\n";
        let lines = scan_lines(bytes);
        let entries = parse_bash(&lines);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command, "ls -la");
    }

    #[test]
    fn zsh_extended_history_parses_epoch_and_elapsed() {
        let bytes = b": 1699999999:0;ls -la\n: 1700000005:2;cd /tmp\n";
        let lines = scan_lines(bytes);
        let entries = parse_zsh(&lines);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "ls -la");
        assert_eq!(entries[0].timestamp.unwrap().to_unix_secs(), 1699999999);
        assert_eq!(entries[0].elapsed_seconds, Some(0));
        assert_eq!(entries[1].elapsed_seconds, Some(2));
    }

    #[test]
    fn zsh_without_extended_history_falls_back_to_plain_commands() {
        let bytes = b"ls -la\ncd /tmp\n";
        let lines = scan_lines(bytes);
        let entries = parse_zsh(&lines);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.timestamp.is_none()));
    }

    #[test]
    fn zsh_backslash_continuation_joins_into_one_multiline_command() {
        let bytes = b": 1699999999:0;echo one \\\necho two\n";
        let lines = scan_lines(bytes);
        let entries = parse_zsh(&lines);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].command, "echo one \necho two");
    }

    #[test]
    fn fish_entries_parse_cmd_and_when() {
        let bytes = b"- cmd: ls -la\n  when: 1699999999\n- cmd: cd /tmp\n  when: 1700000005\n  paths:\n    - /tmp\n";
        let lines = scan_lines(bytes);
        let entries = parse_fish(&lines);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "ls -la");
        assert_eq!(entries[0].timestamp.unwrap().to_unix_secs(), 1699999999);
        assert_eq!(entries[1].command, "cd /tmp");
        assert!(entries[1].raw.contains("paths:"));
    }

    #[test]
    fn fish_entry_with_no_when_line_has_no_timestamp() {
        let bytes = b"- cmd: ls -la\n";
        let lines = scan_lines(bytes);
        let entries = parse_fish(&lines);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].timestamp.is_none());
    }

    #[test]
    fn shell_kind_from_filename_covers_every_known_suffix() {
        assert_eq!(
            shell_kind_from_filename(FPathBuf::from("root/.bash_history").as_path()),
            "bash"
        );
        assert_eq!(
            shell_kind_from_filename(FPathBuf::from("root/.zsh_history").as_path()),
            "zsh"
        );
        assert_eq!(
            shell_kind_from_filename(FPathBuf::from("root/.zhistory").as_path()),
            "zsh"
        );
        assert_eq!(
            shell_kind_from_filename(
                FPathBuf::from("root/.local/share/fish/fish_history").as_path()
            ),
            "fish"
        );
        assert_eq!(
            shell_kind_from_filename(FPathBuf::from("root/.sh_history").as_path()),
            "sh"
        );
        assert_eq!(
            shell_kind_from_filename(FPathBuf::from("root/.mystery_history").as_path()),
            "unknown"
        );
    }

    #[test]
    fn username_from_path_reads_root_and_home_segments() {
        assert_eq!(
            username_from_path(FPathBuf::from("root/.bash_history").as_path()).as_deref(),
            Some("root")
        );
        assert_eq!(
            username_from_path(FPathBuf::from("home/alice/.bash_history").as_path()).as_deref(),
            Some("alice")
        );
        assert_eq!(
            username_from_path(FPathBuf::from("var/lib/x").as_path()),
            None
        );
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
            definition(
                "BashShellHistoryFile",
                &[Cow::Borrowed("/home/*/.bash_history")],
            ),
            definition(
                "BourneShellHistoryFile",
                &[Cow::Borrowed("/home/*/.sh_history")],
            ),
            definition(
                "FishShellHistoryFile",
                &[Cow::Borrowed("/home/*/.local/share/fish/fish_history")],
            ),
            definition("LessHistoryFile", &[Cow::Borrowed("/home/*/.lesshst")]),
            definition(
                "MySQLHistoryFile",
                &[Cow::Borrowed("/home/*/.mysql_history")],
            ),
            definition(
                "PythonHistoryFile",
                &[Cow::Borrowed("/home/*/.python_history")],
            ),
            definition(
                "RootUserShellHistory",
                &[
                    Cow::Borrowed("/root/.bash_history"),
                    Cow::Borrowed("/root/.local/share/fish/fish_history"),
                    Cow::Borrowed("/root/.sh_history"),
                    Cow::Borrowed("/root/.zhistory"),
                    Cow::Borrowed("/root/.zsh_history"),
                ],
            ),
            definition(
                "ShellHistoryFile",
                &[
                    Cow::Borrowed("/home/*/.bash_history"),
                    Cow::Borrowed("/home/*/.sh_history"),
                    Cow::Borrowed("/home/*/.local/share/fish/fish_history"),
                    Cow::Borrowed("/home/*/.zsh_history"),
                ],
            ),
            definition(
                "ZShellHistoryFile",
                &[
                    Cow::Borrowed("/home/*/.zsh_history"),
                    Cow::Borrowed("/home/*/.zhistory"),
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
        let parser = ShellHistoryParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = ShellHistoryParserFactory::new();
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
    fn a_bash_history_file_gets_the_bash_kind_and_the_home_derived_user() {
        let bytes = b"ls -la\ncd /tmp\n";
        let vfs =
            InMemoryVirtualFileSystem::new().with_file("home/alice/.bash_history", bytes.to_vec());
        let items = run(&sources(vfs, true));
        assert!(items.iter().all(|i| i.is_ok()));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2);
        assert!(
            matches!(records[0].artifact(), Artifact::Linux(LinuxArtifacts::ShellHistory(k)) if k == "bash")
        );
        assert_eq!(records[0].field_as_str(USER_NAME), Some("alice"));
        assert_eq!(
            records[0].field_as_str("linux.shell_history.command"),
            Some("ls -la")
        );
        assert!(records[0].field_as_date(TIMESTAMP).is_none());
    }

    #[test]
    fn root_history_derives_fish_from_the_resolved_filename() {
        let bytes = b"- cmd: ls -la\n  when: 1699999999\n";
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("root/.local/share/fish/fish_history", bytes.to_vec());
        let items = run(&sources(vfs, true));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert!(
            matches!(records[0].artifact(), Artifact::Linux(LinuxArtifacts::ShellHistory(k)) if k == "fish")
        );
        assert_eq!(records[0].field_as_str(USER_NAME), Some("root"));
        assert!(records[0].field_as_date(TIMESTAMP).is_some());
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let vfs =
            InMemoryVirtualFileSystem::new().with_file("home/alice/.bash_history", b"ls".to_vec());
        let sources = sources(vfs, false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = ShellHistoryParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }
}
