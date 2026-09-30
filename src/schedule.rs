//! Cron, at, anacron and systemd-timer job scheduling, and [`ScheduleParserFactory`], the
//! [`ArtifactParserFactory`] that resolves `LinuxCronTabs`/`LinuxAtJobs`/`LinuxScheduleFiles`/
//! `AnacronFiles`/`LinuxSystemdTimers`/`CronAtAllowDenyFiles` through the run's artifact catalog
//! (no hardcoded paths) and emits `Artifact::Linux(LinuxArtifacts::Cron(_))` records.
//!
//! # Definition routing, not requested-definition routing
//!
//! `LinuxScheduleFiles` is a *group* definition in the ForensicArtifacts KB — it names no files
//! of its own, it only re-resolves `AnacronFiles`/`LinuxCronTabs`/`LinuxAtJobs`. Resolving it
//! still returns real files, each tagged with the *member* definition's own name
//! ([`ResolvedFile::artifact`]), never `"LinuxScheduleFiles"` itself. This module classifies
//! every file by that resolved leaf name (see [`classify`]), not by which of [`DEFINITIONS`] the
//! lookup started from — so declaring the group is harmless (it dedups against the specific
//! definitions by path) and correct (a file reached only through the group is still classified
//! precisely, not lumped into an "unknown group" bucket).
//!
//! # What counts as persistence-relevant here
//!
//! `@reboot` crontab entries ([`field::IS_REBOOT`]) and anything living in a per-user, non-root
//! spool path ([`field::LOCATION`] `"user_spool"`, set for `/var/spool/cron/**` crontabs) are
//! flagged: both are rewritable by an unprivileged user and run unattended, which is exactly the
//! shape of cron-based persistence. Neither is treated as inherently malicious — that judgment
//! stays with the analyst — only surfaced.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::prelude::*;

use crate::ini;
use crate::text;

/// Registration id of [`ScheduleParserFactory`].
pub const PARSER_ID: &str = "linux.schedule";

/// The ForensicArtifacts definitions this parser declares, in the order the issue lists them.
pub const DEFINITIONS: &[&str] = &[
    "LinuxCronTabs",
    "LinuxAtJobs",
    "LinuxScheduleFiles",
    "AnacronFiles",
    "LinuxSystemdTimers",
    "CronAtAllowDenyFiles",
];

mod field {
    pub const KIND: &str = "linux.schedule.kind";
    pub const LINE_NUMBER: &str = "linux.schedule.line_number";
    pub const RAW_LINE: &str = "linux.schedule.raw_line";
    pub const SCHEDULE_SPEC: &str = "linux.schedule.schedule_spec";
    pub const IS_REBOOT: &str = "linux.schedule.is_reboot";
    pub const COMMAND: &str = "linux.schedule.command";
    pub const CRON_USER_FIELD: &str = "linux.schedule.cron.user_field";
    pub const LOCATION: &str = "linux.schedule.location";
    pub const AT_UID: &str = "linux.schedule.at.uid";
    pub const AT_GID: &str = "linux.schedule.at.gid";
    pub const AT_SCRIPT: &str = "linux.schedule.at.script";
    pub const ANACRON_PERIOD: &str = "linux.schedule.anacron.period";
    pub const ANACRON_DELAY: &str = "linux.schedule.anacron.delay_minutes";
    pub const ANACRON_JOB_ID: &str = "linux.schedule.anacron.job_identifier";
    pub const ANACRON_TIMESTAMP_RAW: &str = "linux.schedule.anacron.last_run_stamp_raw";
    pub const TIMER_KEY: &str = "linux.schedule.timer.key";
    pub const TIMER_VALUE: &str = "linux.schedule.timer.value";
    pub const TIMER_TARGET_SERVICE: &str = "linux.schedule.timer.target_service";
    pub const TIMER_TARGET_SOURCE: &str = "linux.schedule.timer.target_service_source";
    pub const ALLOW_DENY_KIND: &str = "linux.schedule.allow_deny.kind";
}

const CRON_SPECIALS: &[&str] =
    &["@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"];

/// `NAME=VALUE` crontab/anacrontab environment lines (`MAILTO=root`, `PATH=...`), never a
/// scheduling row — recognized so they are skipped rather than reported malformed.
fn is_env_assignment(trimmed: &str) -> bool {
    let Some(eq_idx) = trimmed.find('=') else { return false };
    let name = &trimmed[..eq_idx];
    !name.is_empty()
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The leading time-spec of a crontab/anacrontab line: either one of [`CRON_SPECIALS`] (one
/// token) or five whitespace-separated fields. Returns the spec (rejoined with single spaces —
/// [`field::RAW_LINE`] keeps the exact original text regardless), whether it is `@reboot`, and
/// how many leading tokens it consumed.
fn detect_spec(tokens: &[&str]) -> Result<(String, bool, usize), String> {
    if let Some(first) = tokens.first() {
        if CRON_SPECIALS.contains(first) {
            return Ok((first.to_string(), *first == "@reboot", 1));
        }
    }
    if tokens.len() >= 5 {
        return Ok((tokens[..5].join(" "), false, 5));
    }
    Err(format!(
        "expected 5 time fields or an @special (@reboot, @daily, ...), got {} token(s)",
        tokens.len()
    ))
}

fn period_from_cron_dir_name(name: &str) -> Option<&'static str> {
    match name {
        "cron.daily" => Some("daily"),
        "cron.hourly" => Some("hourly"),
        "cron.weekly" => Some("weekly"),
        "cron.monthly" => Some("monthly"),
        _ => None,
    }
}

/// Which parser applies to a resolved file, by its [`ResolvedFile::artifact`] leaf definition
/// name (see the module docs) and, where one definition covers several real shapes, its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    SystemCrontab,
    UserCrontab,
    AtJob,
    AnacronTabEntry,
    AnacronPeriodicScript,
    AnacronTimestamp,
    SystemdTimer,
    AllowDeny,
}

fn classify(definition: &str, path: &FPath) -> Option<Kind> {
    let p = path.as_str().trim_start_matches('/');
    match definition {
        "LinuxCronTabs" => Some(if p.starts_with("var/spool/cron/") {
            Kind::UserCrontab
        } else {
            Kind::SystemCrontab
        }),
        "LinuxAtJobs" => Some(Kind::AtJob),
        "AnacronFiles" => Some(if p == "etc/anacrontab" {
            Kind::AnacronTabEntry
        } else if p.starts_with("var/spool/anacron/") {
            Kind::AnacronTimestamp
        } else {
            Kind::AnacronPeriodicScript
        }),
        "LinuxSystemdTimers" => Some(Kind::SystemdTimer),
        "CronAtAllowDenyFiles" => Some(Kind::AllowDeny),
        _ => None,
    }
}

fn cron_artifact_kind(kind: Kind) -> &'static str {
    match kind {
        Kind::SystemCrontab | Kind::UserCrontab => "crontab",
        Kind::AtJob => "at",
        Kind::AnacronTabEntry | Kind::AnacronPeriodicScript | Kind::AnacronTimestamp => "anacron",
        Kind::SystemdTimer => "systemd_timer",
        Kind::AllowDeny => "allow_deny",
    }
}

fn new_record(host: &str, kind: Kind, source: &SourceHandle, acquisition: Acquisition) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    ForensicData::new(
        host,
        Artifact::Linux(LinuxArtifacts::Cron(cron_artifact_kind(kind).to_string())),
        provenance,
    )
}

fn base_fields(data: &mut ForensicData, path: &FPath, definition: &str, kind: &'static str) {
    data.set(ARTIFACT_PATH, path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, definition.to_string());
    data.set(field::KIND, kind);
}

fn crontab_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    system: bool,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let mut out = Vec::new();
    let spool_user = (!system).then(|| path.file_name().unwrap_or("").to_string());
    for line in text::lines(bytes) {
        let raw = line.text();
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || is_env_assignment(trimmed) {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let result = (|| -> Result<ForensicData, String> {
            let (spec, is_reboot, consumed) = detect_spec(&tokens)?;
            let rest = &tokens[consumed..];
            let (user_field, command) = if system {
                let (user, cmd_tokens) = rest.split_first().ok_or("missing user field")?;
                if cmd_tokens.is_empty() {
                    return Err("missing command".to_string());
                }
                (Some(user.to_string()), cmd_tokens.join(" "))
            } else {
                if rest.is_empty() {
                    return Err("missing command".to_string());
                }
                (None, rest.join(" "))
            };
            let kind = if system { Kind::SystemCrontab } else { Kind::UserCrontab };
            let mut data = new_record(host, kind, source, acquisition);
            base_fields(&mut data, path, definition, "crontab");
            data.set(field::LINE_NUMBER, line.number as u64);
            data.set(field::RAW_LINE, trimmed.to_string());
            data.set(field::SCHEDULE_SPEC, spec);
            data.set(field::IS_REBOOT, is_reboot);
            data.set(field::COMMAND, command);
            data.set(field::LOCATION, if system { "system" } else { "user_spool" });
            if let Some(user) = &user_field {
                data.set(field::CRON_USER_FIELD, user.clone());
                data.set(USER_NAME, user.clone());
            } else if let Some(user) = &spool_user {
                data.set(USER_NAME, user.clone());
            }
            let _ = kind;
            Ok(data)
        })();
        out.push(result.map_err(|reason| {
            ForensicError::invalid_format("crontab line", format!("line {}: {reason}", line.number))
                .with_path(path.to_owned())
        }));
    }
    out
}

fn at_job_record(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicData {
    let text = String::from_utf8_lossy(bytes);
    let mut uid = None;
    let mut gid = None;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("# atrun uid=") else { continue };
        let mut parts = rest.split_whitespace();
        uid = parts.next().and_then(|s| s.parse::<u64>().ok());
        gid = parts
            .next()
            .and_then(|s| s.strip_prefix("gid="))
            .and_then(|s| s.parse::<u64>().ok());
        break;
    }
    let mut data = new_record(host, Kind::AtJob, source, acquisition);
    base_fields(&mut data, path, definition, "at_job");
    if let Some(uid) = uid {
        data.set(field::AT_UID, uid);
    }
    if let Some(gid) = gid {
        data.set(field::AT_GID, gid);
    }
    data.set(field::AT_SCRIPT, text.into_owned());
    data
}

fn anacrontab_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let mut out = Vec::new();
    for line in text::lines(bytes) {
        let raw = line.text();
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || is_env_assignment(trimmed) {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 4 {
            out.push(Err(ForensicError::invalid_format(
                "anacrontab line",
                format!(
                    "line {}: expected period, delay, job-identifier and a command, got {} token(s)",
                    line.number,
                    tokens.len()
                ),
            )
            .with_path(path.to_owned())));
            continue;
        }
        let mut data = new_record(host, Kind::AnacronTabEntry, source, acquisition);
        base_fields(&mut data, path, definition, "anacrontab");
        data.set(field::LINE_NUMBER, line.number as u64);
        data.set(field::RAW_LINE, trimmed.to_string());
        data.set(field::ANACRON_PERIOD, tokens[0].to_string());
        if let Ok(delay) = tokens[1].parse::<i64>() {
            data.set(field::ANACRON_DELAY, delay);
        }
        data.set(field::ANACRON_JOB_ID, tokens[2].to_string());
        data.set(field::COMMAND, tokens[3..].join(" "));
        out.push(Ok(data));
    }
    out
}

fn anacron_periodic_script_record(
    host: &str,
    definition: &str,
    path: &FPath,
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicData {
    let mut data = new_record(host, Kind::AnacronPeriodicScript, source, acquisition);
    base_fields(&mut data, path, definition, "anacron_periodic_script");
    if let Some(period) = path.parent().and_then(|p| p.file_name()).and_then(period_from_cron_dir_name) {
        data.set(field::ANACRON_PERIOD, period);
    }
    data.set(field::COMMAND, path.as_str().to_string());
    data
}

fn anacron_timestamp_record(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> ForensicData {
    let mut data = new_record(host, Kind::AnacronTimestamp, source, acquisition);
    base_fields(&mut data, path, definition, "anacron_timestamp");
    if let Some(period) = path.file_name().and_then(period_from_cron_dir_name) {
        data.set(field::ANACRON_PERIOD, period);
    }
    // Not decoded into a date: anacron's stamp-file encoding is implementation-specific, and
    // guessing would violate "never invent data". The raw content is kept verbatim instead.
    data.set(field::ANACRON_TIMESTAMP_RAW, String::from_utf8_lossy(bytes).trim().to_string());
    data
}

fn timer_target_service(path: &FPath, entries: &[ini::Entry]) -> (String, &'static str) {
    if let Some(explicit) = entries.iter().find(|e| e.section == "Timer" && e.key == "Unit") {
        return (explicit.value.clone(), "explicit");
    }
    let default = path
        .file_name()
        .and_then(|n| n.strip_suffix(".timer"))
        .map(|stem| format!("{stem}.service"))
        .unwrap_or_default();
    (default, "default_same_name")
}

fn systemd_timer_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicResult<ForensicData>> {
    let (entries, unparsed) = ini::parse(bytes);
    let (target_service, target_source) = timer_target_service(path, &entries);
    let mut out = Vec::new();
    for entry in &entries {
        let mut data = new_record(host, Kind::SystemdTimer, source, acquisition);
        base_fields(&mut data, path, definition, "systemd_timer");
        data.set(field::LINE_NUMBER, entry.line as u64);
        data.set(field::TIMER_KEY, format!("{}.{}", entry.section, entry.key));
        data.set(field::TIMER_VALUE, entry.value.clone());
        if !target_service.is_empty() {
            data.set(field::TIMER_TARGET_SERVICE, target_service.clone());
            data.set(field::TIMER_TARGET_SOURCE, target_source);
        }
        out.push(Ok(data));
    }
    for bad in unparsed {
        out.push(Err(ForensicError::invalid_format(
            "systemd timer unit",
            format!("line {}: not a [Section] header or key=value line: {:?}", bad.line, bad.text),
        )
        .with_path(path.to_owned())));
    }
    out
}

fn allow_deny_kind(path: &FPath) -> Option<&'static str> {
    match path.file_name()? {
        "cron.allow" => Some("cron_allow"),
        "cron.deny" => Some("cron_deny"),
        "at.allow" => Some("at_allow"),
        "at.deny" => Some("at_deny"),
        _ => None,
    }
}

fn allow_deny_records(
    host: &str,
    definition: &str,
    path: &FPath,
    bytes: &[u8],
    source: &SourceHandle,
    acquisition: Acquisition,
) -> Vec<ForensicData> {
    let allow_deny = allow_deny_kind(path);
    let mut out = Vec::new();
    for line in text::lines(bytes) {
        let raw = line.text();
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut data = new_record(host, Kind::AllowDeny, source, acquisition);
        base_fields(&mut data, path, definition, "allow_deny");
        data.set(field::LINE_NUMBER, line.number as u64);
        data.set(USER_NAME, trimmed.to_string());
        if let Some(allow_deny) = allow_deny {
            data.set(field::ALLOW_DENY_KIND, allow_deny);
        }
        out.push(data);
    }
    out
}

/// Emits one [`ForensicData`] per crontab row, at-job file, anacron job, systemd-timer directive
/// and allow/deny entry the run's [`ArtifactCatalog`] locates for [`DEFINITIONS`]. Follows
/// [`crate::unix::utmp::UtmpParserFactory`]'s pattern: stateless (`&self`), deduped by path, one
/// [`SourceHandle`] per real file, never panics on evidence.
pub struct ScheduleParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for ScheduleParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> =
            DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux job scheduling: cron, at, anacron and systemd timers",
                "Emits one record per crontab row, at-job file, anacron job, systemd-timer \
                 directive and cron/at allow-deny entry, from every location the artifact \
                 catalog resolves for LinuxCronTabs, LinuxAtJobs, LinuxScheduleFiles, \
                 AnacronFiles, LinuxSystemdTimers and CronAtAllowDenyFiles.",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![
                Artifact::Linux(LinuxArtifacts::Cron("crontab".to_string())),
                Artifact::Linux(LinuxArtifacts::Cron("at".to_string())),
                Artifact::Linux(LinuxArtifacts::Cron("anacron".to_string())),
                Artifact::Linux(LinuxArtifacts::Cron("systemd_timer".to_string())),
                Artifact::Linux(LinuxArtifacts::Cron("allow_deny".to_string())),
            ])
            .with_requirements(requirements),
        }
    }
}

impl ScheduleParserFactory {
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

impl ArtifactParserFactory for ScheduleParserFactory {
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
                "ArtifactCatalog required: this parser locates schedule files by artifact \
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
                let Some(kind) = classify(leaf, file.path.as_path()) else {
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
                    Kind::SystemCrontab => crontab_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        true,
                        &target.source,
                        acquisition,
                    ),
                    Kind::UserCrontab => crontab_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        false,
                        &target.source,
                        acquisition,
                    ),
                    Kind::AtJob => vec![Ok(at_job_record(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    ))],
                    Kind::AnacronTabEntry => anacrontab_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    ),
                    Kind::AnacronPeriodicScript => vec![Ok(anacron_periodic_script_record(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &target.source,
                        acquisition,
                    ))],
                    Kind::AnacronTimestamp => vec![Ok(anacron_timestamp_record(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    ))],
                    Kind::SystemdTimer => systemd_timer_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    ),
                    Kind::AllowDeny => allow_deny_records(
                        &host,
                        &target.definition,
                        target.path.as_path(),
                        &bytes,
                        &target.source,
                        acquisition,
                    )
                    .into_iter()
                    .map(Ok)
                    .collect(),
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
    fn detects_five_field_and_special_specs() {
        let tokens: Vec<&str> = "*/5 * * * * root somecmd".split_whitespace().collect();
        let (spec, is_reboot, consumed) = detect_spec(&tokens).unwrap();
        assert_eq!(spec, "*/5 * * * *");
        assert!(!is_reboot);
        assert_eq!(consumed, 5);

        let tokens: Vec<&str> = "@reboot root somecmd".split_whitespace().collect();
        let (spec, is_reboot, consumed) = detect_spec(&tokens).unwrap();
        assert_eq!(spec, "@reboot");
        assert!(is_reboot);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn env_assignment_lines_are_recognized_and_schedule_lines_are_not() {
        assert!(is_env_assignment("MAILTO=root"));
        assert!(is_env_assignment("PATH=/usr/bin:/bin"));
        assert!(!is_env_assignment("*/5 * * * * root cmd"));
        assert!(!is_env_assignment("0 3 * * * root VAR=1 cmd"));
    }

    #[test]
    fn classifies_leaf_definitions_by_path() {
        assert_eq!(
            classify("LinuxCronTabs", FPath::new("var/spool/cron/crontabs/alice")),
            Some(Kind::UserCrontab)
        );
        assert_eq!(classify("LinuxCronTabs", FPath::new("etc/crontab")), Some(Kind::SystemCrontab));
        assert_eq!(classify("AnacronFiles", FPath::new("etc/anacrontab")), Some(Kind::AnacronTabEntry));
        assert_eq!(
            classify("AnacronFiles", FPath::new("var/spool/anacron/cron.daily")),
            Some(Kind::AnacronTimestamp)
        );
        assert_eq!(
            classify("AnacronFiles", FPath::new("etc/cron.daily/logrotate")),
            Some(Kind::AnacronPeriodicScript)
        );
        assert_eq!(classify("LinuxScheduleFiles", FPath::new("etc/crontab")), None);
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
            file_def(
                "LinuxCronTabs",
                &[Cow::Borrowed("/etc/crontab"), Cow::Borrowed("/etc/cron.d/*"), Cow::Borrowed("/var/spool/cron/**")],
            ),
            file_def("LinuxAtJobs", &[Cow::Borrowed("/var/spool/at/*")]),
            definition(
                "LinuxScheduleFiles",
                ArtifactSource::Group {
                    names: Cow::Borrowed(&[
                        Cow::Borrowed("AnacronFiles"),
                        Cow::Borrowed("LinuxCronTabs"),
                        Cow::Borrowed("LinuxAtJobs"),
                    ]),
                },
            ),
            file_def(
                "AnacronFiles",
                &[
                    Cow::Borrowed("/etc/anacrontab"),
                    Cow::Borrowed("/etc/cron.daily/*"),
                    Cow::Borrowed("/var/spool/anacron/cron.daily"),
                ],
            ),
            file_def("LinuxSystemdTimers", &[Cow::Borrowed("/etc/systemd/system/*.timer")]),
            file_def(
                "CronAtAllowDenyFiles",
                &[
                    Cow::Borrowed("/etc/cron.allow"),
                    Cow::Borrowed("/etc/cron.deny"),
                    Cow::Borrowed("/etc/at.allow"),
                    Cow::Borrowed("/etc/at.deny"),
                ],
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
        let parser = ScheduleParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = ScheduleParserFactory::new();
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
    fn a_system_crontab_row_carries_the_user_field_and_reboot_flag() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("etc/crontab", b"@reboot root /usr/local/bin/startup.sh\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(
            items.iter().all(|i| i.is_ok()),
            "unexpected errors: {:?}",
            items.iter().filter_map(|i| i.as_ref().err()).collect::<Vec<_>>()
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].field_as_u64(field::IS_REBOOT), Some(1)); // bool fields are U64(0|1)
        assert_eq!(field(records[0], USER_NAME), Some("root"));
        assert_eq!(field(records[0], field::LOCATION), Some("system"));
        assert_eq!(records[0].artifact(), &Artifact::Linux(LinuxArtifacts::Cron("crontab".to_string())));
    }

    #[test]
    fn a_user_spool_crontab_has_no_user_field_but_derives_user_from_the_filename() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("var/spool/cron/crontabs/alice", b"*/5 * * * * /home/alice/poll.sh\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], USER_NAME), Some("alice"));
        assert_eq!(field(records[0], field::LOCATION), Some("user_spool"));
    }

    #[test]
    fn env_assignment_lines_and_comments_are_skipped_not_reported_malformed() {
        let vfs = InMemoryVirtualFileSystem::new().with_file(
            "etc/crontab",
            b"# a comment\nMAILTO=root\n@daily root /usr/bin/true\n".to_vec(),
        );
        let items = run(&sources(vfs));
        assert!(items.iter().all(|i| i.is_ok()));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn a_malformed_crontab_row_is_an_err_item() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/crontab", b"not a valid cron line\n".to_vec());
        let items = run(&sources(vfs));
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
    }

    #[test]
    fn an_at_job_captures_uid_gid_and_the_full_script() {
        let script = b"#!/bin/sh\n# atrun uid=1000 gid=1000\numask 22\ncd /home/alice || exit 1\necho hi\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("var/spool/at/a0001a", script.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].field_as_u64(field::AT_UID), Some(1000));
        assert_eq!(records[0].field_as_u64(field::AT_GID), Some(1000));
        assert!(field(records[0], field::AT_SCRIPT).unwrap().contains("echo hi"));
    }

    #[test]
    fn a_periodic_cron_script_is_one_record_with_its_period() {
        let vfs =
            InMemoryVirtualFileSystem::new().with_file("etc/cron.daily/logrotate", b"#!/bin/sh\nlogrotate\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::ANACRON_PERIOD), Some("daily"));
    }

    #[test]
    fn an_anacron_timestamp_file_keeps_the_raw_stamp_without_decoding_it() {
        let vfs = InMemoryVirtualFileSystem::new()
            .with_file("var/spool/anacron/cron.daily", b"20250131\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], field::ANACRON_TIMESTAMP_RAW), Some("20250131"));
    }

    #[test]
    fn a_systemd_timer_without_an_explicit_unit_resolves_the_default_same_name_service() {
        let bytes = b"[Unit]\nDescription=Backup timer\n\n[Timer]\nOnCalendar=daily\n\n[Install]\nWantedBy=timers.target\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/systemd/system/backup.timer", bytes.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(!records.is_empty());
        assert!(records.iter().all(|r| field(r, field::TIMER_TARGET_SERVICE) == Some("backup.service")));
        assert!(records.iter().all(|r| field(r, field::TIMER_TARGET_SOURCE) == Some("default_same_name")));
    }

    #[test]
    fn a_systemd_timer_with_an_explicit_unit_overrides_the_default() {
        let bytes = b"[Timer]\nOnCalendar=daily\nUnit=other.service\n";
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/systemd/system/backup.timer", bytes.to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert!(records.iter().any(|r| {
            field(r, field::TIMER_TARGET_SERVICE) == Some("other.service")
                && field(r, field::TIMER_TARGET_SOURCE) == Some("explicit")
        }));
    }

    #[test]
    fn allow_deny_entries_carry_the_username_and_file_kind() {
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/cron.allow", b"alice\nbob\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(field(records[0], USER_NAME), Some("alice"));
        assert_eq!(field(records[0], field::ALLOW_DENY_KIND), Some("cron_allow"));
    }

    #[test]
    fn a_file_reached_only_through_the_group_definition_is_still_classified_precisely() {
        // `LinuxScheduleFiles` names no files of its own; its resolution returns files tagged
        // with the real leaf definition, which this parser classifies just like a direct hit.
        let vfs = InMemoryVirtualFileSystem::new().with_file("etc/anacrontab", b"1 5 job.id /bin/true\n".to_vec());
        let items = run(&sources(vfs));
        let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(field(records[0], ARTIFACT_DEFINITION), Some("AnacronFiles"));
    }
}
