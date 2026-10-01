//! Integration tests against real-world artifacts from the shared test corpus.
//!
//! Register the samples this crate needs in `forensic-testenv/manifest/artifacts.toml`
//! (with `used_by = ["frnsc-linux"]`), then fetch them with
//! `forensic-testenv/tools/fetch.py --crate frnsc-linux`. Tests skip when a sample has
//! not been fetched, and fail under `FORENSIC_TESTDATA_STRICT=1` (CI).

use frnsc_linux::log::{audit, syslog};
use frnsc_linux::shell;
use frnsc_linux::unix::utmp;

#[test]
fn real_sample_does_not_panic() {
    // Registered by FOR-29 (forensic-testenv Linux fixtures); skips until then.
    let path = forensic_testdata::artifact_or_skip!("frnsc-linux-utmp-sample");
    let data = std::fs::read(path).unwrap();
    // Scanning must never panic, whatever layout or truncation the real sample has.
    let _ = utmp::scan_records(&data);
}

fn lines_of(path: &std::path::Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    frnsc_linux::log::text::scan_lines(&bytes)
        .iter()
        .map(|l| l.text().into_owned())
        .collect()
}

#[test]
fn real_rfc3164_syslog_parses_every_line() {
    // Registered by FOR-29; skips until fetched. See `generators/textlogs/syslog-rfc3164.log`.
    let path = forensic_testdata::artifact_or_skip!("linux-syslog-rfc3164-synthetic");
    let lines = lines_of(&path);
    assert!(!lines.is_empty());
    for line in &lines {
        let parsed = syslog::parse_line(line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        assert_eq!(parsed.format, syslog::SyslogFormat::Rfc3164);
        assert!(parsed.hostname.is_some());
    }
}

#[test]
fn real_rfc5424_syslog_parses_every_line() {
    // Registered by FOR-29; skips until fetched. See `generators/textlogs/syslog-rfc5424.log`.
    let path = forensic_testdata::artifact_or_skip!("linux-syslog-rfc5424-synthetic");
    let lines = lines_of(&path);
    assert!(!lines.is_empty());
    for line in &lines {
        let parsed = syslog::parse_line(line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        assert_eq!(parsed.format, syslog::SyslogFormat::Rfc5424);
        assert!(
            parsed.timestamp.is_some(),
            "every line in this fixture carries a real timestamp"
        );
    }
    // The fixture documents one structured-data element and one nil (`-`) case.
    let with_sd = lines
        .iter()
        .filter_map(|l| syslog::parse_line(l).ok())
        .filter(|p| p.structured_data.is_some())
        .count();
    assert!(with_sd >= 1);
}

#[test]
fn real_authlog_has_no_pri_prefix_and_still_parses() {
    // Registered by FOR-29; skips until fetched. See `generators/textlogs/auth.log`.
    let path = forensic_testdata::artifact_or_skip!("linux-authlog-synthetic");
    let lines = lines_of(&path);
    assert!(!lines.is_empty());
    for line in &lines {
        let parsed = syslog::parse_line(line).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        assert_eq!(
            parsed.priority, None,
            "this fixture's lines never carry a <PRI> prefix"
        );
    }
}

#[test]
fn real_auditlog_groups_by_serial_and_never_panics() {
    // Registered by FOR-29; skips until fetched. See `generators/textlogs/audit.log`.
    let path = forensic_testdata::artifact_or_skip!("linux-auditlog-synthetic");
    let lines = lines_of(&path);
    assert!(!lines.is_empty());
    let mut serials = std::collections::BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let parsed = audit::parse_line(line, i + 1).unwrap_or_else(|e| panic!("{e}: {line:?}"));
        serials.insert(parsed.serial);
    }
    assert_eq!(
        serials.len(),
        3,
        "this fixture's USER_AUTH/USER_LOGIN/SYSCALL lines each carry a distinct serial"
    );
}

#[test]
fn real_bash_history_plain_has_no_timestamps() {
    // Registered by FOR-29; skips until fetched. See `generators/textlogs/bash_history_plain`.
    let path = forensic_testdata::artifact_or_skip!("linux-bash-history-plain-synthetic");
    let bytes = std::fs::read(path).unwrap();
    let text_lines = frnsc_linux::log::text::scan_lines(&bytes);
    let entries = shell::parse_bash(&text_lines);
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|e| e.timestamp.is_none()));
}

#[test]
fn real_bash_history_histtimeformat_has_a_timestamp_per_command() {
    // Registered by FOR-29; skips until fetched. See
    // `generators/textlogs/bash_history_histtimeformat`.
    let path = forensic_testdata::artifact_or_skip!("linux-bash-history-histtimeformat-synthetic");
    let bytes = std::fs::read(path).unwrap();
    let text_lines = frnsc_linux::log::text::scan_lines(&bytes);
    let entries = shell::parse_bash(&text_lines);
    assert!(!entries.is_empty());
    assert!(
        entries.iter().all(|e| e.timestamp.is_some()),
        "every command in this fixture is preceded by a #<epoch> marker"
    );
}
