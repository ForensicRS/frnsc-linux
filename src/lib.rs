//! Linux artifact parsers: utmp/wtmp/btmp/lastlog login records, journald, syslog and more.
//!
//! ## Status
//!
//! [`unix::utmp::UtmpParserFactory`] (`linux.utmp`), the text-log family —
//! [`log::syslog::SyslogParserFactory`] (`linux.syslog`), [`log::audit::AuditParserFactory`]
//! (`linux.audit`), [`shell::ShellHistoryParserFactory`] (`linux.shell_history`) and
//! [`packages::PackagesParserFactory`] (`linux.packages`) — and the config/state family —
//! [`unix::accounts::AccountsParserFactory`] (`linux.accounts`), [`unix::ssh::SshParserFactory`]
//! (`linux.ssh`), [`schedule::ScheduleParserFactory`] (`linux.schedule`),
//! [`units::UnitsParserFactory`] (`linux.units`) and
//! [`identity::IdentityParserFactory`] (`linux.identity`) — are landed, resolved through the
//! run's artifact catalog (no hardcoded paths). Everything else (`journal/`, `containers/`) is
//! still a gap — see the workspace `FINDINGS.md` entry for `frnsc-linux`.

pub mod identity;
mod ini;
pub mod log;
pub mod packages;
pub mod schedule;
pub mod shell;
mod text;
pub mod unix;
pub mod units;

use std::sync::Arc;

use forensic_rs::prelude::ArtifactParserFactory;

/// Every `frnsc-linux` parser factory, in the order
/// `frnsc-pipeline::catalog::Catalog::standard` should register them.
pub fn standard_parsers() -> Vec<Arc<dyn ArtifactParserFactory>> {
    vec![
        Arc::new(unix::utmp::UtmpParserFactory::new()),
        Arc::new(unix::accounts::AccountsParserFactory::new()),
        Arc::new(unix::ssh::SshParserFactory::new()),
        Arc::new(log::syslog::SyslogParserFactory::new()),
        Arc::new(log::audit::AuditParserFactory::new()),
        Arc::new(shell::ShellHistoryParserFactory::new()),
        Arc::new(packages::PackagesParserFactory::new()),
        Arc::new(schedule::ScheduleParserFactory::new()),
        Arc::new(units::UnitsParserFactory::new()),
        Arc::new(identity::IdentityParserFactory::new()),
    ]
}
