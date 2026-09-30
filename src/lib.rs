//! Linux artifact parsers: utmp/wtmp/btmp/lastlog login records, journald, syslog and more.
//!
//! ## Status
//!
//! [`unix::utmp::UtmpParserFactory`] is the first parser: `utmp`/`wtmp`/`btmp`/`lastlog` login
//! records, resolved through the run's artifact catalog (no hardcoded paths). Everything else
//! (`journal/`, `log/`, `containers/`, `shell.rs`, `schedule.rs`, `units.rs`, `packages.rs`,
//! `identity.rs`) is still a gap — see the workspace `FINDINGS.md` entry for `frnsc-linux`.

pub mod unix;

use std::sync::Arc;

use forensic_rs::prelude::ArtifactParserFactory;

/// Every `frnsc-linux` parser factory, in the order
/// `frnsc-pipeline::catalog::Catalog::standard` should register them.
pub fn standard_parsers() -> Vec<Arc<dyn ArtifactParserFactory>> {
    vec![Arc::new(unix::utmp::UtmpParserFactory::new())]
}
