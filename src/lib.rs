//! Linux artifact parsers: utmp/wtmp/btmp/lastlog login records, journald, syslog and more.
//!
//! ## Status
//!
//! [`unix::utmp`] implements the byte-level `utmp`/`wtmp`/`btmp` record layout. Wiring it into
//! an `ArtifactParserFactory` — resolving `LinuxUtmpFiles`/`LinuxWtmp`/`LinuxLastlogFile`/
//! `UnixUtmpFile` through the run's artifact catalog (no hardcoded paths) and emitting
//! `Artifact::Linux(LinuxArtifacts::Utmp)` records — needs an additive `forensic-rs` change
//! that has not landed yet: a new `LinuxArtifacts::Utmp` variant and a handful of `dictionary`
//! ECS constants. See the workspace `FINDINGS.md` entry for `frnsc-linux` for the tracking
//! issue. [`standard_parsers`] stays empty until that lands.

pub mod unix;

use std::sync::Arc;

use forensic_rs::prelude::ArtifactParserFactory;

/// Every `frnsc-linux` parser factory, in the order
/// `frnsc-pipeline::catalog::Catalog::standard` should register them.
///
/// Empty today — see the module docs.
pub fn standard_parsers() -> Vec<Arc<dyn ArtifactParserFactory>> {
    Vec::new()
}
