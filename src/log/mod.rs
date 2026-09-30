//! Line-oriented text logs: the shared scaffold ([`text`]) plus the two format matchers built on
//! it, syslog and auditd. `shell`/`packages` are siblings at the crate root, not nested here,
//! because they are not full-line "log" records in the same sense — see their own module docs.

pub mod audit;
pub mod syslog;
pub mod text;
