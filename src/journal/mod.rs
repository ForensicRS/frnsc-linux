//! A forensic-grade reader for systemd journal (`.journal`) files.
//!
//! Deliberately depends on nothing else in `frnsc-linux`: every `use crate::journal::...` in this
//! module tree only ever reaches other `journal::*` modules, never `crate::unix`/`crate::log`/etc.
//! — so this stays a crate-in-waiting if a second consumer of a journal reader ever appears
//! elsewhere in the ecosystem.
//!
//! Reference: <https://systemd.io/JOURNAL_FILE_FORMAT/>, cross-checked against systemd's actual
//! `src/libsystemd/sd-journal/{journal-def.h,journal-file.c,lookup3.c}` and
//! `src/basic/{compress.c,siphash24.c}` source for every byte offset, hash algorithm and
//! compression framing this module relies on — see each submodule's own doc comment for exactly
//! what was checked where.
//!
//! # Two read paths, always both
//!
//! [`reader::JournalFile::read_all`] always runs the indexed path (`header.entry_array_offset` ->
//! `EntryArrayObject` chain) and the recovery scan (a linear walk of the whole arena,
//! independent of any pointer) in the same call, tagging entries the recovery scan alone found as
//! [`reader::ResolvedEntry::recovery_only`]. See that module's docs for why this is the default,
//! not a fallback.
//!
//! # Module layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`header`] | File header, compatible/incompatible flags, state |
//! | [`object`] | `ObjectHeader` and the seven object types, compact and regular layouts |
//! | [`array`] | Entry-array chain walk, with cycle detection |
//! | [`hash`] | The two hash functions a `DATA` object's own hash can be, verified against systemd's own source |
//! | [`compress`] | XZ / LZ4 / ZSTD payload decompression, one Cargo feature per codec |
//! | [`window`] | Bounds-checked `offset -> &[u8]` view over the file |
//! | [`scan`] | Linear object walk + carving in slack (the recovery path) |
//! | [`integrity`] | seqnum/timestamp/count consistency -> one `Err` finding per signal |
//! | [`reader`] | [`reader::JournalFile`] (the real entry point) + the `EventLogReader` impl |
//! | [`factory`] | `FormatFactory` (probes the `LPKSHHRH` signature) |
//! | [`parser`] | [`parser::JournalParserFactory`] — `linux.journal`, the pipeline integration |

pub mod array;
pub mod compress;
pub mod factory;
pub mod hash;
pub mod header;
pub mod integrity;
pub mod object;
pub mod parser;
pub mod reader;
pub mod scan;
pub mod window;

pub use factory::JournalFormatFactory;
pub use parser::JournalParserFactory;
pub use reader::{JournalEventLogReader, JournalFile};
