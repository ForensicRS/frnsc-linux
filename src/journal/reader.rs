//! Orchestrates one journal file end to end: header, indexed walk, recovery scan, integrity
//! checks, and per-entry field resolution (decompression, hash cross-checks, `NAME=value`
//! splitting) — then exposes it three ways: [`JournalFile::read_all`] (the data
//! `crate::journal::parser` turns into [`forensic_rs::field::Field`]s), and the
//! [`forensic_rs::traits::events::EventLogReader`] impl below for callers that want the
//! framework's generic event-log shape instead.
//!
//! # Read order
//!
//! [`JournalFile::read_all`] always runs the indexed path (following `entry_array_offset`) first,
//! then the recovery scan (an independent linear walk of the whole arena), and appends whatever
//! the recovery scan found that the indexed walk did not reach, each tagged
//! [`ResolvedEntry::recovery_only`]. This is not a fallback used only when the indexed path fails
//! — it always runs, because `state == ONLINE` with stale tail pointers (an image taken from a
//! running host) is exactly the case where the indexed path alone quietly under-reports, with no
//! error of its own to signal it.
//!
//! # Trusted vs. client-forgeable fields
//!
//! journald prefixes the fields it sets itself (`_PID`, `_UID`, `_COMM`, `_EXE`,
//! `_SYSTEMD_UNIT`, `_BOOT_ID`, `_MACHINE_ID`, `_HOSTNAME`, ...) with `_`; fields without the
//! prefix (`MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `CODE_FILE`, ...) come from the logging
//! client and are exactly as forgeable as anything else that client writes to a socket. This
//! reader keeps that distinction rather than flattening it, but does **not** encode it by minting
//! a fake `Recovery`/`Acquisition` pair to force a different
//! [`forensic_rs::provenance::Confidence`] on forgeable fields: `Confidence` in `forensic-rs`
//! answers "how reliably was this recovered from storage", not "how much should an analyst trust
//! what the field claims" — those are different questions, and it would be inventing data about
//! *how* a field was recovered (it wasn't recovered any differently) to bend that API into
//! answering the second one. Instead, [`crate::journal::parser`] records two explicit,
//! sorted field-name lists (`linux.journal.trusted_fields` / `linux.journal.forgeable_fields`) on
//! every record, so the distinction is visible to an analyst without misusing provenance.

use std::collections::BTreeSet;

use forensic_rs::prelude::*;

use crate::journal::array;
use crate::journal::compress;
use crate::journal::hash;
use crate::journal::header::{self, Header};
use crate::journal::integrity::{self, IndexedEntry as IntegrityEntry, Signals};
use crate::journal::object::{self, EntryObject};
use crate::journal::scan;
use crate::journal::window::Window;

/// One field resolved from an `ENTRY` item's referenced `DATA` object.
#[derive(Debug, Clone)]
pub struct ResolvedField {
    /// The field name exactly as journald wrote it (`_PID`, `MESSAGE`, `SYSLOG_IDENTIFIER`, ...).
    pub raw_name: String,
    /// The decoded value if it is valid UTF-8 — the overwhelmingly common case for journal
    /// fields.
    pub value_utf8: Option<String>,
    /// The exact decompressed value bytes, always kept regardless of [`Self::value_utf8`] — see
    /// the crate-level hostile-input rule that non-UTF-8 values are never dropped.
    pub value_raw: Vec<u8>,
}

/// One `ENTRY` object resolved into its fields.
#[derive(Debug, Clone)]
pub struct ResolvedEntry {
    pub offset: u64,
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub boot_id: [u8; 16],
    /// `true` when this entry was found only by the recovery scan — not reachable from
    /// `entry_array_offset`'s chain. See the module docs' "Read order" section.
    pub recovery_only: bool,
    pub fields: Vec<ResolvedField>,
}

/// [`JournalFile::read_all`]'s result: entries (each independently `Ok`/`Err` — one corrupt entry
/// never drops the rest) and the file-level integrity findings.
pub struct JournalReadResult {
    pub entries: Vec<ForensicResult<ResolvedEntry>>,
    pub findings: Vec<ForensicError>,
}

/// A parsed journal file, ready for [`Self::read_all`] or the [`EventLogReader`] impl below.
pub struct JournalFile {
    header: Header,
    data: Vec<u8>,
}

/// Bound on entry-array chain hops and on total recovery-scan object count, independent of any
/// count the header itself declares (a hostile header could declare `n_objects = 0` and still
/// have a huge arena). Generous enough for any real journal file, since a hop or an object is at
/// minimum a handful of bytes.
fn safety_hop_limit(file_len: u64) -> u64 {
    (file_len / 16).max(4096)
}

impl JournalFile {
    /// Parses just the header. Bounds-checked and cheap — the indexed/recovery walks only happen
    /// in [`Self::read_all`], not here, so a caller that only wants
    /// [`Self::header`] (e.g. [`crate::journal::factory`]'s probe) never pays for them.
    pub fn parse(data: Vec<u8>) -> ForensicResult<Self> {
        let header = header::parse(&data)?;
        Ok(JournalFile { header, data })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    fn window(&self) -> Window<'_> {
        Window::new(&self.data, self.header.header_size, self.header.arena_size)
    }

    /// Runs the indexed path, then the recovery scan, resolves every entry's fields, and runs
    /// every integrity check. `max_decompressed` bounds any single field's decompressed size (see
    /// [`compress::MAX_DECOMPRESSED_SIZE`] for the default).
    pub fn read_all(&self, max_decompressed: u64) -> JournalReadResult {
        let win = self.window();
        let compact = self.header.is_compact();
        let hop_limit = safety_hop_limit(win.file_len());

        let mut entries: Vec<ForensicResult<ResolvedEntry>> = Vec::new();
        let mut hash_stats = HashStats::default();

        let chain = array::walk_chain(&win, self.header.entry_array_offset, compact, hop_limit);
        if chain.cycle_detected {
            entries.push(Err(ForensicError::invalid_format(
                "journal entry array chain",
                "a cycle was detected while following next_entry_array_offset; the indexed walk \
                 stopped there (see the recovery scan for entries beyond it)",
            )));
        }
        if chain.hop_limit_reached {
            entries.push(Err(ForensicError::invalid_format(
                "journal entry array chain",
                format!(
                    "the entry-array chain did not terminate within {hop_limit} hops; the \
                     indexed walk stopped there"
                ),
            )));
        }
        let item_offsets = array::flatten_item_offsets(&chain);
        if let Some(e) = chain.error {
            entries.push(Err(e));
        }
        let mut indexed_summaries: Vec<IntegrityEntry> = Vec::with_capacity(item_offsets.len());
        let mut reachable: BTreeSet<u64> = BTreeSet::new();

        for offset in item_offsets {
            match parse_and_resolve_entry(
                &win,
                &self.header,
                offset,
                compact,
                max_decompressed,
                &mut hash_stats,
            ) {
                Ok((entry, mut field_errors)) => {
                    indexed_summaries.push(IntegrityEntry {
                        offset: entry.offset,
                        seqnum: entry.seqnum,
                        realtime: entry.realtime,
                        boot_id: entry.boot_id,
                    });
                    reachable.insert(entry.offset);
                    entries.append(&mut field_errors);
                    entries.push(Ok(entry));
                }
                Err(e) => entries.push(Err(e.with_offset(offset))),
            }
        }

        let recovery = scan::scan(
            &win,
            self.header.header_size,
            compact,
            self.header.n_objects.saturating_add(hop_limit),
        );
        for (offset, entry_obj) in &recovery.entries {
            if reachable.contains(offset) {
                continue;
            }
            let (fields, mut field_errors) = resolve_fields(
                &win,
                &self.header,
                entry_obj,
                compact,
                max_decompressed,
                &mut hash_stats,
            );
            entries.append(&mut field_errors);
            entries.push(Ok(ResolvedEntry {
                offset: *offset,
                seqnum: entry_obj.seqnum,
                realtime: entry_obj.realtime,
                monotonic: entry_obj.monotonic,
                boot_id: entry_obj.boot_id,
                recovery_only: true,
                fields,
            }));
        }
        for err in recovery.errors.iter() {
            entries.push(Err(err.clone()));
        }

        let signals = Signals {
            header: &self.header,
            indexed_entries: &indexed_summaries,
            recovery: &recovery,
            item_hash_mismatches: hash_stats.item_hash_mismatches,
            item_hash_mismatch_first_offset: hash_stats.item_hash_mismatch_first_offset,
            data_hash_recompute_mismatches: hash_stats.data_hash_recompute_mismatches,
            data_hash_recompute_mismatch_first_offset: hash_stats
                .data_hash_recompute_mismatch_first_offset,
        };
        let findings = integrity::run(&signals);

        JournalReadResult { entries, findings }
    }
}

#[derive(Default)]
struct HashStats {
    item_hash_mismatches: u64,
    item_hash_mismatch_first_offset: Option<u64>,
    data_hash_recompute_mismatches: u64,
    data_hash_recompute_mismatch_first_offset: Option<u64>,
}

fn parse_and_resolve_entry(
    win: &Window<'_>,
    header: &Header,
    offset: u64,
    compact: bool,
    max_decompressed: u64,
    hash_stats: &mut HashStats,
) -> ForensicResult<(ResolvedEntry, Vec<ForensicResult<ResolvedEntry>>)> {
    let obj_header = object::parse_header(win, offset)?;
    let entry_obj = object::parse_entry_object(win, offset, &obj_header, compact)?;
    let (fields, field_errors) =
        resolve_fields(win, header, &entry_obj, compact, max_decompressed, hash_stats);
    Ok((
        ResolvedEntry {
            offset: entry_obj.offset,
            seqnum: entry_obj.seqnum,
            realtime: entry_obj.realtime,
            monotonic: entry_obj.monotonic,
            boot_id: entry_obj.boot_id,
            recovery_only: false,
            fields,
        },
        field_errors,
    ))
}

/// Resolves every item of one already-parsed `ENTRY` object into fields, and runs the two
/// hash-consistency checks along the way (folded into `hash_stats` rather than returned per-item,
/// since the design aggregates them into one summary finding — see
/// `crate::journal::integrity`). A field that fails to resolve (a corrupt `DATA` object, a
/// decompression failure, a payload with no `=`) is one `Err` item in the returned list, and the
/// rest of the entry's fields are still resolved — mirroring the crate-wide "one bad record is
/// one `Err` item" rule at field granularity, since a journal entry has many independent fields
/// where `utmp`'s fixed-width record has none.
fn resolve_fields(
    win: &Window<'_>,
    header: &Header,
    entry: &EntryObject,
    compact: bool,
    max_decompressed: u64,
    hash_stats: &mut HashStats,
) -> (Vec<ResolvedField>, Vec<ForensicResult<ResolvedEntry>>) {
    let mut fields = Vec::with_capacity(entry.items.len());
    let mut errors: Vec<ForensicResult<ResolvedEntry>> = Vec::new();

    for item in &entry.items {
        if item.object_offset == 0 {
            continue; // an empty/unused item slot, not a real reference
        }
        let data_obj = match object::parse_header(win, item.object_offset).and_then(|h| {
            object::parse_data_object(win, item.object_offset, &h, compact)
        }) {
            Ok(d) => d,
            Err(e) => {
                let context = format!("journal entry at offset {}", entry.offset);
                errors.push(Err(e
                    .with_offset(item.object_offset)
                    .with_path(FPathBuf::from(context.as_str()))));
                continue;
            }
        };

        if let Some(item_hash) = item.hash {
            if item_hash != data_obj.hash {
                hash_stats.item_hash_mismatches += 1;
                hash_stats
                    .item_hash_mismatch_first_offset
                    .get_or_insert(entry.offset);
            }
        }

        let decompressed = match data_obj.compression {
            None => data_obj.payload_raw.clone(),
            Some(codec) => match compress::decompress(codec, &data_obj.payload_raw, max_decompressed) {
                Ok(bytes) => bytes,
                Err(e) => {
                    errors.push(Err(e.with_offset(data_obj.offset)));
                    continue;
                }
            },
        };

        let recomputed = if header.is_keyed_hash() {
            hash::keyed_hash64(&decompressed, &header.file_id)
        } else {
            hash::jenkins_hash64(&decompressed)
        };
        if recomputed != data_obj.hash {
            hash_stats.data_hash_recompute_mismatches += 1;
            hash_stats
                .data_hash_recompute_mismatch_first_offset
                .get_or_insert(data_obj.offset);
        }

        match split_field(&decompressed) {
            Some((name, value)) => {
                let value_utf8 = std::str::from_utf8(value).ok().map(|s| s.to_string());
                fields.push(ResolvedField {
                    raw_name: name,
                    value_utf8,
                    value_raw: value.to_vec(),
                });
            }
            None => {
                errors.push(Err(ForensicError::invalid_format(
                    "journal data object",
                    format!(
                        "payload at offset {} has no '=' separator between field name and value",
                        data_obj.offset
                    ),
                )
                .with_offset(data_obj.offset)));
            }
        }
    }
    (fields, errors)
}

/// Splits a decompressed `DATA` payload at its first `=` into `(name, value)`. The name is
/// lossy-decoded (journald field names are always plain ASCII identifiers in practice); the value
/// is returned as a byte slice so the caller decides UTF-8 validity itself.
fn split_field(payload: &[u8]) -> Option<(String, &[u8])> {
    let pos = payload.iter().position(|&b| b == b'=')?;
    let name = String::from_utf8_lossy(&payload[..pos]).into_owned();
    Some((name, &payload[pos + 1..]))
}

// ---------------------------------------------------------------------------------------------
// EventLogReader: the framework's generic event-log abstraction. Real pipeline integration goes
// through `crate::journal::parser::JournalParserFactory` instead (see the module docs); this impl
// exists because the design calls for it and because a generic consumer that already knows how to
// walk an `EventLogReader` (independent of `frnsc-linux`) can use it, accepting that it is a
// lossier view: `EventRecord` has no slot for the trusted/forgeable distinction above, and no
// slot for non-UTF-8 raw bytes, so both are necessarily flattened here.
// ---------------------------------------------------------------------------------------------

/// The one pseudo-channel this reader exposes: a single journal file has no notion of multiple
/// Windows-style channels, so it is treated as one channel named after the file's own `file_id`.
fn channel_name(header: &Header) -> String {
    format!("journal:{}", header::hex_encode(&header.file_id))
}

/// journald's `PRIORITY` field is a syslog severity 0-7; [`EventLevel`] only has five variants.
/// This mapping is deliberately lossy and documented rather than silently approximate:
/// 0-2 (Emergency/Alert/Critical) -> Critical, 3 (Error) -> Error, 4 (Warning) -> Warning,
/// 5-6 (Notice/Informational) -> Information, 7 (Debug) -> Verbose.
fn priority_to_level(priority: u8) -> EventLevel {
    match priority {
        0..=2 => EventLevel::Critical,
        3 => EventLevel::Error,
        4 => EventLevel::Warning,
        5 | 6 => EventLevel::Information,
        _ => EventLevel::Verbose,
    }
}

fn resolved_entry_to_event_record(header: &Header, entry: &ResolvedEntry) -> EventRecord {
    let mut data = std::collections::BTreeMap::new();
    let mut level = EventLevel::Information;
    let mut provider = String::new();
    let mut computer = String::new();
    for f in &entry.fields {
        let value = f
            .value_utf8
            .clone()
            .unwrap_or_else(|| String::from_utf8_lossy(&f.value_raw).into_owned());
        match f.raw_name.as_str() {
            "PRIORITY" => {
                if let Ok(p) = value.parse::<u8>() {
                    level = priority_to_level(p);
                }
            }
            "SYSLOG_IDENTIFIER" | "_COMM" if provider.is_empty() => provider = value.clone(),
            "_HOSTNAME" => computer = value.clone(),
            _ => {}
        }
        data.insert(Text::Owned(f.raw_name.clone()), Field::Text(Text::Owned(value)));
    }
    EventRecord {
        record_id: entry.seqnum,
        event_id: 0,
        timestamp: ForensicTimestamp::from_unix_micros(entry.realtime as i64),
        provider,
        channel: channel_name(header),
        level,
        computer,
        user_sid: None,
        data,
    }
}

pub struct JournalEventLogReader {
    file: JournalFile,
}

impl JournalEventLogReader {
    pub fn from_bytes(data: Vec<u8>) -> ForensicResult<Self> {
        Ok(JournalEventLogReader {
            file: JournalFile::parse(data)?,
        })
    }
}

impl EventLogReader for JournalEventLogReader {
    fn channels(&self) -> ForensicResult<Vec<String>> {
        Ok(vec![channel_name(&self.file.header)])
    }

    fn query(&self, query: &EventLogQuery) -> ForensicResult<Box<dyn EventLogIterator + '_>> {
        let result = self.file.read_all(compress::MAX_DECOMPRESSED_SIZE);
        let header = self.file.header().clone();
        let records: Vec<EventRecord> = result
            .entries
            .into_iter()
            .filter_map(|e| e.ok())
            .map(|e| resolved_entry_to_event_record(&header, &e))
            .filter(|record| query.matches(record))
            .collect();
        Ok(Box::new(VecEventLogIterator {
            records: records.into_iter(),
        }))
    }

    fn event_count(&self, _channel: &str) -> ForensicResult<u64> {
        let result = self.file.read_all(compress::MAX_DECOMPRESSED_SIZE);
        Ok(result.entries.iter().filter(|e| e.is_ok()).count() as u64)
    }
}

struct VecEventLogIterator {
    records: std::vec::IntoIter<EventRecord>,
}

impl EventLogIterator for VecEventLogIterator {
    fn next(&mut self) -> ForensicResult<Option<EventRecord>> {
        Ok(self.records.next())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_simple_field() {
        let (name, value) = split_field(b"MESSAGE=hello world").unwrap();
        assert_eq!(name, "MESSAGE");
        assert_eq!(value, b"hello world");
    }

    #[test]
    fn a_field_with_no_separator_is_none_not_a_panic() {
        assert!(split_field(b"NOVALUE").is_none());
    }

    #[test]
    fn a_value_containing_more_equals_signs_only_splits_on_the_first() {
        let (name, value) = split_field(b"CODE_FILE=src/main.rs=extra").unwrap();
        assert_eq!(name, "CODE_FILE");
        assert_eq!(value, b"src/main.rs=extra");
    }

    #[test]
    fn priority_mapping_is_lossy_but_deterministic() {
        assert_eq!(priority_to_level(0), EventLevel::Critical);
        assert_eq!(priority_to_level(3), EventLevel::Error);
        assert_eq!(priority_to_level(4), EventLevel::Warning);
        assert_eq!(priority_to_level(6), EventLevel::Information);
        assert_eq!(priority_to_level(7), EventLevel::Verbose);
    }
}
