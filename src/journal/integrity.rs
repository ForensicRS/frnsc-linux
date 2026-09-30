//! Turns the cross-checks the design calls for into `Err(ForensicError)` items.
//!
//! Every check here follows the same policy as the rest of `frnsc-linux`
//! (`crates/frnsc-linux/src/unix/utmp.rs` is the precedent): a finding is one `Err` item in the
//! parser's output stream, never a hand-built `Finding` — the pipeline's own
//! `Finding::from_error` machinery turns it into one automatically. A check that could fire once
//! per entry (a seqnum gap, a realtime regression, a hash mismatch) is aggregated into a single
//! summary `Err` carrying a count and the first offending offset instead, so a file with many
//! small inconsistencies produces one clear signal rather than flooding the stream.
//!
//! Nothing here ever reports a *positive* trust claim past what was actually checked: a
//! `SEALED` file is reported as "sealed, unverified" because this reader never accepts an FSS
//! key, and that phrasing is intentional — never "verified" unless a signature actually was.

use forensic_rs::prelude::*;

use crate::journal::header::Header;
use crate::journal::scan::ScanResult;

/// The fields of one indexed-path entry that integrity checks need — not the whole
/// [`crate::journal::object::EntryObject`], so the reader can build this list from the indexed
/// walk without holding every entry's items in memory twice.
#[derive(Debug, Clone, Copy)]
pub struct IndexedEntry {
    pub offset: u64,
    pub seqnum: u64,
    pub realtime: u64,
    pub boot_id: [u8; 16],
}

/// Everything [`run`] needs, gathered by [`crate::journal::reader`] while it walks the indexed and
/// recovery paths.
pub struct Signals<'a> {
    pub header: &'a Header,
    /// Entries in the order the entry-array chain yields them — the order integrity checks like
    /// seqnum/realtime monotonicity are defined against.
    pub indexed_entries: &'a [IndexedEntry],
    pub recovery: &'a ScanResult,
    /// Count of entry items (regular, non-`COMPACT` layout only) whose stored hash did not match
    /// the hash stored on the `DATA` object they reference.
    pub item_hash_mismatches: u64,
    pub item_hash_mismatch_first_offset: Option<u64>,
    /// Count of `DATA` objects whose own stored hash did not match a fresh
    /// Jenkins/siphash24 hash of their (decompressed) payload — skipped, not counted here, when
    /// decompression itself failed or the relevant codec feature isn't compiled in, since then
    /// there is nothing to recompute against.
    pub data_hash_recompute_mismatches: u64,
    pub data_hash_recompute_mismatch_first_offset: Option<u64>,
}

pub fn run(signals: &Signals<'_>) -> Vec<ForensicError> {
    let mut findings = Vec::new();
    check_online_state(signals, &mut findings);
    check_object_and_entry_counts(signals, &mut findings);
    check_seqnum_gaps(signals, &mut findings);
    check_realtime_regression(signals, &mut findings);
    check_boot_id(signals, &mut findings);
    check_item_hash_mismatches(signals, &mut findings);
    check_data_hash_recompute_mismatches(signals, &mut findings);
    check_sealed_unverified(signals, &mut findings);
    check_recovery_only_entries(signals, &mut findings);
    check_unknown_incompatible_flags(signals, &mut findings);
    findings
}

fn finding(reason: impl Into<String>) -> ForensicError {
    ForensicError::invalid_format("journal integrity", reason.into())
}

fn check_online_state(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    use crate::journal::header::State;
    if signals.header.state == State::Online {
        out.push(finding(
            "journal state is ONLINE: the file was open at acquisition time, so its tail \
             pointers (tail_object_offset, entry_array chain heads) may not reflect every entry \
             actually written — run the recovery scan's results alongside the indexed ones",
        ));
    }
}

fn check_object_and_entry_counts(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    let counted_objects = signals.recovery.objects.len() as u64;
    if counted_objects != signals.header.n_objects {
        out.push(finding(format!(
            "header declares n_objects={}, but the recovery scan counted {counted_objects} \
             object(s) in the arena",
            signals.header.n_objects
        )));
    }
    let counted_entries = signals.indexed_entries.len() as u64;
    if counted_entries != signals.header.n_entries {
        out.push(finding(format!(
            "header declares n_entries={}, but the indexed entry-array walk reached \
             {counted_entries} entrie(s)",
            signals.header.n_entries
        )));
    }
}

fn check_seqnum_gaps(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    let mut gaps = 0u64;
    let mut first_offset = None;
    let mut prev: Option<u64> = None;
    for e in signals.indexed_entries {
        if let Some(p) = prev {
            if e.seqnum <= p {
                gaps += 1;
                first_offset.get_or_insert(e.offset);
            } else if e.seqnum > p + 1 {
                gaps += 1;
                first_offset.get_or_insert(e.offset);
            }
        }
        prev = Some(e.seqnum);
    }
    if gaps > 0 {
        out.push(finding(format!(
            "{gaps} seqnum discontinuity/discontinuities (a gap or a non-increasing step) \
             between consecutive indexed entries, first at offset {}",
            first_offset.unwrap_or(0)
        )));
    }
}

fn check_realtime_regression(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    let mut regressions = 0u64;
    let mut first_offset = None;
    let mut prev: Option<u64> = None;
    for e in signals.indexed_entries {
        if let Some(p) = prev {
            if e.realtime < p {
                regressions += 1;
                first_offset.get_or_insert(e.offset);
            }
        }
        prev = Some(e.realtime);
    }
    if regressions > 0 {
        out.push(finding(format!(
            "{regressions} realtime timestamp regression(s) between consecutive entries the \
             entry-array chain says are ordered, first at offset {}",
            first_offset.unwrap_or(0)
        )));
    }
}

fn check_boot_id(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    if !signals.header.has_tail_entry_boot_id() {
        // The header field isn't guaranteed meaningful on files old enough to predate it.
        return;
    }
    let expected = signals.header.tail_entry_boot_id;
    let mut mismatches = 0u64;
    let mut first_offset = None;
    for e in signals.indexed_entries {
        if e.boot_id != expected {
            mismatches += 1;
            first_offset.get_or_insert(e.offset);
        }
    }
    if mismatches > 0 {
        out.push(finding(format!(
            "{mismatches} entrie(s) carry a boot_id different from the header's own \
             tail_entry_boot_id, first at offset {}",
            first_offset.unwrap_or(0)
        )));
    }
}

fn check_item_hash_mismatches(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    if signals.item_hash_mismatches > 0 {
        out.push(finding(format!(
            "{} entry item(s) carry a hash that does not match the hash stored on the DATA \
             object they reference, first at entry offset {}",
            signals.item_hash_mismatches,
            signals.item_hash_mismatch_first_offset.unwrap_or(0)
        )));
    }
}

fn check_data_hash_recompute_mismatches(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    if signals.data_hash_recompute_mismatches > 0 {
        out.push(finding(format!(
            "{} DATA object(s) carry a stored hash that does not match a freshly computed hash \
             of their own (decompressed) payload, first at offset {}",
            signals.data_hash_recompute_mismatches,
            signals.data_hash_recompute_mismatch_first_offset.unwrap_or(0)
        )));
    }
}

fn check_sealed_unverified(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    if signals.header.is_sealed() {
        out.push(finding(
            "HEADER_COMPATIBLE_SEALED is set (this file was written with Forward Secure \
             Sealing) but this reader never accepts an FSS key: the seal is sealed, unverified \
             — never treat the entries below as signature-verified",
        ));
    }
}

fn check_recovery_only_entries(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    use std::collections::BTreeSet;
    let reachable: BTreeSet<u64> = signals.indexed_entries.iter().map(|e| e.offset).collect();
    let recovery_only: Vec<u64> = signals
        .recovery
        .entries
        .iter()
        .map(|(offset, _)| *offset)
        .filter(|offset| !reachable.contains(offset))
        .collect();
    if !recovery_only.is_empty() {
        out.push(finding(format!(
            "{} entrie(s) exist in the arena but are not reachable from the entry-array chain \
             (recovery-scan-only); first at offset {}",
            recovery_only.len(),
            recovery_only[0]
        )));
    }
}

fn check_unknown_incompatible_flags(signals: &Signals<'_>, out: &mut Vec<ForensicError>) {
    let unknown = signals.header.incompatible_flags.unknown_bits();
    if unknown != 0 {
        out.push(finding(format!(
            "header incompatible_flags has unrecognized bit(s) set (0x{unknown:x}): this file \
             may use a feature this reader does not understand, so its objects could be \
             misinterpreted rather than merely incomplete"
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::header::{CompatibleFlags, IncompatibleFlags, State};

    fn base_header() -> Header {
        Header {
            compatible_flags: CompatibleFlags::empty(),
            incompatible_flags: IncompatibleFlags::empty(),
            state: State::Offline,
            file_id: [0; 16],
            machine_id: [0; 16],
            tail_entry_boot_id: [0xAA; 16],
            seqnum_id: [0; 16],
            header_size: 272,
            arena_size: 0,
            data_hash_table_offset: 0,
            data_hash_table_size: 0,
            field_hash_table_offset: 0,
            field_hash_table_size: 0,
            tail_object_offset: 0,
            n_objects: 0,
            n_entries: 0,
            tail_entry_seqnum: 0,
            head_entry_seqnum: 0,
            entry_array_offset: 0,
            head_entry_realtime: None,
            tail_entry_realtime: None,
            tail_entry_monotonic: None,
            n_data: None,
            n_fields: None,
            n_tags: None,
            n_entry_arrays: None,
            data_hash_chain_depth: None,
            field_hash_chain_depth: None,
            tail_entry_array_offset: None,
            tail_entry_array_n_entries: None,
            tail_entry_offset: None,
        }
    }

    fn empty_signals<'a>(header: &'a Header, recovery: &'a ScanResult) -> Signals<'a> {
        Signals {
            header,
            indexed_entries: &[],
            recovery,
            item_hash_mismatches: 0,
            item_hash_mismatch_first_offset: None,
            data_hash_recompute_mismatches: 0,
            data_hash_recompute_mismatch_first_offset: None,
        }
    }

    #[test]
    fn a_clean_offline_file_with_matching_counts_has_no_findings() {
        let header = base_header();
        let recovery = ScanResult::default();
        let findings = run(&empty_signals(&header, &recovery));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn online_state_is_flagged() {
        let mut header = base_header();
        header.state = State::Online;
        let recovery = ScanResult::default();
        let findings = run(&empty_signals(&header, &recovery));
        assert!(findings.iter().any(|f| f.to_string().contains("ONLINE")));
    }

    #[test]
    fn a_seqnum_gap_is_flagged_once_with_a_count() {
        let header = base_header();
        let recovery = ScanResult::default();
        let entries = [
            IndexedEntry { offset: 0, seqnum: 1, realtime: 0, boot_id: [0xAA; 16] },
            IndexedEntry { offset: 64, seqnum: 5, realtime: 0, boot_id: [0xAA; 16] }, // gap
        ];
        let mut signals = empty_signals(&header, &recovery);
        signals.indexed_entries = &entries;
        let findings = run(&signals);
        let hits: Vec<_> = findings.iter().filter(|f| f.to_string().contains("seqnum")).collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].to_string().contains('1'));
    }

    #[test]
    fn a_realtime_regression_is_flagged() {
        let header = base_header();
        let recovery = ScanResult::default();
        let entries = [
            IndexedEntry { offset: 0, seqnum: 1, realtime: 1000, boot_id: [0xAA; 16] },
            IndexedEntry { offset: 64, seqnum: 2, realtime: 500, boot_id: [0xAA; 16] },
        ];
        let mut signals = empty_signals(&header, &recovery);
        signals.indexed_entries = &entries;
        let findings = run(&signals);
        assert!(findings.iter().any(|f| f.to_string().contains("realtime")));
    }

    #[test]
    fn a_boot_id_mismatch_is_only_checked_when_the_compat_flag_is_set() {
        let mut header = base_header();
        let entries = [IndexedEntry { offset: 0, seqnum: 1, realtime: 0, boot_id: [0xFF; 16] }];
        let recovery = ScanResult::default();

        let mut signals = empty_signals(&header, &recovery);
        signals.indexed_entries = &entries;
        assert!(!run(&signals).iter().any(|f| f.to_string().contains("boot_id")));

        header.compatible_flags = CompatibleFlags::TAIL_ENTRY_BOOT_ID;
        let mut signals2 = empty_signals(&header, &recovery);
        signals2.indexed_entries = &entries;
        assert!(run(&signals2).iter().any(|f| f.to_string().contains("boot_id")));
    }

    #[test]
    fn sealed_is_always_reported_as_unverified() {
        let mut header = base_header();
        header.compatible_flags = CompatibleFlags::SEALED;
        let recovery = ScanResult::default();
        let findings = run(&empty_signals(&header, &recovery));
        let hit = findings.iter().find(|f| f.to_string().contains("sealed")).unwrap();
        assert!(hit.to_string().contains("unverified"));
        assert!(!hit.to_string().to_lowercase().contains("verified: true"));
    }

    #[test]
    fn an_unknown_incompatible_flag_bit_is_reported() {
        let mut header = base_header();
        header.incompatible_flags = IncompatibleFlags(1 << 31);
        let recovery = ScanResult::default();
        let findings = run(&empty_signals(&header, &recovery));
        assert!(findings.iter().any(|f| f.to_string().contains("unrecognized")));
    }

    #[test]
    fn hash_mismatch_counts_are_surfaced() {
        let header = base_header();
        let recovery = ScanResult::default();
        let mut signals = empty_signals(&header, &recovery);
        signals.item_hash_mismatches = 3;
        signals.item_hash_mismatch_first_offset = Some(128);
        let findings = run(&signals);
        let hit = findings.iter().find(|f| f.to_string().contains("entry item")).unwrap();
        assert!(hit.to_string().contains('3'));
        assert!(hit.to_string().contains("128"));
    }
}
