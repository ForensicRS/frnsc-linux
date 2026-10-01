//! The recovery read path: a linear walk of every object from `header_size` to the real end of
//! the file, independent of what any array chain or `tail_object_offset` claims.
//!
//! This is what finds an `ENTRY` object left behind by rotation, by a crash that left tail
//! pointers stale, or by deliberate unlinking from the entry-array chain (the
//! `linux-journal-unlinked-entries-synthetic` fixture's whole point): such an object's bytes are
//! still physically present and still parse as a structurally valid `ENTRY`, so a scan that walks
//! by declared object size — rather than by following any pointer a writer or an attacker
//! controls — finds it regardless of whether anything still references it.
//!
//! Walking by `ObjectHeader.size` only works while the size chain stays trustworthy. The moment
//! it doesn't (a corrupt size, or a size that doesn't 8-byte-align to anything plausible), this
//! module falls back to carving: scanning forward byte-by-byte for the next position that looks
//! like a plausible object header, so the scan can resynchronize instead of giving up on the rest
//! of the file.

use forensic_rs::prelude::*;

use crate::journal::object::{self, EntryObject, ObjectHeader, ObjectType};
use crate::journal::window::Window;

/// One object found during the scan, successfully parsed or not.
#[derive(Debug)]
pub struct ScannedObject {
    pub offset: u64,
    pub header: ObjectHeader,
    /// `true` if this object was found by byte-level carving after the declared-size chain broke
    /// down, rather than by trusting the previous object's `size` to land exactly here.
    pub carved: bool,
}

/// Everything the recovery scan found in one pass over a file.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// One item per object whose header parsed, in file order — including `OBJECT_UNUSED` slots
    /// and objects of types this reader doesn't otherwise interpret (`FIELD`, hash tables), since
    /// even those count toward `n_objects` cross-checks.
    pub objects: Vec<ScannedObject>,
    /// Every `ENTRY` object that parsed structurally, keyed by its own offset — whether or not any
    /// entry-array chain references it. This is the superset the indexed path's reachable offsets
    /// are compared against to find recovery-only entries.
    pub entries: Vec<(u64, EntryObject)>,
    /// One item per structural failure hit while scanning (a corrupt header, an object whose type
    /// claims to be `ENTRY`/`ENTRY_ARRAY`/`DATA` but fails to parse as one). The scan does not stop
    /// at the first failure — see the module docs on carving — so this can hold several.
    pub errors: Vec<ForensicError>,
    /// `true` if carving was needed anywhere in the file (the declared-size chain broke down at
    /// least once).
    pub carving_used: bool,
}

/// A generous but finite bound on carving distance: how far past a broken size chain to search,
/// byte-by-byte, for the next plausible object header before giving up on that stretch of the
/// file. Kept well under a typical object's own maximum plausible size so carving cannot itself
/// become the slow part of parsing a large hostile file.
const MAX_CARVE_DISTANCE: u64 = 1024 * 1024;

/// Runs the full recovery scan of `win`, from `header_size` to the real end of the file (never
/// past it, even if `arena_size` claims more — see [`Window`]'s own bounds). `compact` selects
/// `DATA`/`ENTRY`/`ENTRY_ARRAY`'s on-disk item layout. `max_objects` bounds total iterations
/// (cycle-free by construction, since every step advances the cursor by at least
/// [`object::OBJECT_HEADER_SIZE`] bytes — but corrupted input could still mean this scan finds an
/// implausibly large number of tiny "objects", so a hard cap keeps a hostile file from making the
/// scan itself the resource exhaustion).
pub fn scan(win: &Window<'_>, header_size: u64, compact: bool, max_objects: u64) -> ScanResult {
    let mut result = ScanResult::default();
    let mut cursor = header_size;
    // Whether `cursor` was reached by carving rather than by trusting the previous object's
    // declared size — carried across loop iterations so the object actually found there (in the
    // *next* iteration) is recorded with the right `carved` flag.
    let mut cursor_is_carved = false;
    let end = win.file_len().min(win.declared_end());
    let mut objects_seen: u64 = 0;

    while cursor + object::OBJECT_HEADER_SIZE <= end {
        if objects_seen >= max_objects {
            result.errors.push(ForensicError::invalid_format(
                "journal recovery scan",
                format!("stopped after the {max_objects} object safety cap"),
            ));
            break;
        }
        match object::parse_header(win, cursor) {
            Ok(header) => {
                let advance = align_up(header.size, 8);
                if advance == 0 || cursor.saturating_add(advance) > end {
                    // A structurally-declared header whose size doesn't fit what's left: record
                    // it, then try to carve forward rather than stopping the whole scan here.
                    result.errors.push(
                        ForensicError::invalid_format(
                            "journal recovery scan",
                            format!(
                                "object at offset {cursor} declares size {} which does not fit \
                                 in the remaining {} byte(s)",
                                header.size,
                                end - cursor
                            ),
                        )
                        .with_offset(cursor),
                    );
                    match carve_forward(win, cursor + 8, end, compact) {
                        Some(next) => {
                            result.carving_used = true;
                            cursor = next;
                            cursor_is_carved = true;
                            objects_seen += 1;
                            continue;
                        }
                        None => break,
                    }
                }
                record_object(win, cursor, header, cursor_is_carved, compact, &mut result);
                cursor_is_carved = false;
                objects_seen += 1;
                cursor += advance;
            }
            Err(e) => {
                // A real journal's arena is typically pre-allocated well past what has actually
                // been written (every fixture in `journal_real_samples.rs` is 8 MiB with only a
                // few KiB actually used) — the never-written tail reads back as all zero bytes,
                // which parses as `ObjectHeader { type: 0, size: 0 }` and fails `parse_header`'s
                // own size check. That is the ordinary, expected shape of unused arena space, not
                // corruption: confirming the *entire* remainder is zero (not just this one
                // header-sized read) is what tells the two apart from a hostile file that plants
                // a zeroed decoy over a real object placed deeper in — see
                // `a_zeroed_tail_is_the_end_of_the_scan_not_an_error` and
                // `a_zeroed_gap_with_a_real_object_further_in_is_still_found` below.
                if is_all_zero(win, cursor, end) {
                    break;
                }
                result.errors.push(e.with_offset(cursor));
                match carve_forward(win, cursor + 8, end, compact) {
                    Some(next) => {
                        result.carving_used = true;
                        cursor = next;
                        cursor_is_carved = true;
                        objects_seen += 1;
                        continue;
                    }
                    None => break,
                }
            }
        }
    }
    result
}

/// Rounds `v` up to the next multiple of `align`, saturating at `u64::MAX` instead of overflowing
/// — a hostile object can declare `size` as close to `u64::MAX` as it likes.
fn align_up(v: u64, align: u64) -> u64 {
    let rem = v % align;
    if rem == 0 {
        v
    } else {
        v.saturating_add(align - rem)
    }
}

/// Records one successfully-header-parsed object into `result`: tallies it, and for `ENTRY`
/// objects specifically, fully decodes and stores it (a parse failure there is one more error
/// item, not a scan-ending one — a single corrupt `ENTRY` does not implicate the object after it,
/// since that next object's header was already independently found by declared size or by
/// carving).
fn record_object(
    win: &Window<'_>,
    offset: u64,
    header: ObjectHeader,
    carved: bool,
    compact: bool,
    result: &mut ScanResult,
) {
    if ObjectType::from_u8(header.object_type_raw) == Some(ObjectType::Entry) {
        match object::parse_entry_object(win, offset, &header, compact) {
            Ok(entry) => result.entries.push((offset, entry)),
            Err(e) => result.errors.push(e.with_offset(offset)),
        }
    }
    result.objects.push(ScannedObject {
        offset,
        header,
        carved,
    });
}

/// Whether every byte from `from` to `end` is zero — how the scan tells a legitimate never-written
/// arena tail apart from a corrupt or hostile object header that merely starts with a zero type
/// and size (see the call site in [`scan`]). A hostile file can still plant a real object further
/// into an otherwise-zero span; that case is bounded by [`MAX_CARVE_DISTANCE`] the same as any
/// other carve, not by this check (which only short-circuits the fully-empty case).
fn is_all_zero(win: &Window<'_>, from: u64, end: u64) -> bool {
    match win.slice(from, end - from) {
        Ok(bytes) => bytes.iter().all(|&b| b == 0),
        Err(_) => false,
    }
}

/// Scans byte-by-byte from `from` (inclusive) up to `from + MAX_CARVE_DISTANCE` (capped at `end`)
/// for the next offset where an [`object::ObjectHeader`] parses with a recognized, non-`Unused`
/// type and a `size` that both fits before `end` and leaves the following bytes 8-byte aligned —
/// the same plausibility signal a real writer's own alignment guarantees. Returns that offset
/// (the object there is recorded by the caller's next loop iteration, not here), or `None` if
/// nothing plausible turns up before the distance cap.
fn carve_forward(win: &Window<'_>, from: u64, end: u64, compact: bool) -> Option<u64> {
    let limit = from.saturating_add(MAX_CARVE_DISTANCE).min(end);
    let mut offset = from;
    while offset + object::OBJECT_HEADER_SIZE <= limit {
        if let Ok(header) = object::parse_header(win, offset) {
            let plausible_type = matches!(
                ObjectType::from_u8(header.object_type_raw),
                Some(ObjectType::Entry)
                    | Some(ObjectType::Data)
                    | Some(ObjectType::EntryArray)
                    | Some(ObjectType::Field)
            );
            let fits = offset.checked_add(header.size).is_some_and(|e| e <= end);
            if plausible_type && fits && header.size % 8 == 0 {
                // A weak extra check for ENTRY specifically, since it's the type this scan cares
                // about most: it should actually parse as one, not just claim to be one.
                if ObjectType::from_u8(header.object_type_raw) == Some(ObjectType::Entry)
                    && object::parse_entry_object(win, offset, &header, compact).is_err()
                {
                    offset += 1;
                    continue;
                }
                return Some(offset);
            }
        }
        offset += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_object_bytes(seqnum: u64, items: &[(u64, u64)]) -> Vec<u8> {
        let size = 16u64 + 48 + items.len() as u64 * 16;
        let mut buf = vec![3u8, 0, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&seqnum.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // realtime
        buf.extend_from_slice(&0u64.to_le_bytes()); // monotonic
        buf.extend_from_slice(&[0u8; 16]); // boot_id
        buf.extend_from_slice(&0u64.to_le_bytes()); // xor_hash
        for (offset, hash) in items {
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(&hash.to_le_bytes());
        }
        buf
    }

    fn unused_object_bytes(size: u64) -> Vec<u8> {
        let mut buf = vec![0u8, 0, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&size.to_le_bytes());
        buf.resize(size as usize, 0);
        buf
    }

    #[test]
    fn finds_every_entry_sequentially_by_declared_size() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry_object_bytes(1, &[(0, 0)]));
        buf.extend_from_slice(&entry_object_bytes(2, &[(0, 0)]));
        buf.extend_from_slice(&entry_object_bytes(3, &[(0, 0)]));
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert_eq!(result.entries.len(), 3);
        let seqnums: Vec<u64> = result.entries.iter().map(|(_, e)| e.seqnum).collect();
        assert_eq!(seqnums, vec![1, 2, 3]);
        assert!(!result.carving_used);
    }

    #[test]
    fn an_unlinked_entry_still_present_in_the_arena_is_found_by_a_plain_sequential_walk() {
        // The recovery scan needs no special "unlinked" handling of its own: it walks by size
        // regardless of what any array chain references, so an entry with no incoming array item
        // at all is found exactly the same way a linked one is. What makes it "recovery-only" is
        // purely that the indexed path (elsewhere) never reaches it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry_object_bytes(1, &[(0, 0)]));
        buf.extend_from_slice(&entry_object_bytes(2, &[(0, 0)])); // not referenced by any array
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert_eq!(result.entries.len(), 2);
    }

    #[test]
    fn tallies_unused_and_non_entry_objects_too() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&unused_object_bytes(32));
        buf.extend_from_slice(&entry_object_bytes(1, &[(0, 0)]));
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert_eq!(result.objects.len(), 2);
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn a_zeroed_tail_is_the_end_of_the_scan_not_an_error() {
        // A pre-allocated arena is almost always bigger than what has been written so far — the
        // never-written tail is all zero bytes, which is the ordinary shape of unused space, not
        // corruption. Every real fixture in `journal_real_samples.rs` looks exactly like this
        // (an 8 MiB arena with a few KiB actually used).
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry_object_bytes(1, &[(0, 0)]));
        buf.resize(buf.len() + 4096, 0); // a large never-written tail
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert_eq!(result.entries.len(), 1);
        assert!(
            !result.carving_used,
            "a clean zero tail needs no carving at all"
        );
    }

    #[test]
    fn a_zeroed_gap_with_a_real_object_further_in_is_still_found() {
        // Distinguishes "the rest of the file really is empty" from "there is a real object
        // sitting past some zero padding" — the latter must still be found by carving, not
        // swallowed by the zero-tail short-circuit above.
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry_object_bytes(1, &[(0, 0)]));
        buf.resize(buf.len() + 256, 0); // a zeroed gap, well under MAX_CARVE_DISTANCE
        buf.extend_from_slice(&entry_object_bytes(2, &[(0, 0)]));
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert!(result.carving_used);
        let seqnums: Vec<u64> = result.entries.iter().map(|(_, e)| e.seqnum).collect();
        assert_eq!(seqnums, vec![1, 2]);
    }

    #[test]
    fn a_zero_size_object_does_not_loop_forever_and_is_reported() {
        let mut buf = vec![3u8, 0, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&0u64.to_le_bytes()); // size = 0: rejected by parse_header itself
        buf.resize(64, 0);
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert!(!result.errors.is_empty());
        // The scan terminates (this assertion running at all, without timing out, is the point).
    }

    #[test]
    fn a_corrupt_object_in_the_middle_is_carved_past_so_later_entries_are_still_found() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&entry_object_bytes(1, &[(0, 0)])); // offset 0, size 80
        let junk_start = buf.len();
        buf.extend_from_slice(&[0xFFu8; 16]); // garbage: not a valid object header
                                              // pad to an 8-byte boundary, then place a real, carvable entry object
        let carve_target = junk_start + 16;
        buf.extend_from_slice(&entry_object_bytes(2, &[(0, 0)]));
        let win = Window::new(&buf, 0, buf.len() as u64);
        let result = scan(&win, 0, false, 1000);
        assert!(result.carving_used);
        assert!(
            !result.errors.is_empty(),
            "the garbage bytes are reported, not silently skipped"
        );
        let seqnums: Vec<u64> = result.entries.iter().map(|(_, e)| e.seqnum).collect();
        assert!(seqnums.contains(&1));
        assert!(
            seqnums.contains(&2),
            "carving found the entry after the garbage at {carve_target}"
        );
    }
}
