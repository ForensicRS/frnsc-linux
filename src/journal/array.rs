//! Walks the `entry_array_offset -> EntryArrayObject.next_entry_array_offset` chain: the indexed
//! read path needs no hash tables, just this chain.
//!
//! `next_entry_array_offset` is attacker-controlled bytes in a hostile file, so the walk is
//! bounded two ways: a visited-offset set catches a direct cycle, and a hop limit catches a long
//! or exploding chain that never repeats an exact offset but still never terminates in a
//! reasonable number of steps.

use std::collections::BTreeSet;

use forensic_rs::prelude::*;

use crate::journal::object::{self, EntryArrayObject};
use crate::journal::window::Window;

/// The result of walking one entry-array chain from its starting offset to its end (or to the
/// point where the walk had to stop for a structural or safety reason).
#[derive(Debug, Default)]
pub struct ChainWalk {
    /// One item per array object successfully parsed, in chain order.
    pub arrays: Vec<EntryArrayObject>,
    /// Set once a `next_entry_array_offset` pointed back at an offset already visited in this
    /// chain. The walk stops there; `arrays` holds everything found before the cycle closed.
    pub cycle_detected: bool,
    /// Set once the walk exceeded its hop budget without cycling or reaching a natural end
    /// (offset `0`) — a very long or adversarially inflated chain.
    pub hop_limit_reached: bool,
    /// The first structural error hit while parsing an array object in the chain, if any. The
    /// walk stops there (a corrupt `size`/item count means the rest of the chain, reached only
    /// through this object, cannot be trusted either).
    pub error: Option<ForensicError>,
}

/// Walks the chain starting at `start_offset` (a `0` start offset means "no arrays", the ordinary
/// shape of a journal file with zero entries — not an error). `hop_limit` bounds the walk
/// independently of cycle detection, for a chain that grows without exactly repeating an offset.
pub fn walk_chain(win: &Window<'_>, start_offset: u64, compact: bool, hop_limit: u64) -> ChainWalk {
    let mut result = ChainWalk::default();
    if start_offset == 0 {
        return result;
    }
    let mut visited = BTreeSet::new();
    let mut offset = start_offset;
    let mut hops: u64 = 0;
    loop {
        if hops >= hop_limit {
            result.hop_limit_reached = true;
            break;
        }
        if !visited.insert(offset) {
            result.cycle_detected = true;
            break;
        }
        hops += 1;
        let header = match object::parse_header(win, offset) {
            Ok(h) => h,
            Err(e) => {
                result.error = Some(e);
                break;
            }
        };
        let array = match object::parse_entry_array_object(win, offset, &header, compact) {
            Ok(a) => a,
            Err(e) => {
                result.error = Some(e);
                break;
            }
        };
        let next = array.next_entry_array_offset;
        result.arrays.push(array);
        if next == 0 {
            break;
        }
        offset = next;
    }
    result
}

/// Flattens a [`ChainWalk`]'s arrays into the sequence of non-zero item offsets they reference, in
/// chain order. A `0` item is an empty/unused slot (see [`EntryArrayObject::items`]'s docs), never
/// a real object — file offset `0` always falls inside the header.
pub fn flatten_item_offsets(walk: &ChainWalk) -> Vec<u64> {
    walk.arrays
        .iter()
        .flat_map(|a| a.items.iter().copied())
        .filter(|&o| o != 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array_object_bytes(next: u64, items: &[u64]) -> Vec<u8> {
        let size = 16u64 + 8 + items.len() as u64 * 8;
        let mut buf = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&next.to_le_bytes());
        for item in items {
            buf.extend_from_slice(&item.to_le_bytes());
        }
        buf
    }

    /// Builds a file with an array object at `offset_a` chaining to one at `offset_b`.
    fn two_array_file(offset_a: u64, offset_b: u64, items_a: &[u64], items_b: &[u64]) -> Vec<u8> {
        let a = array_object_bytes(offset_b, items_a);
        let b = array_object_bytes(0, items_b);
        let end = offset_b as usize + b.len();
        let mut buf = vec![0u8; end];
        buf[offset_a as usize..offset_a as usize + a.len()].copy_from_slice(&a);
        buf[offset_b as usize..offset_b as usize + b.len()].copy_from_slice(&b);
        buf
    }

    #[test]
    fn a_zero_start_offset_is_an_empty_chain_not_an_error() {
        let data = [0u8; 16];
        let win = Window::new(&data, 0, 16);
        let walk = walk_chain(&win, 0, false, 100);
        assert!(walk.arrays.is_empty());
        assert!(!walk.cycle_detected);
        assert!(walk.error.is_none());
    }

    #[test]
    fn walks_a_two_link_chain_in_order() {
        let data = two_array_file(64, 128, &[1000, 2000], &[3000]);
        let win = Window::new(&data, 0, data.len() as u64);
        let walk = walk_chain(&win, 64, false, 100);
        assert!(walk.error.is_none());
        assert!(!walk.cycle_detected);
        assert_eq!(walk.arrays.len(), 2);
        assert_eq!(flatten_item_offsets(&walk), vec![1000, 2000, 3000]);
    }

    /// Places `bytes` at absolute offset `offset` inside a zero-filled buffer at least
    /// `min_len` bytes long.
    fn place_at(offset: u64, bytes: &[u8], min_len: u64) -> Vec<u8> {
        let len = min_len.max(offset + bytes.len() as u64) as usize;
        let mut buf = vec![0u8; len];
        buf[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
        buf
    }

    #[test]
    fn a_self_referencing_array_is_a_cycle_not_an_infinite_loop() {
        // The array at offset 64 points at itself.
        let obj = array_object_bytes(64, &[1000]);
        let buf = place_at(64, &obj, 200);
        let win = Window::new(&buf, 0, buf.len() as u64);
        let walk = walk_chain(&win, 64, false, 1000);
        assert!(walk.cycle_detected);
        assert_eq!(
            walk.arrays.len(),
            1,
            "the array is recorded once, then the cycle is caught"
        );
    }

    #[test]
    fn a_two_cycle_is_also_caught() {
        // a (offset 64) -> b (offset 128) -> a (offset 64): a two-hop cycle.
        let a = array_object_bytes(128, &[1]);
        let b = array_object_bytes(64, &[2]);
        let mut buf = place_at(64, &a, 200);
        buf[128..128 + b.len()].copy_from_slice(&b);
        let win = Window::new(&buf, 0, buf.len() as u64);
        let walk = walk_chain(&win, 64, false, 1000);
        assert!(walk.cycle_detected);
        assert_eq!(walk.arrays.len(), 2);
    }

    #[test]
    fn a_long_non_repeating_chain_stops_at_the_hop_limit() {
        // Each array points to the next one, never repeating an offset, so only the hop limit —
        // not cycle detection — can stop this. Arrays start at STRIDE (not 0), since a start
        // offset of 0 means "no arrays" in the real API.
        const N: u64 = 10;
        const STRIDE: u64 = 64;
        let mut buf = vec![0u8; (STRIDE * (N + 2)) as usize];
        for i in 0..N {
            let offset = STRIDE * (i + 1);
            let next = STRIDE * (i + 2);
            let obj = array_object_bytes(next, &[i]);
            buf[offset as usize..offset as usize + obj.len()].copy_from_slice(&obj);
        }
        let win = Window::new(&buf, 0, buf.len() as u64);
        let walk = walk_chain(&win, STRIDE, false, 3); // hop limit lower than the real chain length
        assert!(walk.hop_limit_reached);
        assert!(!walk.cycle_detected);
        assert_eq!(walk.arrays.len(), 3);
    }

    #[test]
    fn a_corrupt_array_in_the_middle_of_the_chain_stops_the_walk_with_an_error() {
        let good = array_object_bytes(64, &[1]);
        let mut buf = vec![0u8; 64 + 16];
        buf[0..good.len()].copy_from_slice(&good);
        // offset 64: a header claiming a size smaller than any valid object.
        buf[64..64 + 16].copy_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
        let win = Window::new(&buf, 0, buf.len() as u64);
        let walk = walk_chain(&win, 0, false, 100);
        assert_eq!(
            walk.arrays.len(),
            0,
            "start offset 0 is the empty-chain case in this fixture"
        );

        // Re-run starting from the first real array instead, so the corrupt second link is
        // actually exercised.
        let mut buf2 = vec![0u8; 64];
        buf2.extend_from_slice(&array_object_bytes(128, &[1]));
        buf2.resize(128 + 16, 0);
        buf2[128..128 + 16].copy_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
        let win2 = Window::new(&buf2, 0, buf2.len() as u64);
        let walk2 = walk_chain(&win2, 64, false, 100);
        assert_eq!(
            walk2.arrays.len(),
            1,
            "the first, valid array is still recorded"
        );
        assert!(walk2.error.is_some());
        assert!(!walk2.cycle_detected);
    }
}
