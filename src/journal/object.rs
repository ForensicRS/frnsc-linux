//! `ObjectHeader` and the seven journal object types, in both the regular (8-byte offset) and
//! `COMPACT` (4-byte offset) on-disk layouts.
//!
//! Every layout below is confirmed against systemd's `src/libsystemd/sd-journal/journal-def.h`
//! (fetched and cross-checked against the systemd.io format doc) and, for the common case,
//! against real fixture bytes in `crates/frnsc-linux/tests/journal_real_samples.rs`.

use crate::journal::window::Window;
use forensic_rs::prelude::*;

/// Common 16-byte header at the start of every object.
#[derive(Debug, Clone, Copy)]
pub struct ObjectHeader {
    pub object_type_raw: u8,
    pub flags: u8,
    /// Total object size in bytes, including this 16-byte header.
    pub size: u64,
}

pub const OBJECT_HEADER_SIZE: u64 = 16;

/// A recognized `ObjectHeader.type` value. `OBJECT_UNUSED` (0) is a legitimate, empty slot — not
/// an error — so it is included here rather than folded into "unknown".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Unused,
    Data,
    Field,
    Entry,
    DataHashTable,
    FieldHashTable,
    EntryArray,
    Tag,
}

impl ObjectType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ObjectType::Unused),
            1 => Some(ObjectType::Data),
            2 => Some(ObjectType::Field),
            3 => Some(ObjectType::Entry),
            4 => Some(ObjectType::DataHashTable),
            5 => Some(ObjectType::FieldHashTable),
            6 => Some(ObjectType::EntryArray),
            7 => Some(ObjectType::Tag),
            _ => None,
        }
    }
}

/// Parses the 16-byte `ObjectHeader` at `offset`. A `size` smaller than the header itself is
/// rejected here — nothing meaningful can follow it.
pub fn parse_header(win: &Window<'_>, offset: u64) -> ForensicResult<ObjectHeader> {
    let mut reader = win.reader_at(offset, OBJECT_HEADER_SIZE)?;
    let object_type_raw = reader.read_u8()?;
    let flags = reader.read_u8()?;
    reader.skip(6)?; // reserved
    let size = reader.read_u64_le()?;
    if size < OBJECT_HEADER_SIZE {
        return Err(ForensicError::invalid_format(
            "journal object",
            format!("object at offset {offset} declares size {size}, smaller than its own {OBJECT_HEADER_SIZE}-byte header"),
        )
        .with_offset(offset));
    }
    Ok(ObjectHeader {
        object_type_raw,
        flags,
        size,
    })
}

/// A parsed `DATA` object. `payload_raw` is exactly the bytes stored on disk — compressed, if
/// [`Self::compression`] is set — never decompressed eagerly, since not every caller needs the
/// value (e.g. a pure object-count tally in the recovery scan).
#[derive(Debug, Clone)]
pub struct DataObject {
    pub offset: u64,
    pub hash: u64,
    pub next_hash_offset: u64,
    pub next_field_offset: u64,
    pub entry_offset: u64,
    pub entry_array_offset: u64,
    pub n_entries: u64,
    pub compression: Option<crate::journal::compress::Codec>,
    pub payload_raw: Vec<u8>,
}

/// Byte length of the fixed fields between the `ObjectHeader` and the payload: `hash` through
/// `n_entries` (48 bytes), plus — in `COMPACT` mode only — `tail_entry_array_offset` (4) and
/// `tail_entry_array_n_entries` (4).
fn data_prefix_len(compact: bool) -> u64 {
    if compact {
        48 + 8
    } else {
        48
    }
}

pub fn parse_data_object(
    win: &Window<'_>,
    offset: u64,
    header: &ObjectHeader,
    compact: bool,
) -> ForensicResult<DataObject> {
    let prefix_len = data_prefix_len(compact);
    let fixed_len = OBJECT_HEADER_SIZE + prefix_len;
    if header.size < fixed_len {
        return Err(ForensicError::invalid_format(
            "journal data object",
            format!(
                "object at offset {offset} declares size {}, smaller than the {fixed_len}-byte \
                 fixed prefix",
                header.size
            ),
        )
        .with_offset(offset));
    }
    let mut reader = win.reader_at(offset + OBJECT_HEADER_SIZE, prefix_len)?;
    let hash = reader.read_u64_le()?;
    let next_hash_offset = reader.read_u64_le()?;
    let next_field_offset = reader.read_u64_le()?;
    let entry_offset = reader.read_u64_le()?;
    let entry_array_offset = reader.read_u64_le()?;
    let n_entries = reader.read_u64_le()?;
    if compact {
        reader.skip(8)?; // tail_entry_array_offset + tail_entry_array_n_entries: writer bookkeeping
    }
    let payload_len = header.size - fixed_len;
    let payload_raw = win.slice(offset + fixed_len, payload_len)?.to_vec();
    let compression = crate::journal::compress::codec_from_object_flags(header.flags);
    Ok(DataObject {
        offset,
        hash,
        next_hash_offset,
        next_field_offset,
        entry_offset,
        entry_array_offset,
        n_entries,
        compression,
        payload_raw,
    })
}

/// One item inside an `ENTRY` object: the offset of the `DATA` object it references, plus its
/// stored hash copy — `None` in `COMPACT` mode, where items narrow to just the offset.
#[derive(Debug, Clone, Copy)]
pub struct EntryItem {
    pub object_offset: u64,
    pub hash: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EntryObject {
    pub offset: u64,
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub boot_id: [u8; 16],
    pub xor_hash: u64,
    pub items: Vec<EntryItem>,
}

/// Bytes between the `ObjectHeader` and the items array: `seqnum`/`realtime`/`monotonic`(8+8+8) +
/// `boot_id`(16) + `xor_hash`(8) = 48 bytes, the same in both layouts.
const ENTRY_FIXED_LEN: u64 = 48;

pub fn parse_entry_object(
    win: &Window<'_>,
    offset: u64,
    header: &ObjectHeader,
    compact: bool,
) -> ForensicResult<EntryObject> {
    let fixed_len = OBJECT_HEADER_SIZE + ENTRY_FIXED_LEN;
    if header.size < fixed_len {
        return Err(ForensicError::invalid_format(
            "journal entry object",
            format!(
                "object at offset {offset} declares size {}, smaller than the {fixed_len}-byte \
                 fixed prefix",
                header.size
            ),
        )
        .with_offset(offset));
    }
    let mut reader = win.reader_at(offset + OBJECT_HEADER_SIZE, ENTRY_FIXED_LEN)?;
    let seqnum = reader.read_u64_le()?;
    let realtime = reader.read_u64_le()?;
    let monotonic = reader.read_u64_le()?;
    let boot_id = reader.read_fixed::<16>()?;
    let xor_hash = reader.read_u64_le()?;

    let item_stride: u64 = if compact { 4 } else { 16 };
    let items_bytes = header.size - fixed_len;
    if !items_bytes.is_multiple_of(item_stride) {
        return Err(ForensicError::invalid_format(
            "journal entry object",
            format!(
                "object at offset {offset} has {items_bytes} byte(s) of items, not a multiple \
                 of the {item_stride}-byte item stride"
            ),
        )
        .with_offset(offset));
    }
    let n_items = items_bytes / item_stride;
    let mut items_reader = win.reader_at(offset + fixed_len, items_bytes)?;
    let mut items = Vec::with_capacity(n_items as usize);
    for _ in 0..n_items {
        if compact {
            let object_offset = items_reader.read_u32_le()? as u64;
            items.push(EntryItem {
                object_offset,
                hash: None,
            });
        } else {
            let object_offset = items_reader.read_u64_le()?;
            let hash = items_reader.read_u64_le()?;
            items.push(EntryItem {
                object_offset,
                hash: Some(hash),
            });
        }
    }
    Ok(EntryObject {
        offset,
        seqnum,
        realtime,
        monotonic,
        boot_id,
        xor_hash,
        items,
    })
}

#[derive(Debug, Clone)]
pub struct EntryArrayObject {
    pub offset: u64,
    pub next_entry_array_offset: u64,
    /// Item offsets, widened to `u64` regardless of on-disk width. A `0` entry is an empty slot
    /// (never a real object at file offset 0, which always falls inside the header), preserved
    /// here rather than filtered so callers can see array shape exactly as stored.
    pub items: Vec<u64>,
}

/// `next_entry_array_offset` (8 bytes) is unconditionally 8 bytes wide even in `COMPACT` mode;
/// only the `items[]` array narrows.
const ENTRY_ARRAY_FIXED_LEN: u64 = 8;

pub fn parse_entry_array_object(
    win: &Window<'_>,
    offset: u64,
    header: &ObjectHeader,
    compact: bool,
) -> ForensicResult<EntryArrayObject> {
    let fixed_len = OBJECT_HEADER_SIZE + ENTRY_ARRAY_FIXED_LEN;
    if header.size < fixed_len {
        return Err(ForensicError::invalid_format(
            "journal entry array object",
            format!(
                "object at offset {offset} declares size {}, smaller than the {fixed_len}-byte \
                 fixed prefix",
                header.size
            ),
        )
        .with_offset(offset));
    }
    let next_entry_array_offset = win
        .reader_at(offset + OBJECT_HEADER_SIZE, ENTRY_ARRAY_FIXED_LEN)?
        .read_u64_le()?;

    let item_stride: u64 = if compact { 4 } else { 8 };
    let items_bytes = header.size - fixed_len;
    if !items_bytes.is_multiple_of(item_stride) {
        return Err(ForensicError::invalid_format(
            "journal entry array object",
            format!(
                "object at offset {offset} has {items_bytes} byte(s) of items, not a multiple \
                 of the {item_stride}-byte item stride"
            ),
        )
        .with_offset(offset));
    }
    let n_items = items_bytes / item_stride;
    let mut reader = win.reader_at(offset + fixed_len, items_bytes)?;
    let mut items = Vec::with_capacity(n_items as usize);
    for _ in 0..n_items {
        let v = if compact {
            reader.read_u32_le()? as u64
        } else {
            reader.read_u64_le()?
        };
        items.push(v);
    }
    Ok(EntryArrayObject {
        offset,
        next_entry_array_offset,
        items,
    })
}

/// A parsed `TAG` object (FSS sealing). Only enough is decoded to report the tag's presence and
/// bookkeeping fields — verifying the HMAC would require an FSS key this reader never accepts as
/// input (see the crate-level `journal` module docs' "sealed, unverified" policy).
#[derive(Debug, Clone)]
pub struct TagObject {
    pub offset: u64,
    pub seqnum: u64,
    pub epoch: u64,
}

const TAG_FIXED_LEN: u64 = 16 + 32; // seqnum(8) + epoch(8) + tag[32]

pub fn parse_tag_object(
    win: &Window<'_>,
    offset: u64,
    header: &ObjectHeader,
) -> ForensicResult<TagObject> {
    let fixed_len = OBJECT_HEADER_SIZE + TAG_FIXED_LEN;
    if header.size < fixed_len {
        return Err(ForensicError::invalid_format(
            "journal tag object",
            format!(
                "object at offset {offset} declares size {}, smaller than the {fixed_len}-byte \
                 tag object",
                header.size
            ),
        )
        .with_offset(offset));
    }
    let mut reader = win.reader_at(offset + OBJECT_HEADER_SIZE, 16)?;
    let seqnum = reader.read_u64_le()?;
    let epoch = reader.read_u64_le()?;
    Ok(TagObject {
        offset,
        seqnum,
        epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(object_type: u8, flags: u8, size: u64) -> Vec<u8> {
        let mut buf = vec![object_type, flags, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&size.to_le_bytes());
        buf
    }

    #[test]
    fn parses_an_object_header() {
        let mut bytes = header_bytes(3, 0, 64);
        bytes.extend_from_slice(&[0u8; 48]);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        assert_eq!(header.object_type_raw, 3);
        assert_eq!(header.size, 64);
    }

    #[test]
    fn rejects_a_size_smaller_than_the_header_itself() {
        let bytes = header_bytes(3, 0, 8);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        assert!(parse_header(&win, 0).is_err());
    }

    fn sample_data_object_bytes(payload: &[u8], compact: bool) -> Vec<u8> {
        let prefix_len = data_prefix_len(compact);
        let size = OBJECT_HEADER_SIZE + prefix_len + payload.len() as u64;
        let mut buf = header_bytes(1, 0, size);
        buf.extend_from_slice(&0xAAAAu64.to_le_bytes()); // hash
        buf.extend_from_slice(&0u64.to_le_bytes()); // next_hash_offset
        buf.extend_from_slice(&0u64.to_le_bytes()); // next_field_offset
        buf.extend_from_slice(&0u64.to_le_bytes()); // entry_offset
        buf.extend_from_slice(&0u64.to_le_bytes()); // entry_array_offset
        buf.extend_from_slice(&1u64.to_le_bytes()); // n_entries
        if compact {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parses_a_regular_data_object() {
        let bytes = sample_data_object_bytes(b"MESSAGE=hello", false);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        let obj = parse_data_object(&win, 0, &header, false).unwrap();
        assert_eq!(obj.hash, 0xAAAA);
        assert_eq!(obj.n_entries, 1);
        assert_eq!(obj.payload_raw, b"MESSAGE=hello");
    }

    #[test]
    fn parses_a_compact_data_object_with_the_extra_prefix_fields() {
        let bytes = sample_data_object_bytes(b"MESSAGE=hi", true);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        let obj = parse_data_object(&win, 0, &header, true).unwrap();
        assert_eq!(obj.payload_raw, b"MESSAGE=hi");
    }

    #[test]
    fn rejects_a_data_object_too_small_for_its_own_fixed_prefix() {
        let mut bytes = header_bytes(1, 0, 32); // smaller than 16+48
        bytes.extend_from_slice(&[0u8; 16]);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        assert!(parse_data_object(&win, 0, &header, false).is_err());
    }

    fn sample_entry_object_bytes(items: &[(u64, Option<u64>)], compact: bool) -> Vec<u8> {
        let stride = if compact { 4 } else { 16 };
        let size = OBJECT_HEADER_SIZE + ENTRY_FIXED_LEN + items.len() as u64 * stride;
        let mut buf = header_bytes(3, 0, size);
        buf.extend_from_slice(&7u64.to_le_bytes()); // seqnum
        buf.extend_from_slice(&123u64.to_le_bytes()); // realtime
        buf.extend_from_slice(&456u64.to_le_bytes()); // monotonic
        buf.extend_from_slice(&[0xEEu8; 16]); // boot_id
        buf.extend_from_slice(&0u64.to_le_bytes()); // xor_hash
        for (offset, hash) in items {
            if compact {
                buf.extend_from_slice(&(*offset as u32).to_le_bytes());
            } else {
                buf.extend_from_slice(&offset.to_le_bytes());
                buf.extend_from_slice(&hash.unwrap_or(0).to_le_bytes());
            }
        }
        buf
    }

    #[test]
    fn parses_a_regular_entry_object_with_items() {
        let bytes = sample_entry_object_bytes(&[(64, Some(999)), (128, Some(1000))], false);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        let entry = parse_entry_object(&win, 0, &header, false).unwrap();
        assert_eq!(entry.seqnum, 7);
        assert_eq!(entry.items.len(), 2);
        assert_eq!(entry.items[0].object_offset, 64);
        assert_eq!(entry.items[0].hash, Some(999));
    }

    #[test]
    fn parses_a_compact_entry_object_with_no_item_hash() {
        let bytes = sample_entry_object_bytes(&[(64, None), (128, None)], true);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        let entry = parse_entry_object(&win, 0, &header, true).unwrap();
        assert_eq!(entry.items.len(), 2);
        assert_eq!(entry.items[0].object_offset, 64);
        assert_eq!(entry.items[0].hash, None);
    }

    #[test]
    fn rejects_an_entry_object_whose_items_do_not_evenly_divide() {
        let mut bytes = sample_entry_object_bytes(&[(64, Some(1))], false);
        bytes.push(0xFF); // one stray trailing byte
        let size = bytes.len() as u64;
        bytes[8..16].copy_from_slice(&size.to_le_bytes());
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        assert!(parse_entry_object(&win, 0, &header, false).is_err());
    }

    fn sample_entry_array_bytes(next: u64, items: &[u64], compact: bool) -> Vec<u8> {
        let stride = if compact { 4 } else { 8 };
        let size = OBJECT_HEADER_SIZE + ENTRY_ARRAY_FIXED_LEN + items.len() as u64 * stride;
        let mut buf = header_bytes(6, 0, size);
        buf.extend_from_slice(&next.to_le_bytes());
        for item in items {
            if compact {
                buf.extend_from_slice(&(*item as u32).to_le_bytes());
            } else {
                buf.extend_from_slice(&item.to_le_bytes());
            }
        }
        buf
    }

    #[test]
    fn parses_a_regular_entry_array_object() {
        let bytes = sample_entry_array_bytes(999, &[64, 128, 0], false);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        let array = parse_entry_array_object(&win, 0, &header, false).unwrap();
        assert_eq!(array.next_entry_array_offset, 999);
        assert_eq!(array.items, vec![64, 128, 0]);
    }

    #[test]
    fn parses_a_compact_entry_array_object_with_narrow_items_but_wide_next_offset() {
        let bytes = sample_entry_array_bytes(0xFFFF_FFFF_0000u64, &[64, 128], true);
        let win = Window::new(&bytes, 0, bytes.len() as u64);
        let header = parse_header(&win, 0).unwrap();
        let array = parse_entry_array_object(&win, 0, &header, true).unwrap();
        assert_eq!(array.next_entry_array_offset, 0xFFFF_FFFF_0000);
        assert_eq!(array.items, vec![64, 128]);
    }

    #[test]
    fn object_type_unused_is_not_an_error() {
        assert_eq!(ObjectType::from_u8(0), Some(ObjectType::Unused));
        assert_eq!(ObjectType::from_u8(255), None);
    }
}
