//! The systemd journal file `Header`: signature, compatible/incompatible feature flags, and the
//! object-count/offset bookkeeping fields the indexed and recovery read paths both need.
//!
//! Byte layout confirmed against systemd's own `src/libsystemd/sd-journal/journal-def.h` and
//! cross-checked field-for-field against real `systemd-journal-remote`-produced fixtures (see
//! `crates/frnsc-linux/tests/journal_real_samples.rs`): `file_id`/`seqnum_id` at their documented
//! offsets round-trip byte-for-byte against `journalctl --output=json`'s `__SEQNUM_ID`, and
//! `header_size`/`arena_size` sum to the exact on-disk file length of an untruncated fixture.

use forensic_rs::prelude::*;

/// `"LPKSHHRH"`, the first 8 bytes of every journal file.
pub const SIGNATURE: [u8; 8] = *b"LPKSHHRH";

/// Byte offset of [`Header::entry_array_offset`] plus its width: everything up to and including
/// this offset is required to make sense of a journal file at all. Fields after it
/// (`head_entry_realtime` onward) are read best-effort: a header shorter than the full modern
/// struct (an older systemd, or a hostile/truncated one) still yields a usable [`Header`] with
/// those trailing fields left `None` rather than failing the whole parse.
const REQUIRED_PREFIX_LEN: usize = 184;

/// Minimal `bitflags`-shaped helper, spelled out by hand so this module has no dependency beyond
/// `forensic-rs` (see the crate-level `journal` module doc: this reader is meant to stay
/// extractable into its own crate with zero sibling dependencies).
macro_rules! bitflags_like {
    (
        $(#[$outer:meta])*
        pub struct $name:ident: $ty:ty {
            $(const $flag:ident = $value:expr;)*
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name(pub $ty);

        impl $name {
            $(pub const $flag: $name = $name($value);)*

            pub const fn empty() -> Self { $name(0) }
            pub const fn bits(self) -> $ty { self.0 }
            pub const fn contains(self, other: Self) -> bool { self.0 & other.0 == other.0 }
            pub const fn known_mask() -> $ty { 0 $(| $value)* }
            /// Bits set that this module does not recognize — a real, forward-compatibility
            /// signal worth surfacing, never silently ignored.
            pub const fn unknown_bits(self) -> $ty { self.0 & !Self::known_mask() }
        }

        impl std::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { $name(self.0 | rhs.0) }
        }
    };
}

bitflags_like! {
    /// `Header.incompatible_flags`: a reader that does not understand a set bit cannot correctly
    /// interpret the file's objects at all (contrast [`CompatibleFlags`], where an unknown bit
    /// only means a reader misses out on extra information, not that it misreads the ones it
    /// does understand).
    pub struct IncompatibleFlags: u32 {
        const COMPRESSED_XZ = 1 << 0;
        const COMPRESSED_LZ4 = 1 << 1;
        const KEYED_HASH = 1 << 2;
        const COMPRESSED_ZSTD = 1 << 3;
        const COMPACT = 1 << 4;
    }
}

bitflags_like! {
    /// `Header.compatible_flags`: an unknown bit here is safe to ignore for reading purposes.
    pub struct CompatibleFlags: u32 {
        const SEALED = 1 << 0;
        const TAIL_ENTRY_BOOT_ID = 1 << 1;
    }
}

/// `Header.state`. An unrecognized byte is kept verbatim in [`State::Unknown`] rather than
/// guessed at — never invent a state the file didn't declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Offline,
    Online,
    Archived,
    Unknown(u8),
}

impl State {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => State::Offline,
            1 => State::Online,
            2 => State::Archived,
            other => State::Unknown(other),
        }
    }

    pub fn name(self) -> std::borrow::Cow<'static, str> {
        match self {
            State::Offline => "OFFLINE".into(),
            State::Online => "ONLINE".into(),
            State::Archived => "ARCHIVED".into(),
            State::Unknown(b) => format!("UNKNOWN({b})").into(),
        }
    }
}

/// The parsed journal file header. See the module docs for how this was validated against real
/// on-disk bytes.
#[derive(Debug, Clone)]
pub struct Header {
    pub compatible_flags: CompatibleFlags,
    pub incompatible_flags: IncompatibleFlags,
    pub state: State,
    pub file_id: [u8; 16],
    pub machine_id: [u8; 16],
    pub tail_entry_boot_id: [u8; 16],
    pub seqnum_id: [u8; 16],
    pub header_size: u64,
    pub arena_size: u64,
    pub data_hash_table_offset: u64,
    pub data_hash_table_size: u64,
    pub field_hash_table_offset: u64,
    pub field_hash_table_size: u64,
    pub tail_object_offset: u64,
    pub n_objects: u64,
    pub n_entries: u64,
    pub tail_entry_seqnum: u64,
    pub head_entry_seqnum: u64,
    pub entry_array_offset: u64,
    /// Best-effort trailing fields: `None` when the header is shorter than the struct that
    /// declares them (an older format revision, or a truncated/hostile file), never guessed at.
    pub head_entry_realtime: Option<u64>,
    pub tail_entry_realtime: Option<u64>,
    pub tail_entry_monotonic: Option<u64>,
    pub n_data: Option<u64>,
    pub n_fields: Option<u64>,
    pub n_tags: Option<u64>,
    pub n_entry_arrays: Option<u64>,
    pub data_hash_chain_depth: Option<u64>,
    pub field_hash_chain_depth: Option<u64>,
    pub tail_entry_array_offset: Option<u32>,
    pub tail_entry_array_n_entries: Option<u32>,
    pub tail_entry_offset: Option<u64>,
}

impl Header {
    pub fn is_compact(&self) -> bool {
        self.incompatible_flags.contains(IncompatibleFlags::COMPACT)
    }

    pub fn is_keyed_hash(&self) -> bool {
        self.incompatible_flags
            .contains(IncompatibleFlags::KEYED_HASH)
    }

    pub fn is_sealed(&self) -> bool {
        self.compatible_flags.contains(CompatibleFlags::SEALED)
    }

    /// `TAIL_ENTRY_BOOT_ID`: whether [`Header::tail_entry_boot_id`] is meaningful. Older journal
    /// files never populated it.
    pub fn has_tail_entry_boot_id(&self) -> bool {
        self.compatible_flags
            .contains(CompatibleFlags::TAIL_ENTRY_BOOT_ID)
    }

    /// Which compression codec `OBJECT_COMPRESSED_*` object flags refer to in this file, or
    /// `None` if no compression incompatible-flag is set. The three bits are meant to be
    /// mutually exclusive; if a hostile header sets more than one, the lowest-valued (XZ, then
    /// LZ4, then ZSTD) wins, matching the order objects are checked in — this is a defensive
    /// tie-break, not a claim that such a file is well-formed.
    pub fn compression_codec(&self) -> Option<crate::journal::compress::Codec> {
        use crate::journal::compress::Codec;
        if self
            .incompatible_flags
            .contains(IncompatibleFlags::COMPRESSED_XZ)
        {
            Some(Codec::Xz)
        } else if self
            .incompatible_flags
            .contains(IncompatibleFlags::COMPRESSED_LZ4)
        {
            Some(Codec::Lz4)
        } else if self
            .incompatible_flags
            .contains(IncompatibleFlags::COMPRESSED_ZSTD)
        {
            Some(Codec::Zstd)
        } else {
            None
        }
    }
}

/// Parses the header at the start of `bytes`. Bounds-checked throughout via [`ByteReader`];
/// never panics on truncated or hostile input.
///
/// Only the fields up to and including `entry_array_offset` are required (see
/// [`REQUIRED_PREFIX_LEN`]); a file whose declared or actual size is shorter than that is
/// rejected as not a journal file at all, since nothing past that point can be located without
/// it. Fields declared later in the real systemd struct are read opportunistically and left
/// `None` if absent.
pub fn parse(bytes: &[u8]) -> ForensicResult<Header> {
    if bytes.len() < REQUIRED_PREFIX_LEN {
        return Err(ForensicError::invalid_format(
            "journal header",
            format!(
                "file is only {} byte(s), less than the minimum {REQUIRED_PREFIX_LEN} required \
                 header prefix",
                bytes.len()
            ),
        ));
    }
    let mut reader = ByteReader::new(bytes);
    let signature = reader.read_fixed::<8>()?;
    if signature != SIGNATURE {
        return Err(ForensicError::invalid_magic(
            "journal header",
            "LPKSHHRH",
            String::from_utf8_lossy(&signature).into_owned(),
        ));
    }
    let compatible_flags = CompatibleFlags(reader.read_u32_le()?);
    let incompatible_flags = IncompatibleFlags(reader.read_u32_le()?);
    let state = State::from_byte(reader.read_u8()?);
    reader.skip(7)?; // reserved
    let file_id = reader.read_fixed::<16>()?;
    let machine_id = reader.read_fixed::<16>()?;
    let tail_entry_boot_id = reader.read_fixed::<16>()?;
    let seqnum_id = reader.read_fixed::<16>()?;
    let header_size = reader.read_u64_le()?;
    let arena_size = reader.read_u64_le()?;
    let data_hash_table_offset = reader.read_u64_le()?;
    let data_hash_table_size = reader.read_u64_le()?;
    let field_hash_table_offset = reader.read_u64_le()?;
    let field_hash_table_size = reader.read_u64_le()?;
    let tail_object_offset = reader.read_u64_le()?;
    let n_objects = reader.read_u64_le()?;
    let n_entries = reader.read_u64_le()?;
    let tail_entry_seqnum = reader.read_u64_le()?;
    let head_entry_seqnum = reader.read_u64_le()?;
    let entry_array_offset = reader.read_u64_le()?;
    debug_assert_eq!(reader.position(), REQUIRED_PREFIX_LEN);

    let head_entry_realtime = reader.read_u64_le().ok();
    let tail_entry_realtime = reader.read_u64_le().ok();
    let tail_entry_monotonic = reader.read_u64_le().ok();
    let n_data = reader.read_u64_le().ok();
    let n_fields = reader.read_u64_le().ok();
    let n_tags = reader.read_u64_le().ok();
    let n_entry_arrays = reader.read_u64_le().ok();
    let data_hash_chain_depth = reader.read_u64_le().ok();
    let field_hash_chain_depth = reader.read_u64_le().ok();
    let tail_entry_array_offset = reader.read_u32_le().ok();
    let tail_entry_array_n_entries = reader.read_u32_le().ok();
    let tail_entry_offset = reader.read_u64_le().ok();

    Ok(Header {
        compatible_flags,
        incompatible_flags,
        state,
        file_id,
        machine_id,
        tail_entry_boot_id,
        seqnum_id,
        header_size,
        arena_size,
        data_hash_table_offset,
        data_hash_table_size,
        field_hash_table_offset,
        field_hash_table_size,
        tail_object_offset,
        n_objects,
        n_entries,
        tail_entry_seqnum,
        head_entry_seqnum,
        entry_array_offset,
        head_entry_realtime,
        tail_entry_realtime,
        tail_entry_monotonic,
        n_data,
        n_fields,
        n_tags,
        n_entry_arrays,
        data_hash_chain_depth,
        field_hash_chain_depth,
        tail_entry_array_offset,
        tail_entry_array_n_entries,
        tail_entry_offset,
    })
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header_bytes(incompatible: u32, compatible: u32, state: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SIGNATURE);
        buf.extend_from_slice(&compatible.to_le_bytes());
        buf.extend_from_slice(&incompatible.to_le_bytes());
        buf.push(state);
        buf.extend_from_slice(&[0u8; 7]);
        buf.extend_from_slice(&[0xAAu8; 16]); // file_id
        buf.extend_from_slice(&[0xBBu8; 16]); // machine_id
        buf.extend_from_slice(&[0xCCu8; 16]); // tail_entry_boot_id
        buf.extend_from_slice(&[0xDDu8; 16]); // seqnum_id
        buf.extend_from_slice(&272u64.to_le_bytes()); // header_size
        buf.extend_from_slice(&1000u64.to_le_bytes()); // arena_size
        for _ in 0..9 {
            buf.extend_from_slice(&0u64.to_le_bytes());
        }
        buf.extend_from_slice(&176u64.to_le_bytes()); // entry_array_offset
        assert_eq!(buf.len(), REQUIRED_PREFIX_LEN);
        buf
    }

    #[test]
    fn parses_the_required_prefix() {
        let bytes = sample_header_bytes(0, 0, 0);
        let header = parse(&bytes).unwrap();
        assert_eq!(header.file_id, [0xAA; 16]);
        assert_eq!(header.state, State::Offline);
        assert_eq!(header.header_size, 272);
        assert_eq!(header.arena_size, 1000);
        assert_eq!(header.entry_array_offset, 176);
        assert!(
            header.head_entry_realtime.is_none(),
            "no trailing fields present"
        );
    }

    #[test]
    fn rejects_a_bad_magic_instead_of_misreading_it() {
        let mut bytes = sample_header_bytes(0, 0, 0);
        bytes[0] = b'X';
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_a_file_shorter_than_the_required_prefix() {
        let bytes = vec![0u8; 100];
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn decodes_flags_and_state() {
        let bytes = sample_header_bytes(
            IncompatibleFlags::COMPACT.bits() | IncompatibleFlags::KEYED_HASH.bits(),
            CompatibleFlags::SEALED.bits(),
            1,
        );
        let header = parse(&bytes).unwrap();
        assert!(header.is_compact());
        assert!(header.is_keyed_hash());
        assert!(header.is_sealed());
        assert!(!header.has_tail_entry_boot_id());
        assert_eq!(header.state, State::Online);
    }

    #[test]
    fn an_unknown_incompatible_bit_is_never_silently_dropped() {
        let flags = IncompatibleFlags(0x1 << 30);
        assert_ne!(flags.unknown_bits(), 0);
        let known = IncompatibleFlags::COMPACT;
        assert_eq!(known.unknown_bits(), 0);
    }

    #[test]
    fn an_unknown_state_byte_is_kept_verbatim_not_guessed_at() {
        let bytes = sample_header_bytes(0, 0, 200);
        let header = parse(&bytes).unwrap();
        assert_eq!(header.state, State::Unknown(200));
    }
}
