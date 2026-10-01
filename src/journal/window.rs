//! [`Window`]: a bounds-checked `offset -> &[u8]` view over one journal file's bytes.
//!
//! Every object in a journal file is found by absolute offset, not by sequential reading, so the
//! reader needs random access rather than [`forensic_rs::parsing::ByteReader`]'s cursor shape.
//! [`Window::slice`] is the single choke point every other module in `journal/` goes through to
//! turn an offset into bytes: it checks the offset against both the real (possibly truncated)
//! file length *and* the header's own `arena_size`, per the hostile-input rule that every offset
//! must be checked against both before any read.

use forensic_rs::prelude::*;

/// A bounds-checked view over one journal file's bytes.
#[derive(Debug, Clone, Copy)]
pub struct Window<'a> {
    data: &'a [u8],
    /// End of the arena the header declares (`header_size + arena_size`), which may be larger
    /// than `data.len()` for a truncated file — in that case the real file length is always the
    /// tighter bound, and [`Window::slice`] enforces both.
    declared_end: u64,
}

impl<'a> Window<'a> {
    /// `header_size`/`arena_size` come from the parsed [`crate::journal::header::Header`].
    pub fn new(data: &'a [u8], header_size: u64, arena_size: u64) -> Self {
        let declared_end = header_size.saturating_add(arena_size);
        Window { data, declared_end }
    }

    /// The real, possibly-truncated length of the underlying file. This — never the header's own
    /// `arena_size` — is what a recovery scan walks to, so a hostile or stale `arena_size` can
    /// only shrink what is reachable, never expand a read past real bytes.
    pub fn file_len(&self) -> u64 {
        self.data.len() as u64
    }

    /// The declared end of the arena (`header_size + arena_size`), clamped to nothing by itself —
    /// callers that want the tighter of the two bounds should compare against
    /// [`Self::file_len`] too, as [`Self::slice`] already does internally.
    pub fn declared_end(&self) -> u64 {
        self.declared_end
    }

    /// Returns exactly `len` bytes starting at `offset`, or an error naming which bound was
    /// violated. Checked against the real file length *and* the header's declared arena end;
    /// checked for `u64` overflow before either comparison, so a hostile `offset`/`len` pair
    /// cannot wrap around to a small, spuriously "in range" value.
    pub fn slice(&self, offset: u64, len: u64) -> ForensicResult<&'a [u8]> {
        let end = offset.checked_add(len).ok_or_else(|| {
            ForensicError::invalid_format(
                "journal object",
                format!("offset {offset} + length {len} overflows u64"),
            )
        })?;
        if end > self.file_len() {
            return Err(ForensicError::buffer_out_of_bounds(
                end as usize,
                self.data.len(),
            ));
        }
        if end > self.declared_end {
            return Err(ForensicError::invalid_format(
                "journal object",
                format!(
                    "offset {offset} + length {len} = {end} exceeds the header's declared arena \
                     end {}",
                    self.declared_end
                ),
            ));
        }
        // Safe: offset <= end <= self.data.len(), checked above.
        Ok(&self.data[offset as usize..end as usize])
    }

    /// [`Self::slice`] wrapped in a [`ByteReader`] for structured field-by-field reads.
    pub fn reader_at(&self, offset: u64, len: u64) -> ForensicResult<ByteReader<'a>> {
        Ok(ByteReader::new(self.slice(offset, len)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_within_bounds() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let win = Window::new(&data, 0, 8);
        assert_eq!(win.slice(2, 3).unwrap(), &[3, 4, 5]);
    }

    #[test]
    fn rejects_a_slice_past_the_real_file_length() {
        let data = [1u8, 2, 3, 4];
        let win = Window::new(&data, 0, 1000); // declared arena is a lie
        assert!(win.slice(0, 5).is_err(), "file is only 4 bytes long");
    }

    #[test]
    fn rejects_a_slice_past_the_declared_arena_even_if_the_file_is_longer() {
        let data = [0u8; 100];
        let win = Window::new(&data, 8, 10); // arena ends at byte 18
        assert!(
            win.slice(15, 10).is_err(),
            "would read past declared_end=18"
        );
        assert!(win.slice(15, 3).is_ok());
    }

    #[test]
    fn rejects_an_overflowing_offset_length_pair_instead_of_wrapping() {
        let data = [0u8; 16];
        let win = Window::new(&data, 0, 16);
        assert!(win.slice(u64::MAX - 2, 10).is_err());
    }
}
