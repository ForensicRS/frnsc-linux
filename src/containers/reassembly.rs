//! Partial-line reassembly, shared by the Docker `json-file` and containerd/CRI line formats.
//!
//! Both formats can split one logical line of container output across several on-disk records
//! when the line exceeds the log driver's write buffer: every fragment but the last carries a
//! "this is not the end of the line" marker (no trailing `\n` for Docker, `P` for CRI). This
//! reassembler concatenates consecutive fragments verbatim (no separator inserted -- the split
//! happened mid-line, so the original bytes must come back together with nothing between them)
//! until a terminal fragment arrives, and never drops a fragment that never sees one.

/// One reassembled logical line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedLine {
    /// The concatenated bytes of every fragment, in order.
    pub bytes: Vec<u8>,
    /// How many on-disk records contributed to this line. `1` for an ordinary, unsplit line.
    pub fragment_count: usize,
    /// `fragment_count > 1`: this line was reconstructed from more than one record.
    pub reassembled: bool,
    /// The stream never saw a terminal fragment before the file ended -- these bytes are
    /// genuine evidence, kept rather than dropped, but the line may not be complete.
    pub truncated: bool,
}

/// Buffers fragments for one logical line until a terminal fragment closes it.
///
/// Callers that reassemble more than one concurrent line per file (Docker and CRI both tag
/// every record with a stream, and stdout/stderr fragments never interleave with each other)
/// keep one `LineReassembler` per stream key.
#[derive(Debug, Default)]
pub struct LineReassembler {
    buffer: Vec<u8>,
    fragment_count: usize,
}

impl LineReassembler {
    /// Feeds one fragment. Returns `Some` once `is_final` closes the line; the caller must emit
    /// that completed line before pushing more fragments for the same logical line (a fresh
    /// buffer is started internally either way).
    pub fn push(&mut self, mut bytes: Vec<u8>, is_final: bool) -> Option<CompletedLine> {
        self.buffer.append(&mut bytes);
        self.fragment_count += 1;
        if !is_final {
            return None;
        }
        let fragment_count = self.fragment_count;
        self.fragment_count = 0;
        Some(CompletedLine {
            bytes: std::mem::take(&mut self.buffer),
            fragment_count,
            reassembled: fragment_count > 1,
            truncated: false,
        })
    }

    /// Call once at end-of-file: flushes a trailing partial line that never saw a terminal
    /// fragment. `None` when nothing is buffered (the ordinary, cleanly-closed case).
    pub fn flush_incomplete(&mut self) -> Option<CompletedLine> {
        if self.buffer.is_empty() {
            return None;
        }
        let fragment_count = self.fragment_count;
        self.fragment_count = 0;
        Some(CompletedLine {
            bytes: std::mem::take(&mut self.buffer),
            fragment_count,
            reassembled: fragment_count > 1,
            truncated: true,
        })
    }
}

/// A [`LineReassembler`] plus the timestamp of the fragment that *started* the line currently
/// being buffered -- Docker and CRI both stamp every fragment individually, but the forensically
/// meaningful time for a reassembled line is when it started, not when the last fragment (which
/// may arrive much later for a slow writer) closed it.
#[derive(Debug, Default)]
pub struct StreamBuffer {
    reassembler: LineReassembler,
    start_time_raw: Option<String>,
    start_timestamp: Option<forensic_rs::utils::time::ForensicTimestamp>,
}

/// A completed line plus the time its first fragment carried.
pub struct TimedLine {
    pub line: CompletedLine,
    pub time_raw: String,
    pub timestamp: Option<forensic_rs::utils::time::ForensicTimestamp>,
}

impl StreamBuffer {
    pub fn push(
        &mut self,
        bytes: Vec<u8>,
        is_final: bool,
        time_raw: &str,
        timestamp: Option<forensic_rs::utils::time::ForensicTimestamp>,
    ) -> Option<TimedLine> {
        if self.start_time_raw.is_none() {
            self.start_time_raw = Some(time_raw.to_string());
            self.start_timestamp = timestamp;
        }
        let line = self.reassembler.push(bytes, is_final)?;
        Some(TimedLine {
            line,
            time_raw: self.start_time_raw.take().unwrap_or_default(),
            timestamp: self.start_timestamp.take(),
        })
    }

    pub fn flush_incomplete(&mut self) -> Option<TimedLine> {
        let line = self.reassembler.flush_incomplete()?;
        Some(TimedLine {
            line,
            time_raw: self.start_time_raw.take().unwrap_or_default(),
            timestamp: self.start_timestamp.take(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_final_fragment_is_not_marked_reassembled() {
        let mut r = LineReassembler::default();
        let line = r.push(b"hello".to_vec(), true).unwrap();
        assert_eq!(line.bytes, b"hello");
        assert_eq!(line.fragment_count, 1);
        assert!(!line.reassembled);
        assert!(!line.truncated);
    }

    #[test]
    fn a_line_split_three_ways_is_concatenated_with_no_separator_and_marked_reassembled() {
        let mut r = LineReassembler::default();
        assert!(r.push(b"hel".to_vec(), false).is_none());
        assert!(r.push(b"lo w".to_vec(), false).is_none());
        let line = r.push(b"orld\n".to_vec(), true).unwrap();
        assert_eq!(line.bytes, b"hello world\n");
        assert_eq!(line.fragment_count, 3);
        assert!(line.reassembled);
        assert!(!line.truncated);
    }

    #[test]
    fn flush_incomplete_returns_the_buffered_fragments_marked_truncated() {
        let mut r = LineReassembler::default();
        r.push(b"hel".to_vec(), false);
        r.push(b"lo".to_vec(), false);
        let line = r.flush_incomplete().unwrap();
        assert_eq!(line.bytes, b"hello");
        assert_eq!(line.fragment_count, 2);
        assert!(line.reassembled);
        assert!(line.truncated);
    }

    #[test]
    fn flush_incomplete_is_none_after_a_clean_close() {
        let mut r = LineReassembler::default();
        r.push(b"done\n".to_vec(), true);
        assert!(r.flush_incomplete().is_none());
    }

    #[test]
    fn the_buffer_resets_between_logical_lines() {
        let mut r = LineReassembler::default();
        let first = r.push(b"first\n".to_vec(), true).unwrap();
        assert_eq!(first.bytes, b"first\n");
        let second = r.push(b"second\n".to_vec(), true).unwrap();
        assert_eq!(second.bytes, b"second\n", "must not still contain 'first'");
        assert_eq!(second.fragment_count, 1);
    }

    #[test]
    fn stream_buffer_keeps_the_first_fragments_timestamp_not_the_lasts() {
        use forensic_rs::utils::time::ForensicTimestamp;
        let mut buf = StreamBuffer::default();
        let early = ForensicTimestamp::from_unix_micros(1_000_000);
        let late = ForensicTimestamp::from_unix_micros(2_000_000);
        assert!(buf
            .push(b"hel".to_vec(), false, "T1", Some(early))
            .is_none());
        let timed = buf.push(b"lo\n".to_vec(), true, "T2", Some(late)).unwrap();
        assert_eq!(timed.line.bytes, b"hello\n");
        assert_eq!(timed.time_raw, "T1");
        assert_eq!(timed.timestamp, Some(early));
    }

    #[test]
    fn stream_buffer_flush_incomplete_keeps_the_pending_lines_start_time() {
        use forensic_rs::utils::time::ForensicTimestamp;
        let mut buf = StreamBuffer::default();
        let ts = ForensicTimestamp::from_unix_micros(42);
        buf.push(b"partial".to_vec(), false, "T1", Some(ts));
        let timed = buf.flush_incomplete().unwrap();
        assert_eq!(timed.line.bytes, b"partial");
        assert!(timed.line.truncated);
        assert_eq!(timed.time_raw, "T1");
        assert_eq!(timed.timestamp, Some(ts));
    }
}
