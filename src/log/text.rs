//! Shared line-oriented text-log scaffold — Plaso's "text plugin" idea: one host that handles
//! line iteration, encoding and error containment, with per-format matchers ([`super::syslog`],
//! [`super::audit`], [`crate::shell`], [`crate::packages`]) built on top instead of four bespoke
//! readers.
//!
//! What lives here on purpose, and nothing more:
//!
//! * [`scan_lines`] — split raw bytes into 1-based-numbered [`TextLine`]s, without assuming the
//!   whole file is valid UTF-8 and without inventing a trailing empty line when the file ends
//!   with a newline.
//! * [`systematic_parse_failure`] — turns a high per-file failure rate into one extra `Err` item,
//!   distinct from the one-`Err`-per-bad-line the caller already emits, so an analyst sees "this
//!   whole file looks like the wrong format" instead of wading through hundreds of identical line
//!   errors to notice the pattern themselves.
//! * [`hex_encode`] / [`hex_decode`] — shared by [`super::audit`]'s `a0`/`a1`/`proctitle` decoding
//!   today; crate-local, not an upstream `forensic-rs` API.
//!
//! Format-specific concerns — what a line *means* — stay in the per-format modules.

use std::borrow::Cow;

use forensic_rs::prelude::*;

/// One line read from a text log file, still exactly as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextLine<'a> {
    /// 1-based line number within the file (counting `\n`-terminated segments, so it matches
    /// what a human counts opening the file in an editor).
    pub number: usize,
    /// The raw bytes of the line, with the line terminator (`\n`, and a preceding `\r` if
    /// present) stripped but otherwise untouched. Never lossily decoded here: that is
    /// [`Self::text`]'s job, and only for display.
    pub raw: &'a [u8],
}

impl<'a> TextLine<'a> {
    /// [`Self::raw`], lossy-decoded for display/matching only. Non-UTF-8 bytes become U+FFFD;
    /// [`Self::raw`] is what a caller should keep for provenance.
    pub fn text(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.raw)
    }
}

/// Splits `bytes` into [`TextLine`]s on `\n`, trimming one trailing `\r` per line (CRLF) and
/// never yielding a phantom empty final line just because the file ends with `\n`. A final line
/// with no trailing newline (a log still being written, or truncated mid-line) is still yielded.
/// An empty file yields no lines; a file that is just `"\n"` yields one empty line (a genuine
/// blank line before EOF), and a blank line in the middle of a file is preserved the same way —
/// this function does not decide which lines are meaningful, only where they are.
pub fn scan_lines(bytes: &[u8]) -> Vec<TextLine<'_>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let trimmed = match bytes.strip_suffix(b"\n") {
        Some(rest) => rest,
        None => bytes,
    };
    trimmed
        .split(|&b| b == b'\n')
        .enumerate()
        .map(|(i, raw)| {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            TextLine { number: i + 1, raw }
        })
        .collect()
}

/// Builds a [`ForensicError`] for a per-file line-failure rate that signals a systematic
/// mismatch (wrong format, truncation, corruption) rather than a handful of odd lines. Returns
/// `None` below the threshold: each bad line is already its own `Err` item, so a small number of
/// them needs no extra summary. `total` is the number of lines the format module attempted to
/// parse (blank lines the format treats as not-data are the caller's decision to exclude before
/// calling this).
pub fn systematic_parse_failure(
    path: &FPath,
    format: &'static str,
    total: usize,
    failed: usize,
) -> Option<ForensicError> {
    // A tiny file (a couple of lines) failing is not "systematic" in any useful sense, and
    // dividing by a near-zero total would make the ratio noisy; require a real sample size.
    if total < 4 || failed * 2 < total {
        return None;
    }
    Some(
        ForensicError::other(
            format,
            format!(
                "{failed} of {total} lines failed to parse as {format}; the file may be a \
                 different format, truncated, or corrupted"
            ),
        )
        .with_path(path),
    )
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex of `bytes`. Shared by [`super::audit`]; crate-local, not an upstream API.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

/// Decodes a hex string into bytes. `None` for anything that is not a well-formed hex string
/// (odd length, non-hex-digit byte) rather than guessing — the raw text stays available to the
/// caller either way, so a rejected decode loses nothing.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let (chunks, _) = bytes.as_chunks::<2>();
    let mut out = Vec::with_capacity(chunks.len());
    for pair in chunks {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_yields_no_lines() {
        assert!(scan_lines(b"").is_empty());
    }

    #[test]
    fn a_lone_newline_yields_one_empty_line_not_two() {
        let lines = scan_lines(b"\n");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].raw, b"");
        assert_eq!(lines[0].number, 1);
    }

    #[test]
    fn a_trailing_newline_does_not_add_a_phantom_final_line() {
        let lines = scan_lines(b"a\nb\n");
        let texts: Vec<&str> = lines.iter().map(|l| l.raw).map(|r| std::str::from_utf8(r).unwrap()).collect();
        assert_eq!(texts, vec!["a", "b"]);
    }

    #[test]
    fn a_missing_trailing_newline_still_yields_the_last_line() {
        let lines = scan_lines(b"a\nb");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].raw, b"b");
    }

    #[test]
    fn a_blank_line_in_the_middle_is_preserved() {
        let lines = scan_lines(b"a\n\nb\n");
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1].raw, b"");
    }

    #[test]
    fn a_trailing_cr_is_stripped_as_part_of_the_line_terminator() {
        let lines = scan_lines(b"a\r\nb\r\n");
        assert_eq!(lines[0].raw, b"a");
        assert_eq!(lines[1].raw, b"b");
    }

    #[test]
    fn line_numbers_are_one_based_and_sequential() {
        let lines = scan_lines(b"a\nb\nc\n");
        let numbers: Vec<usize> = lines.iter().map(|l| l.number).collect();
        assert_eq!(numbers, vec![1, 2, 3]);
    }

    #[test]
    fn non_utf8_bytes_are_kept_raw_and_only_lossy_decoded_for_display() {
        let bytes: &[u8] = &[b'a', 0xFF, 0xFE, b'\n'];
        let lines = scan_lines(bytes);
        assert_eq!(lines[0].raw, &[b'a', 0xFF, 0xFE]);
        assert!(lines[0].text().contains('\u{FFFD}'));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = b"\x00\x01\xFF/bin/ls";
        let encoded = hex_encode(bytes);
        assert_eq!(hex_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_odd_length_and_non_hex() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode("").is_none());
    }

    #[test]
    fn systematic_failure_is_none_below_threshold() {
        let path = FPathBuf::from("var/log/x.log");
        assert!(systematic_parse_failure(path.as_path(), "test", 3, 3).is_none());
        assert!(systematic_parse_failure(path.as_path(), "test", 10, 4).is_none());
    }

    #[test]
    fn systematic_failure_fires_at_half_or_more() {
        let path = FPathBuf::from("var/log/x.log");
        let err = systematic_parse_failure(path.as_path(), "test", 10, 5).unwrap();
        assert!(err.to_string().contains("5 of 10"));
    }
}
