//! Byte-safe line splitting shared by every text/config parser in this crate.
//!
//! Every parser here reads evidence that is nominally text but not guaranteed to be valid UTF-8
//! (a corrupted file, a deliberately hostile field). Lines keep their raw bytes; only display or
//! parsing convenience goes through a lossy decode, matching [`crate::unix::utmp`]'s
//! raw-field-first convention.

use std::borrow::Cow;

/// One physical line of a text file: its 1-based line number and its bytes with a trailing
/// `\n`/`\r\n` stripped.
#[derive(Debug, Clone, Copy)]
pub struct Line<'a> {
    pub number: usize,
    pub bytes: &'a [u8],
}

impl<'a> Line<'a> {
    /// Lossy-decoded for display/parsing convenience. Never the basis for silently dropping the
    /// raw bytes — callers that must keep the exact bytes use [`Self::bytes`] directly.
    pub fn text(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.bytes)
    }
}

/// Splits `bytes` into physical lines on `\n`, stripping one trailing `\r` per line. Never
/// panics on arbitrary evidence bytes. Empty input yields no lines; a file with no trailing `\n`
/// still yields its last (possibly empty) line; a file that does end in `\n` does not report a
/// synthetic empty line after it.
pub fn lines(bytes: &[u8]) -> Vec<Line<'_>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if bytes.last() == Some(&b'\n') {
        parts.pop();
    }
    parts
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| Line {
            number: i + 1,
            bytes: strip_trailing_cr(chunk),
        })
        .collect()
}

fn strip_trailing_cr(chunk: &[u8]) -> &[u8] {
    match chunk.last() {
        Some(b'\r') => &chunk[..chunk.len() - 1],
        _ => chunk,
    }
}

/// Splits a `,`-separated list field (group members, sudoers lists, ...), trimming whitespace
/// around each entry and dropping empty entries (a trailing comma, a doubled comma).
pub fn comma_list(field: &str) -> Vec<String> {
    field
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// One logical line after joining `\`-continued physical lines — the continuation convention
/// shared by `sudoers` and systemd unit files. `starting_line` is the physical line number the
/// logical line began on.
#[derive(Debug, Clone)]
pub struct LogicalLine {
    pub starting_line: usize,
    pub text: String,
}

/// Joins `\`-terminated physical lines of `bytes` into logical lines.
pub fn join_backslash_continuations(bytes: &[u8]) -> Vec<LogicalLine> {
    let mut out = Vec::new();
    let mut pending: Option<LogicalLine> = None;
    for line in lines(bytes) {
        let piece = line.text();
        let continues = piece.ends_with('\\');
        let content = piece.strip_suffix('\\').unwrap_or(&piece);
        match pending.take() {
            Some(mut acc) => {
                acc.text.push_str(content);
                pending = Some(acc);
            }
            None => {
                pending = Some(LogicalLine {
                    starting_line: line.number,
                    text: content.to_string(),
                });
            }
        }
        if !continues {
            out.push(pending.take().unwrap());
        }
    }
    if let Some(acc) = pending {
        out.push(acc);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_no_lines() {
        assert!(lines(b"").is_empty());
    }

    #[test]
    fn a_trailing_newline_does_not_add_an_empty_line() {
        let ls = lines(b"a\nb\n");
        assert_eq!(ls.len(), 2);
        assert_eq!(ls[0].text(), "a");
        assert_eq!(ls[1].text(), "b");
    }

    #[test]
    fn no_trailing_newline_still_yields_the_last_line() {
        let ls = lines(b"a\nb");
        assert_eq!(ls.len(), 2);
        assert_eq!(ls[1].text(), "b");
    }

    #[test]
    fn crlf_line_endings_are_stripped() {
        let ls = lines(b"a\r\nb\r\n");
        assert_eq!(ls[0].bytes, b"a");
        assert_eq!(ls[1].bytes, b"b");
    }

    #[test]
    fn line_numbers_are_one_based() {
        let ls = lines(b"first\nsecond\nthird");
        let numbers: Vec<usize> = ls.iter().map(|l| l.number).collect();
        assert_eq!(numbers, vec![1, 2, 3]);
    }

    #[test]
    fn non_utf8_bytes_are_kept_raw_and_only_lossy_decoded_for_display() {
        let raw: &[u8] = b"us\xFFer\n";
        let ls = lines(raw);
        assert_eq!(ls[0].bytes, b"us\xFFer");
        assert!(ls[0].text().contains('\u{FFFD}'));
    }

    #[test]
    fn comma_list_trims_and_drops_empties() {
        assert_eq!(
            comma_list(" alice, bob ,,carol"),
            vec!["alice", "bob", "carol"]
        );
        assert!(comma_list("").is_empty());
    }

    #[test]
    fn backslash_continuations_are_joined_and_track_the_starting_line() {
        let logical = join_backslash_continuations(b"alice ALL = (root) \\\n    ALL\nbob ALL\n");
        assert_eq!(logical.len(), 2);
        assert_eq!(logical[0].starting_line, 1);
        assert!(logical[0].text.contains("ALL"));
        assert_eq!(logical[1].starting_line, 3);
        assert_eq!(logical[1].text, "bob ALL");
    }
}
