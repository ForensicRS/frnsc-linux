//! A minimal systemd-unit-file reader, shared by `linux.schedule` (`.timer` units) and
//! `linux.units` (`.service` units). Not a general INI parser: it follows systemd's own
//! `\`-continuation convention (via [`crate::text::join_backslash_continuations`]) and — unlike
//! most INI readers — never collapses a repeated key, because systemd unit files use repetition
//! meaningfully (multiple `After=` lines all apply).

use crate::text;

/// One `key=value` line under a `[Section]` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub section: String,
    pub key: String,
    pub value: String,
    pub line: usize,
}

/// A non-blank, non-comment line that is neither a `[Section]` header nor a `key=value` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unparsed {
    pub line: usize,
    pub text: String,
}

/// Reads every `[Section]`/`key=value` entry in `bytes`, in file order, plus every line that
/// fit neither shape. Never panics on arbitrary evidence bytes; a `key=value` line outside any
/// `[Section]` gets `section == ""`, never dropped.
pub fn parse(bytes: &[u8]) -> (Vec<Entry>, Vec<Unparsed>) {
    let mut entries = Vec::new();
    let mut unparsed = Vec::new();
    let mut section = String::new();
    for logical in text::join_backslash_continuations(bytes) {
        let trimmed = logical.text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        match trimmed.split_once('=') {
            Some((key, value)) => entries.push(Entry {
                section: section.clone(),
                key: key.trim().to_string(),
                value: value.trim().to_string(),
                line: logical.starting_line,
            }),
            None => unparsed.push(Unparsed {
                line: logical.starting_line,
                text: trimmed.to_string(),
            }),
        }
    }
    (entries, unparsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sections_and_key_value_pairs() {
        let bytes = b"[Unit]\nDescription=Example\nAfter=network.target\n\n[Service]\nExecStart=/usr/bin/example\n";
        let (entries, unparsed) = parse(bytes);
        assert!(unparsed.is_empty());
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].section, "Unit");
        assert_eq!(entries[0].key, "Description");
        assert_eq!(entries[0].value, "Example");
        assert_eq!(entries[2].section, "Service");
        assert_eq!(entries[2].key, "ExecStart");
    }

    #[test]
    fn repeated_keys_are_never_collapsed() {
        let bytes = b"[Unit]\nAfter=a.service\nAfter=b.service\n";
        let (entries, _) = parse(bytes);
        let after: Vec<&str> = entries
            .iter()
            .filter(|e| e.key == "After")
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(after, vec!["a.service", "b.service"]);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let bytes = b"[Unit]\n# a comment\n; also a comment\n\nDescription=x\n";
        let (entries, unparsed) = parse(bytes);
        assert_eq!(entries.len(), 1);
        assert!(unparsed.is_empty());
    }

    #[test]
    fn a_line_with_no_equals_and_no_section_syntax_is_reported_unparsed_not_dropped() {
        let bytes = b"[Unit]\ngarbage line with no equals sign\nDescription=x\n";
        let (entries, unparsed) = parse(bytes);
        assert_eq!(entries.len(), 1);
        assert_eq!(unparsed.len(), 1);
        assert_eq!(unparsed[0].text, "garbage line with no equals sign");
    }

    #[test]
    fn continuation_lines_are_joined_before_being_parsed() {
        let bytes = b"[Service]\nExecStart=/usr/bin/example \\\n    --flag value\n";
        let (entries, _) = parse(bytes);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].value.contains("--flag value"));
    }
}
