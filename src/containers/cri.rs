//! containerd/CRI log lines: `/var/log/pods/<namespace>_<pod>_<uid>/<container>/N.log`, one
//! space-separated record per line: `<RFC3339Nano> <stdout|stderr> <P|F> <message>`.
//!
//! Unlike Docker's JSON format, the message here is raw bytes straight from the container's
//! stdout/stderr with no JSON-string encoding step in between, so it can be anything, including
//! invalid UTF-8. [`parse_line`] keeps it as `Vec<u8>` for exactly that reason -- see the crate
//! rule that non-UTF-8 evidence is kept raw and only lossy-decoded for display.

use forensic_rs::core::path::FPath;
use forensic_rs::prelude::{ForensicError, ForensicResult, ForensicTimestamp};

use super::time::parse_rfc3339_nano;

const KIND: &str = "containerd/CRI log line";

pub(crate) struct CriLogLine {
    pub time_raw: String,
    pub timestamp: Option<ForensicTimestamp>,
    pub stream: String,
    /// `true` for a terminal (`F`) fragment, `false` for a partial (`P`) one.
    pub is_final: bool,
    /// The raw message bytes: everything after the third space, verbatim.
    pub message: Vec<u8>,
}

/// Parses one line (without its trailing `\n`). A line that doesn't have all three
/// space-delimited fields, or whose tag is neither `P` nor `F`, is one `Err`, never a panic; the
/// caller keeps scanning the rest of the file.
pub(crate) fn parse_line(line: &[u8]) -> ForensicResult<CriLogLine> {
    let first_space = find(line, 0).ok_or_else(|| missing_field(KIND, "stream"))?;
    let second_space = find(line, first_space + 1).ok_or_else(|| missing_field(KIND, "P/F tag"))?;
    let third_space = find(line, second_space + 1).ok_or_else(|| missing_field(KIND, "message"))?;

    let time_raw = std::str::from_utf8(&line[..first_space])
        .map_err(|_| ForensicError::invalid_format(KIND, "timestamp field is not valid UTF-8"))?
        .to_string();
    let stream = std::str::from_utf8(&line[first_space + 1..second_space])
        .map_err(|_| ForensicError::invalid_format(KIND, "stream field is not valid UTF-8"))?
        .to_string();
    let tag = &line[second_space + 1..third_space];
    let is_final = match tag {
        b"F" => true,
        b"P" => false,
        other => {
            return Err(ForensicError::invalid_format(
                KIND,
                format!(
                    "expected the P/F tag to be exactly \"P\" or \"F\", got {:?}",
                    String::from_utf8_lossy(other)
                ),
            ))
        }
    };
    let message = line[third_space + 1..].to_vec();
    let timestamp = parse_rfc3339_nano(&time_raw);

    Ok(CriLogLine {
        time_raw,
        timestamp,
        stream,
        is_final,
        message,
    })
}

fn find(line: &[u8], from: usize) -> Option<usize> {
    line.get(from..)?
        .iter()
        .position(|&b| b == b' ')
        .map(|p| p + from)
}

fn missing_field(kind: &'static str, field: &str) -> ForensicError {
    ForensicError::invalid_format(kind, format!("missing the {field} field"))
}

/// Identity derived purely from a `/var/log/pods/<namespace>_<pod>_<uid>/<container>/N.log`
/// path -- the weaker, path-derived claim the design doc calls out, since nothing here is
/// confirmed against container metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PodPathIdentity {
    pub namespace: String,
    pub pod: String,
    pub uid: String,
    pub container: String,
}

/// Parses the pods-directory path layout. `None` when the path doesn't have at least
/// `.../<ns>_<pod>_<uid>/<container>/<file>` (e.g. a shallower or differently-shaped match) or
/// when the `<ns>_<pod>_<uid>` segment doesn't split into exactly three `_`-separated parts --
/// Kubernetes namespace and pod names are DNS-1123 labels and can never contain `_` themselves,
/// so a clean 3-way split is the expected shape, not a coincidence.
pub(crate) fn identity_from_pods_path(path: &FPath) -> Option<PodPathIdentity> {
    let container_dir = path.parent()?;
    let container = container_dir.file_name()?;
    let pod_dir = container_dir.parent()?;
    let ns_pod_uid = pod_dir.file_name()?;
    let mut parts = ns_pod_uid.splitn(3, '_');
    let namespace = parts.next()?;
    let pod = parts.next()?;
    let uid = parts.next()?;
    if namespace.is_empty() || pod.is_empty() || uid.is_empty() {
        return None;
    }
    Some(PodPathIdentity {
        namespace: namespace.to_string(),
        pod: pod.to_string(),
        uid: uid.to_string(),
        container: container.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_rs::core::path::FPathBuf;

    #[test]
    fn parses_a_full_line() {
        let line = b"2023-11-15T12:34:56.000000000Z stdout F hello world";
        let record = parse_line(line).unwrap();
        assert_eq!(record.stream, "stdout");
        assert!(record.is_final);
        assert_eq!(record.message, b"hello world");
        assert!(record.timestamp.is_some());
    }

    #[test]
    fn a_partial_tag_is_not_final() {
        let line = b"2023-11-15T12:34:56.000000000Z stderr P partial chunk";
        let record = parse_line(line).unwrap();
        assert!(!record.is_final);
        assert_eq!(record.message, b"partial chunk");
    }

    #[test]
    fn the_message_may_itself_contain_spaces_and_is_never_re_split() {
        let line = b"2023-11-15T12:34:56.000000000Z stdout F a b c d e";
        let record = parse_line(line).unwrap();
        assert_eq!(record.message, b"a b c d e");
    }

    #[test]
    fn non_utf8_message_bytes_are_kept_raw() {
        let mut line = b"2023-11-15T12:34:56.000000000Z stdout F ".to_vec();
        line.extend_from_slice(&[0xFF, 0xFE, b'x']);
        let record = parse_line(&line).unwrap();
        assert_eq!(&record.message, &[0xFF, 0xFE, b'x']);
        assert!(std::str::from_utf8(&record.message).is_err());
    }

    #[test]
    fn an_empty_message_is_valid() {
        let line = b"2023-11-15T12:34:56.000000000Z stdout F ";
        let record = parse_line(line).unwrap();
        assert_eq!(record.message, b"");
    }

    #[test]
    fn an_invalid_tag_is_an_error_not_a_panic() {
        assert!(parse_line(b"2023-11-15T12:34:56.000000000Z stdout X hello").is_err());
    }

    #[test]
    fn missing_fields_are_errors_not_panics() {
        assert!(parse_line(b"").is_err());
        assert!(parse_line(b"2023-11-15T12:34:56.000000000Z").is_err());
        assert!(parse_line(b"2023-11-15T12:34:56.000000000Z stdout").is_err());
        assert!(parse_line(b"2023-11-15T12:34:56.000000000Z stdout F").is_err());
    }

    #[test]
    fn extracts_identity_from_a_well_formed_pods_path() {
        let path = FPathBuf::from("var/log/pods/kube-system_coredns-abc123_a1b2c3d4/coredns/0.log");
        let identity = identity_from_pods_path(path.as_path()).unwrap();
        assert_eq!(identity.namespace, "kube-system");
        assert_eq!(identity.pod, "coredns-abc123");
        assert_eq!(identity.uid, "a1b2c3d4");
        assert_eq!(identity.container, "coredns");
    }

    #[test]
    fn a_path_too_shallow_to_have_the_expected_layout_yields_no_identity() {
        let path = FPathBuf::from("var/log/pods/onlyonedir/0.log");
        assert!(identity_from_pods_path(path.as_path()).is_none());
    }

    #[test]
    fn a_dir_name_that_does_not_split_into_three_parts_yields_no_identity() {
        let path = FPathBuf::from("var/log/pods/not-enough-parts/coredns/0.log");
        assert!(identity_from_pods_path(path.as_path()).is_none());
    }
}
