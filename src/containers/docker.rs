//! Docker `json-file` log driver: one JSON object per line at
//! `/var/lib/docker/containers/<id>/<id>-json.log[.N]`, plus the `config.v2.json`/
//! `hostconfig.json` sidecar files in the same directory that carry container identity.
//!
//! # Line format
//!
//! `{"log":"...","stream":"stdout|stderr","time":"RFC3339Nano"}`. A line longer than the
//! driver's internal buffer is split across several JSON records: every fragment but the last
//! omits the trailing `\n` that `"log"` would otherwise end with, so [`is_final_fragment`] is
//! the same "does this end the logical line" test the write side used to decide where to split.
//!
//! JSON already forces the `"log"` string to be valid Unicode (Docker replaces invalid bytes
//! with U+FFFD before it ever reaches the log file), so unlike the CRI format there is no raw,
//! possibly-non-UTF-8 message to preserve here.

use forensic_rs::prelude::{ForensicError, ForensicResult, ForensicTimestamp};

use super::time::parse_rfc3339_nano;

pub(crate) struct DockerLogLine {
    pub message: String,
    pub stream: String,
    pub time_raw: String,
    pub timestamp: Option<ForensicTimestamp>,
}

const KIND: &str = "docker json-file log line";

/// Parses one line (without its trailing `\n`) of a Docker `json-file` log. Malformed JSON, a
/// non-object value, or a missing required field is one `Err`, never a panic; the caller keeps
/// scanning the rest of the file.
pub(crate) fn parse_line(line: &[u8]) -> ForensicResult<DockerLogLine> {
    let value: serde_json::Value = serde_json::from_slice(line)
        .map_err(|e| ForensicError::invalid_format(KIND, format!("invalid JSON: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| ForensicError::invalid_format(KIND, "top-level value is not a JSON object"))?;
    let message = obj
        .get("log")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ForensicError::invalid_format(KIND, "missing string field \"log\""))?
        .to_string();
    let stream = obj
        .get("stream")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ForensicError::invalid_format(KIND, "missing string field \"stream\""))?
        .to_string();
    let time_raw = obj
        .get("time")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ForensicError::invalid_format(KIND, "missing string field \"time\""))?
        .to_string();
    let timestamp = parse_rfc3339_nano(&time_raw);
    Ok(DockerLogLine { message, stream, time_raw, timestamp })
}

/// Whether `message` (a line's `"log"` field) closes the logical line, per the module docs.
pub(crate) fn is_final_fragment(message: &str) -> bool {
    message.ends_with('\n')
}

/// Container identity as read from `config.v2.json` and, where present, `hostconfig.json` --
/// never from the log lines themselves. Each field is `None`/empty when its source file didn't
/// have it, never guessed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DockerContainerIdentity {
    /// `config.v2.json` `"ID"`.
    pub id: Option<String>,
    /// `config.v2.json` `"Name"`, with the leading `/` Docker always prefixes it with stripped.
    pub name: Option<String>,
    /// `config.v2.json` `"Config"."Image"`: the image reference as configured (name:tag or digest).
    pub image: Option<String>,
    /// `config.v2.json` top-level `"Image"`: the resolved image ID.
    pub image_id: Option<String>,
    /// `config.v2.json` `"Config"."Cmd"`, kept verbatim as the JSON array read (not re-quoted or
    /// shell-joined, so no shell-escaping guess is smuggled in).
    pub command_raw: Option<String>,
    /// `config.v2.json` `"Config"."Entrypoint"`, same treatment as `command_raw`.
    pub entrypoint_raw: Option<String>,
    /// `hostconfig.json` `"Binds"` (`host:container[:mode]` strings), verbatim.
    pub mounts_raw: Vec<String>,
    pub has_config_v2: bool,
    pub has_hostconfig: bool,
}

const CONFIG_KIND: &str = "docker config.v2.json";
const HOSTCONFIG_KIND: &str = "docker hostconfig.json";

/// Parses `config.v2.json`. Every field is read defensively: an unexpected shape for one field
/// (e.g. `Cmd` not an array) is not fatal to the others, it is just left `None` -- this file's
/// shape is Docker's internal, undocumented format and varies across Engine versions.
pub(crate) fn parse_config_v2(bytes: &[u8]) -> ForensicResult<DockerContainerIdentity> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| ForensicError::invalid_format(CONFIG_KIND, format!("invalid JSON: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| ForensicError::invalid_format(CONFIG_KIND, "top-level value is not a JSON object"))?;

    let id = obj.get("ID").and_then(|v| v.as_str()).map(str::to_string);
    let name = obj
        .get("Name")
        .and_then(|v| v.as_str())
        .map(|n| n.strip_prefix('/').unwrap_or(n).to_string());
    let image_id = obj.get("Image").and_then(|v| v.as_str()).map(str::to_string);
    let config = obj.get("Config").and_then(|v| v.as_object());
    let image = config
        .and_then(|c| c.get("Image"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let command_raw = config
        .and_then(|c| c.get("Cmd"))
        .filter(|v| v.is_array())
        .map(|v| v.to_string());
    let entrypoint_raw = config
        .and_then(|c| c.get("Entrypoint"))
        .filter(|v| v.is_array())
        .map(|v| v.to_string());

    Ok(DockerContainerIdentity {
        id,
        name,
        image,
        image_id,
        command_raw,
        entrypoint_raw,
        mounts_raw: Vec::new(),
        has_config_v2: true,
        has_hostconfig: false,
    })
}

/// Adds `hostconfig.json`'s mount list onto an identity already built from `config.v2.json`
/// (or a default one, if `config.v2.json` was absent or unreadable).
pub(crate) fn merge_hostconfig(
    identity: &mut DockerContainerIdentity,
    bytes: &[u8],
) -> ForensicResult<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| ForensicError::invalid_format(HOSTCONFIG_KIND, format!("invalid JSON: {e}")))?;
    let obj = value.as_object().ok_or_else(|| {
        ForensicError::invalid_format(HOSTCONFIG_KIND, "top-level value is not a JSON object")
    })?;
    if let Some(binds) = obj.get("Binds").and_then(|v| v.as_array()) {
        identity.mounts_raw = binds
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::to_string)
            .collect();
    }
    identity.has_hostconfig = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_line() {
        let line = br#"{"log":"hello world\n","stream":"stdout","time":"2023-11-15T12:34:56.000000000Z"}"#;
        let record = parse_line(line).unwrap();
        assert_eq!(record.message, "hello world\n");
        assert_eq!(record.stream, "stdout");
        assert!(record.timestamp.is_some());
        assert!(is_final_fragment(&record.message));
    }

    #[test]
    fn a_fragment_without_a_trailing_newline_is_not_final() {
        let line = br#"{"log":"partial chunk one","stream":"stdout","time":"2023-11-15T12:34:56.000000000Z"}"#;
        let record = parse_line(line).unwrap();
        assert!(!is_final_fragment(&record.message));
    }

    #[test]
    fn malformed_json_is_one_err_not_a_panic() {
        assert!(parse_line(b"not json at all").is_err());
        assert!(parse_line(b"{\"log\": \"unterminated").is_err());
        assert!(parse_line(b"[]").is_err(), "a JSON array is not an object");
    }

    #[test]
    fn a_missing_required_field_is_an_error() {
        assert!(parse_line(br#"{"stream":"stdout","time":"2023-11-15T12:34:56Z"}"#).is_err());
        assert!(parse_line(br#"{"log":"x","time":"2023-11-15T12:34:56Z"}"#).is_err());
        assert!(parse_line(br#"{"log":"x","stream":"stdout"}"#).is_err());
    }

    #[test]
    fn an_unparseable_time_is_kept_raw_with_no_derived_timestamp() {
        let line = br#"{"log":"x\n","stream":"stdout","time":"not-a-time"}"#;
        let record = parse_line(line).unwrap();
        assert_eq!(record.time_raw, "not-a-time");
        assert!(record.timestamp.is_none());
    }

    #[test]
    fn config_v2_extracts_identity_and_strips_the_leading_slash_from_name() {
        let bytes = br#"{
            "ID": "abc123",
            "Name": "/my-container",
            "Image": "sha256:deadbeef",
            "Config": {
                "Image": "nginx:latest",
                "Cmd": ["nginx", "-g", "daemon off;"],
                "Entrypoint": ["/docker-entrypoint.sh"]
            }
        }"#;
        let identity = parse_config_v2(bytes).unwrap();
        assert_eq!(identity.id.as_deref(), Some("abc123"));
        assert_eq!(identity.name.as_deref(), Some("my-container"));
        assert_eq!(identity.image.as_deref(), Some("nginx:latest"));
        assert_eq!(identity.image_id.as_deref(), Some("sha256:deadbeef"));
        assert_eq!(
            identity.command_raw.as_deref(),
            Some(r#"["nginx","-g","daemon off;"]"#)
        );
        assert!(identity.has_config_v2);
        assert!(!identity.has_hostconfig);
    }

    #[test]
    fn a_missing_config_field_is_none_not_a_guess() {
        let identity = parse_config_v2(br#"{"ID": "abc123"}"#).unwrap();
        assert_eq!(identity.id.as_deref(), Some("abc123"));
        assert_eq!(identity.name, None);
        assert_eq!(identity.image, None);
        assert_eq!(identity.command_raw, None);
    }

    #[test]
    fn hostconfig_adds_the_bind_mounts() {
        let mut identity = DockerContainerIdentity::default();
        let bytes = br#"{"Binds": ["/host/path:/container/path:ro"]}"#;
        merge_hostconfig(&mut identity, bytes).unwrap();
        assert_eq!(identity.mounts_raw, vec!["/host/path:/container/path:ro"]);
        assert!(identity.has_hostconfig);
    }

    #[test]
    fn malformed_config_json_is_an_error_not_a_panic() {
        assert!(parse_config_v2(b"not json").is_err());
        assert!(parse_config_v2(b"[1,2,3]").is_err());
    }
}
