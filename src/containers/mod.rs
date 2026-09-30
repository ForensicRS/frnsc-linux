//! Container log parsers: Docker's `json-file` driver, containerd/CRI's pods-directory logs,
//! and the Kubernetes `/var/log/containers` symlinks between them.
//!
//! Kept as its own module rather than folded into a text-log parser: container logs have their
//! own reassembly rule (a line can be split across records) and their own identity problem (a
//! path or a sidecar JSON file, not the line text, is what says which container/pod/image a
//! line came from). See [`docker`], [`cri`], [`kubernetes`], [`reassembly`] and [`time`] for the
//! pieces; this module wires them into one [`ArtifactParserFactory`].
//!
//! # One parser id, not three
//!
//! [`ContainersParserFactory`] is registered once, as `linux.containers`, covering all three
//! formats rather than splitting into `linux.containers.docker` / `.cri` / `.kubernetes`. The
//! three formats answer the same forensic question -- what did this container emit, and which
//! container/pod/image was it -- and identity correlation between the Kubernetes symlink names
//! (which carry a container ID) and the pods-directory paths (which don't) only works if both
//! are visible to the same run. A `linux.containers.runtime` field (`"docker"` | `"cri"`) on
//! every emitted event keeps the formats distinguishable to a query.
//!
//! # Symlink duplication
//!
//! forensic-rs's [`FileSystem`](forensic_rs::traits::vfs::FileSystem) has no way to read a
//! symlink's target (see `core/fs/walk.rs`'s `follow_symlinks` doc comment) and a collector may
//! have already dereferenced the symlink into a plain-file byte copy, so a target-string
//! comparison wouldn't cover every case anyway. Instead, every `/var/log/pods/.../*.log` file's
//! content is fingerprinted (length + SHA-256) as it's read, and each
//! `/var/log/containers/*.log` entry is compared against the fingerprints recorded for the same
//! `(namespace, pod, container)` triple (parsed from its own file name). A byte-identical match
//! is reported as one duplication note and its events are not re-emitted; anything else -- a
//! dangling symlink, or content that doesn't match any pods-directory file -- is parsed and
//! emitted on its own, since in that case it may be the only copy of that container's log.

mod cri;
mod docker;
mod kubernetes;
mod reassembly;
mod time;

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::core::path::{FPath, FPathBuf};
use forensic_rs::prelude::*;

use reassembly::StreamBuffer;

/// Registration id of [`ContainersParserFactory`].
pub const PARSER_ID: &str = "linux.containers";

pub const DOCKER_CONFIG_DEFINITION: &str = "DockerContainerConfig";
/// Local addition to the vendored KB (`crates/artifacts/artifacts/data/docker.yaml`): upstream
/// ForensicArtifacts has no definition for `hostconfig.json`, only `config.v2.json`/`config.json`
/// (`DockerContainerConfig`). See that file's `# --- Local additions ---` section.
pub const DOCKER_HOSTCONFIG_DEFINITION: &str = "DockerContainerHostConfig";
pub const DOCKER_LOG_DEFINITION: &str = "GKEDockerContainerLogs";
/// Local addition to the vendored KB (`crates/artifacts/artifacts/data/kubernetes.yaml`):
/// upstream has `KubernetesKubeletPodLogs` for `/var/log/pods/...` but nothing for the
/// `/var/log/containers/*.log` symlinks kubelet maintains alongside them.
pub const KUBERNETES_SYMLINK_DEFINITION: &str = "KubernetesContainerLogSymlinks";
pub const CRI_LOG_DEFINITION: &str = "KubernetesKubeletPodLogs";

/// The ForensicArtifacts definitions this parser reads, in the order the descriptor lists them
/// (sorted by name; resolution and emission order are independently deterministic via the
/// `BTreeMap`/`BTreeSet` structures `open()` builds, not this order).
pub const DEFINITIONS: &[&str] = &[
    DOCKER_CONFIG_DEFINITION,
    DOCKER_HOSTCONFIG_DEFINITION,
    DOCKER_LOG_DEFINITION,
    KUBERNETES_SYMLINK_DEFINITION,
    CRI_LOG_DEFINITION,
];

/// Crate-local `linux.containers.*` field names. These mirror the shape of the ECS `container.*`
/// and `orchestrator.*` namespaces, but are not (yet) `forensic_rs::dictionary` constants -- that
/// crate is shared across every parser crate in the workspace and adding to it needs the
/// ForensicRS Lead's sign-off, which is out of scope for this change. Named identically to what
/// their ECS promotion would look like so a future migration is a rename, not a reshape.
mod field {
    pub const RUNTIME: &str = "linux.containers.runtime";
    pub const STREAM: &str = "linux.containers.stream";
    pub const MESSAGE: &str = "linux.containers.message";
    /// Hex of the reassembled line's raw bytes. CRI only: Docker's `"log"` field is already
    /// JSON-decoded, valid-UTF-8 text by the time it reaches this parser (Docker itself replaces
    /// invalid bytes before writing the JSON), so there is nothing non-UTF-8 to preserve there.
    pub const MESSAGE_RAW: &str = "linux.containers.message_raw";
    pub const TIME_RAW: &str = "linux.containers.time_raw";
    pub const REASSEMBLED: &str = "linux.containers.reassembled";
    pub const FRAGMENT_COUNT: &str = "linux.containers.fragment_count";
    pub const TRUNCATED: &str = "linux.containers.truncated";
    /// CRI rotation index (`N` from `N.log`), when this event's file has one.
    pub const LOG_INDEX: &str = "linux.containers.log_index";

    pub const CONTAINER_ID: &str = "linux.containers.container.id";
    pub const CONTAINER_ID_SOURCE: &str = "linux.containers.container.id_source";
    pub const CONTAINER_NAME: &str = "linux.containers.container.name";
    pub const CONTAINER_NAME_SOURCE: &str = "linux.containers.container.name_source";
    pub const IMAGE: &str = "linux.containers.image";
    pub const IMAGE_ID: &str = "linux.containers.image_id";
    pub const COMMAND_RAW: &str = "linux.containers.command_raw";
    pub const ENTRYPOINT_RAW: &str = "linux.containers.entrypoint_raw";
    pub const MOUNTS_RAW: &str = "linux.containers.mounts_raw";
    pub const HOSTCONFIG_PATH: &str = "linux.containers.hostconfig_path";

    pub const NAMESPACE: &str = "linux.containers.orchestrator.namespace";
    pub const NAMESPACE_SOURCE: &str = "linux.containers.orchestrator.namespace_source";
    pub const POD_NAME: &str = "linux.containers.orchestrator.pod";
    pub const POD_NAME_SOURCE: &str = "linux.containers.orchestrator.pod_source";
    pub const POD_UID: &str = "linux.containers.orchestrator.pod_uid";
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_DIGITS[(b >> 4) as usize] as char);
        s.push(HEX_DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

/// Splits `bytes` on `\n`, dropping exactly one trailing empty element (the artifact of a file
/// that ends with a newline, not a real blank final line). Any *other* empty element -- a stray
/// `\n\n` in the middle of a file -- is kept and reaches the caller's line parser, which rejects
/// it as malformed rather than this function silently swallowing it.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines
}

/// Length + SHA-256 of `bytes`, used only to tell whether two files' content is identical (see
/// the module docs on symlink duplication). Not a security use of the hash.
fn content_fingerprint(bytes: &[u8]) -> (usize, [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    (bytes.len(), hasher.finalize().into())
}

/// Reads the whole file at `path`. Every failure carries the path, so an `Err` item names the
/// file it came from.
fn read_file(fs: &dyn FileSystem, path: &FPath) -> ForensicResult<Vec<u8>> {
    let mut file = fs
        .open(path)
        .map_err(|e| e.with_path(FPathBuf::from(path.as_str())))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| ForensicError::io_error_with_source(e, format!("{PARSER_ID}: reading {path}")))?;
    Ok(bytes)
}

/// Identity fields for one emitted event, each paired with where it came from (a path is a
/// weaker claim than a sidecar config file or a kubelet-maintained symlink name -- see the
/// module docs).
#[derive(Debug, Default, Clone)]
struct LineIdentity {
    container_id: Option<String>,
    container_id_source: Option<&'static str>,
    container_name: Option<String>,
    container_name_source: Option<&'static str>,
    image: Option<String>,
    namespace: Option<String>,
    namespace_source: Option<&'static str>,
    pod: Option<String>,
    pod_source: Option<&'static str>,
    pod_uid: Option<String>,
}

impl LineIdentity {
    fn apply(&self, data: &mut ForensicData) {
        if let Some(v) = &self.container_id {
            data.set(field::CONTAINER_ID, v.clone());
        }
        if let Some(v) = self.container_id_source {
            data.set(field::CONTAINER_ID_SOURCE, v);
        }
        if let Some(v) = &self.container_name {
            data.set(field::CONTAINER_NAME, v.clone());
        }
        if let Some(v) = self.container_name_source {
            data.set(field::CONTAINER_NAME_SOURCE, v);
        }
        if let Some(v) = &self.image {
            data.set(field::IMAGE, v.clone());
        }
        if let Some(v) = &self.namespace {
            data.set(field::NAMESPACE, v.clone());
        }
        if let Some(v) = self.namespace_source {
            data.set(field::NAMESPACE_SOURCE, v);
        }
        if let Some(v) = &self.pod {
            data.set(field::POD_NAME, v.clone());
        }
        if let Some(v) = self.pod_source {
            data.set(field::POD_NAME_SOURCE, v);
        }
        if let Some(v) = &self.pod_uid {
            data.set(field::POD_UID, v.clone());
        }
    }
}

/// Per-run state shared by every file-processing helper below, bundled so they don't each carry
/// four separate parameters.
struct RunCtx<'a> {
    host: &'a str,
    fs: &'a dyn FileSystem,
    acquisition: Acquisition,
    cancellation: &'a CancellationToken,
}

/// `(namespace, pod, container)`: the identity triple a `/var/log/pods/...` path and a
/// `/var/log/containers/*.log` symlink name both resolve to, used to correlate the two.
type PodContainerKey = (String, String, String);
/// Length + SHA-256 of a file's content, from [`content_fingerprint`].
type ContentFingerprint = (usize, [u8; 32]);
/// Every pods-directory file recorded for a given [`PodContainerKey`], for the Kubernetes
/// symlink pass to compare its own content against.
type DedupIndex = BTreeMap<PodContainerKey, Vec<(FPathBuf, ContentFingerprint)>>;
/// Container IDs a `/var/log/containers/*.log` symlink name carries for a given
/// [`PodContainerKey`] (usually zero or one; more than one means an ambiguous match that is
/// deliberately not used to enrich identity -- see [`process_cri_log_file`]).
type SymlinkIndex = BTreeMap<PodContainerKey, Vec<String>>;

/// Everything about a record's own location and lineage, bundled to keep the emit helpers'
/// argument lists manageable.
struct EmitCtx<'a> {
    host: &'a str,
    path: &'a FPath,
    definition: &'static str,
    source: &'a SourceHandle,
    acquisition: Acquisition,
}

/// Builds one log-event [`ForensicData`] from a completed, reassembled line.
fn line_record(
    ctx: &EmitCtx<'_>,
    runtime: &'static str,
    stream: &str,
    timed: &reassembly::TimedLine,
    message: String,
    message_raw_hex: Option<String>,
    identity: &LineIdentity,
) -> ForensicData {
    let provenance = ctx.source.mint(ctx.acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(
        ctx.host,
        Artifact::Linux(LinuxArtifacts::Log("containers".to_string())),
        provenance,
    );
    data.set(ARTIFACT_PATH, ctx.path.as_str().to_string());
    data.set(ARTIFACT_DEFINITION, ctx.definition);
    data.set(field::RUNTIME, runtime);
    data.set(field::STREAM, stream.to_string());
    data.set(field::MESSAGE, message);
    if let Some(hex) = message_raw_hex {
        data.set(field::MESSAGE_RAW, hex);
    }
    data.set(field::TIME_RAW, timed.time_raw.clone());
    data.set(field::REASSEMBLED, timed.line.reassembled);
    data.set(field::FRAGMENT_COUNT, timed.line.fragment_count as u64);
    data.set(field::TRUNCATED, timed.line.truncated);
    if let Some(ts) = timed.timestamp {
        data.set(TIMESTAMP, ts);
    }
    identity.apply(&mut data);
    data
}

fn decode_lossy(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

#[derive(Default)]
struct DockerContainerFiles {
    log_files: Vec<(FPathBuf, SourceHandle)>,
    config_file: Option<(FPathBuf, SourceHandle)>,
    hostconfig_file: Option<(FPathBuf, SourceHandle)>,
}

/// Reads `dir`'s `config.v2.json`/`hostconfig.json` (when present), emits one context record
/// (never a log event) carrying whatever identity they had, then parses and emits every log
/// file in the group. Returns `true` when the pipeline asked to stop.
fn process_docker_container(
    run: &RunCtx<'_>,
    dir: &FPath,
    group: DockerContainerFiles,
    out: &mut dyn ParserOutput,
) -> bool {
    let mut identity = docker::DockerContainerIdentity::default();
    let mut config_source_info: Option<(&'static str, FPathBuf, SourceHandle)> = None;
    let mut hostconfig_path_str: Option<String> = None;

    if let Some((path, source)) = &group.config_file {
        match read_file(run.fs, path.as_path()) {
            Ok(bytes) => match docker::parse_config_v2(&bytes) {
                Ok(parsed) => {
                    identity = parsed;
                    config_source_info = Some((DOCKER_CONFIG_DEFINITION, path.clone(), source.clone()));
                }
                Err(e) => {
                    if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                        return true;
                    }
                }
            },
            Err(e) => {
                if out.emit(Err(e)).is_stop() {
                    return true;
                }
            }
        }
    }
    if let Some((path, source)) = &group.hostconfig_file {
        match read_file(run.fs, path.as_path()) {
            Ok(bytes) => match docker::merge_hostconfig(&mut identity, &bytes) {
                Ok(()) => {
                    hostconfig_path_str = Some(path.as_str().to_string());
                    if config_source_info.is_none() {
                        config_source_info = Some((DOCKER_HOSTCONFIG_DEFINITION, path.clone(), source.clone()));
                    }
                }
                Err(e) => {
                    if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                        return true;
                    }
                }
            },
            Err(e) => {
                if out.emit(Err(e)).is_stop() {
                    return true;
                }
            }
        }
    }

    let path_derived_id = dir.file_name().map(str::to_string);
    let mut line_identity = LineIdentity::default();
    if let Some(id) = identity.id.clone().or_else(|| path_derived_id.clone()) {
        line_identity.container_id_source = Some(if identity.id.is_some() { "config.v2.json" } else { "path" });
        line_identity.container_id = Some(id);
    }
    if let Some(name) = identity.name.clone() {
        line_identity.container_name = Some(name);
        line_identity.container_name_source = Some("config.v2.json");
    }
    line_identity.image = identity.image.clone();

    if let Some((definition, path, source)) = config_source_info {
        let provenance = source.mint(run.acquisition, Recovery::Allocated);
        let mut data = ForensicData::new(
            run.host,
            Artifact::Linux(LinuxArtifacts::Other("container-config".to_string())),
            provenance,
        );
        data.set(ARTIFACT_PATH, path.as_str().to_string());
        data.set(ARTIFACT_DEFINITION, definition);
        if let Some(hc) = &hostconfig_path_str {
            data.set(field::HOSTCONFIG_PATH, hc.clone());
        }
        if let Some(v) = &identity.image_id {
            data.set(field::IMAGE_ID, v.clone());
        }
        if let Some(v) = &identity.command_raw {
            data.set(field::COMMAND_RAW, v.clone());
        }
        if let Some(v) = &identity.entrypoint_raw {
            data.set(field::ENTRYPOINT_RAW, v.clone());
        }
        if !identity.mounts_raw.is_empty() {
            data.set(field::MOUNTS_RAW, identity.mounts_raw.join(";"));
        }
        line_identity.apply(&mut data);
        if out.emit(Ok(data)).is_stop() {
            return true;
        }
    }

    for (path, source) in &group.log_files {
        if run.cancellation.is_cancelled() {
            return true;
        }
        let bytes = match read_file(run.fs, path.as_path()) {
            Ok(b) => b,
            Err(e) => {
                if out.emit(Err(e)).is_stop() {
                    return true;
                }
                continue;
            }
        };
        let ctx = EmitCtx {
            host: run.host,
            path: path.as_path(),
            definition: DOCKER_LOG_DEFINITION,
            source,
            acquisition: run.acquisition,
        };
        let mut streams: BTreeMap<String, StreamBuffer> = BTreeMap::new();
        for raw_line in split_lines(&bytes) {
            if run.cancellation.is_cancelled() {
                return true;
            }
            match docker::parse_line(raw_line) {
                Ok(rec) => {
                    let is_final = docker::is_final_fragment(&rec.message);
                    let stream = rec.stream.clone();
                    let buf = streams.entry(stream.clone()).or_default();
                    if let Some(timed) = buf.push(rec.message.into_bytes(), is_final, &rec.time_raw, rec.timestamp) {
                        let message = decode_lossy(&timed.line.bytes);
                        let data = line_record(&ctx, "docker", &stream, &timed, message, None, &line_identity);
                        if out.emit(Ok(data)).is_stop() {
                            return true;
                        }
                    }
                }
                Err(e) => {
                    if out.emit(Err(e.with_path(path.clone()))).is_stop() {
                        return true;
                    }
                }
            }
        }
        for (stream, mut buf) in streams {
            if let Some(timed) = buf.flush_incomplete() {
                let message = decode_lossy(&timed.line.bytes);
                let data = line_record(&ctx, "docker", &stream, &timed, message, None, &line_identity);
                if out.emit(Ok(data)).is_stop() {
                    return true;
                }
            }
        }
    }
    false
}

/// Reads and parses one `/var/log/pods/.../N.log` file. Records its content fingerprint into
/// `dedup_index` (keyed by namespace/pod/container) for the Kubernetes symlink pass to compare
/// against, and looks up `symlink_index` for a stronger, symlink-name-derived container ID when
/// exactly one candidate exists for this file's namespace/pod/container.
fn process_cri_log_file(
    run: &RunCtx<'_>,
    path: &FPathBuf,
    source: &SourceHandle,
    symlink_index: &SymlinkIndex,
    dedup_index: &mut DedupIndex,
    out: &mut dyn ParserOutput,
) -> bool {
    let path_identity = cri::identity_from_pods_path(path.as_path());

    let bytes = match read_file(run.fs, path.as_path()) {
        Ok(b) => b,
        Err(e) => return out.emit(Err(e)).is_stop(),
    };

    let mut line_identity = LineIdentity::default();
    if let Some(id) = &path_identity {
        let key = (id.namespace.clone(), id.pod.clone(), id.container.clone());
        dedup_index.entry(key.clone()).or_default().push((path.clone(), content_fingerprint(&bytes)));

        line_identity.namespace = Some(id.namespace.clone());
        line_identity.namespace_source = Some("path");
        line_identity.pod = Some(id.pod.clone());
        line_identity.pod_source = Some("path");
        line_identity.pod_uid = Some(id.uid.clone());
        line_identity.container_name = Some(id.container.clone());
        line_identity.container_name_source = Some("path");

        if let Some([only]) = symlink_index.get(&key).map(Vec::as_slice) {
            line_identity.container_id = Some(only.clone());
            line_identity.container_id_source = Some("kubernetes-symlink-name");
        }
    }

    let log_index = path
        .as_path()
        .file_name()
        .and_then(|n| n.strip_suffix(".log"))
        .map(str::to_string);
    let ctx = EmitCtx {
        host: run.host,
        path: path.as_path(),
        definition: CRI_LOG_DEFINITION,
        source,
        acquisition: run.acquisition,
    };

    emit_cri_lines(&ctx, &bytes, run.cancellation, log_index.as_deref(), &line_identity, out)
}

/// Shared by [`process_cri_log_file`] and the Kubernetes symlink path: both formats are CRI text
/// lines once opened, they just differ in identity and in the artifact-catalog definition
/// attributed to the file.
fn emit_cri_lines(
    ctx: &EmitCtx<'_>,
    bytes: &[u8],
    cancellation: &CancellationToken,
    log_index: Option<&str>,
    line_identity: &LineIdentity,
    out: &mut dyn ParserOutput,
) -> bool {
    let mut streams: BTreeMap<String, StreamBuffer> = BTreeMap::new();
    for raw_line in split_lines(bytes) {
        if cancellation.is_cancelled() {
            return true;
        }
        match cri::parse_line(raw_line) {
            Ok(rec) => {
                let stream = rec.stream.clone();
                let is_final = rec.is_final;
                let buf = streams.entry(stream.clone()).or_default();
                if let Some(timed) = buf.push(rec.message, is_final, &rec.time_raw, rec.timestamp) {
                    if emit_one_cri_line(ctx, &stream, &timed, log_index, line_identity, out) {
                        return true;
                    }
                }
            }
            Err(e) => {
                if out.emit(Err(e.with_path(FPathBuf::from(ctx.path)))).is_stop() {
                    return true;
                }
            }
        }
    }
    for (stream, mut buf) in streams {
        if let Some(timed) = buf.flush_incomplete() {
            if emit_one_cri_line(ctx, &stream, &timed, log_index, line_identity, out) {
                return true;
            }
        }
    }
    false
}

fn emit_one_cri_line(
    ctx: &EmitCtx<'_>,
    stream: &str,
    timed: &reassembly::TimedLine,
    log_index: Option<&str>,
    line_identity: &LineIdentity,
    out: &mut dyn ParserOutput,
) -> bool {
    let message = String::from_utf8_lossy(&timed.line.bytes).into_owned();
    let raw_hex = hex_encode(&timed.line.bytes);
    let mut data = line_record(ctx, "cri", stream, timed, message, Some(raw_hex), line_identity);
    if let Some(idx) = log_index {
        data.set(field::LOG_INDEX, idx.to_string());
    }
    out.emit(Ok(data)).is_stop()
}

/// Parses one `/var/log/containers/*.log` entry: if its content byte-for-byte matches a
/// pods-directory file already recorded for the same namespace/pod/container, reports the
/// duplication and emits nothing further for it. If it can't even be opened (a dangling
/// symlink -- an expected, benign collection artifact) it is silently skipped, not treated as a
/// failure. Otherwise -- no matching pods-directory content was found at all -- its lines are
/// the only copy available and are parsed and emitted using the symlink name's own identity.
fn process_kubernetes_symlink(
    run: &RunCtx<'_>,
    path: &FPathBuf,
    source: &SourceHandle,
    dedup_index: &DedupIndex,
    out: &mut dyn ParserOutput,
) -> bool {
    let Some(file_name) = path.as_path().file_name() else {
        return false;
    };
    let Some(name_identity) = kubernetes::identity_from_symlink_name(file_name) else {
        return false;
    };

    let bytes = match read_file(run.fs, path.as_path()) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let key = (name_identity.namespace.clone(), name_identity.pod.clone(), name_identity.container.clone());
    let fingerprint = content_fingerprint(&bytes);
    if let Some(candidates) = dedup_index.get(&key) {
        if let Some((dup_path, _)) = candidates.iter().find(|(_, fp)| *fp == fingerprint) {
            let note = ForensicError::other(
                "linux.containers",
                format!(
                    "{path} duplicates {dup_path} byte for byte (kubelet symlink content matches \
                     the pods-directory log); not re-emitting its events"
                ),
            )
            .with_path(path.clone());
            return out.emit(Err(note)).is_stop();
        }
    }

    // No image claim is available from a symlink name alone, so `image`/`image_source` are left
    // at their `None` default.
    let line_identity = LineIdentity {
        namespace: Some(name_identity.namespace.clone()),
        namespace_source: Some("kubernetes-symlink-name"),
        pod: Some(name_identity.pod.clone()),
        pod_source: Some("kubernetes-symlink-name"),
        container_name: Some(name_identity.container.clone()),
        container_name_source: Some("kubernetes-symlink-name"),
        container_id: Some(name_identity.container_id.clone()),
        container_id_source: Some("kubernetes-symlink-name"),
        ..LineIdentity::default()
    };

    let ctx = EmitCtx {
        host: run.host,
        path: path.as_path(),
        definition: KUBERNETES_SYMLINK_DEFINITION,
        source,
        acquisition: run.acquisition,
    };
    emit_cri_lines(&ctx, &bytes, run.cancellation, None, &line_identity, out)
}

/// [`ArtifactParserFactory`] for Docker `json-file`, containerd/CRI and the Kubernetes
/// `/var/log/containers` symlinks. See the module docs for why this is one parser id.
pub struct ContainersParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for ContainersParserFactory {
    fn default() -> Self {
        let requirements: Vec<Requirement> = DEFINITIONS.iter().copied().map(Requirement::artifact).collect();
        Self {
            descriptor: ParserDescriptor::new(
                PARSER_ID,
                "Linux/Kubernetes container logs (Docker json-file, containerd/CRI)",
                "Emits one record per reassembled container log line from Docker's json-file \
                 driver and containerd/CRI's pods-directory logs, plus one context record per \
                 Docker container's config.v2.json/hostconfig.json. Detects and reports \
                 /var/log/containers symlink duplication instead of double-emitting.",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![
                Artifact::Linux(LinuxArtifacts::Log("containers".to_string())),
                Artifact::Linux(LinuxArtifacts::Other("container-config".to_string())),
            ])
            .with_requirements(requirements),
        }
    }
}

impl ContainersParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for ContainersParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.vfs().is_some() && ctx.sources().catalog().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx.vfs().cloned().ok_or_else(|| {
            ForensicError::missing_data("FileSystem source required", CompactString::const_new(PARSER_ID))
        })?;
        if ctx.sources().catalog().is_none() {
            return Err(ForensicError::missing_data(
                "ArtifactCatalog required: this parser locates container log/config files by \
                 artifact definition name, never by a local glob list",
                CompactString::const_new(PARSER_ID),
            ));
        }
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let cancellation = ctx.cancellation().clone();

        let mut head: Vec<ForensicResult<ForensicData>> = Vec::new();
        let mut docker_groups: BTreeMap<FPathBuf, DockerContainerFiles> = BTreeMap::new();
        let mut cri_entries: Vec<(FPathBuf, SourceHandle)> = Vec::new();
        let mut symlink_entries: Vec<(FPathBuf, SourceHandle)> = Vec::new();

        for definition in DEFINITIONS.iter().copied() {
            let resolution = match ctx.resolve_artifact(definition) {
                Ok(resolution) => resolution,
                Err(e) => {
                    head.push(Err(e));
                    continue;
                }
            };
            head.extend(resolution.errors.into_iter().map(Err));
            head.extend(resolution.unresolved.into_iter().map(|u| {
                Err(ForensicError::other(
                    "catalog",
                    format!("{definition}: source {:?} was not searched: {}", u.source, u.reason),
                ))
            }));
            for note in &resolution.notes {
                debug!("{PARSER_ID}: {definition}: {note}");
            }
            for file in resolution.files {
                if file.directory {
                    continue;
                }
                let source = ctx.register_source(SourceKey::Path(file.path.as_str().to_string()));
                if definition == DOCKER_CONFIG_DEFINITION {
                    if let Some(dir) = file.path.as_path().parent().map(FPathBuf::from) {
                        docker_groups.entry(dir).or_default().config_file = Some((file.path, source));
                    }
                } else if definition == DOCKER_HOSTCONFIG_DEFINITION {
                    if let Some(dir) = file.path.as_path().parent().map(FPathBuf::from) {
                        docker_groups.entry(dir).or_default().hostconfig_file = Some((file.path, source));
                    }
                } else if definition == DOCKER_LOG_DEFINITION {
                    if let Some(dir) = file.path.as_path().parent().map(FPathBuf::from) {
                        docker_groups.entry(dir).or_default().log_files.push((file.path, source));
                    }
                } else if definition == CRI_LOG_DEFINITION {
                    cri_entries.push((file.path, source));
                } else if definition == KUBERNETES_SYMLINK_DEFINITION {
                    symlink_entries.push((file.path, source));
                }
            }
        }

        Ok(ParserRun::push(move |out| {
            let run = RunCtx { host: host.as_str(), fs: fs.as_ref(), acquisition, cancellation: &cancellation };

            for item in head {
                if out.emit(item).is_stop() {
                    return Ok(());
                }
            }

            let mut symlink_index: SymlinkIndex = BTreeMap::new();
            for (path, _) in &symlink_entries {
                if let Some(file_name) = path.as_path().file_name() {
                    if let Some(id) = kubernetes::identity_from_symlink_name(file_name) {
                        symlink_index
                            .entry((id.namespace.clone(), id.pod.clone(), id.container.clone()))
                            .or_default()
                            .push(id.container_id.clone());
                    }
                }
            }

            for (dir, group) in docker_groups {
                if run.cancellation.is_cancelled() {
                    return Ok(());
                }
                if process_docker_container(&run, dir.as_path(), group, out) {
                    return Ok(());
                }
            }

            let mut dedup_index: DedupIndex = BTreeMap::new();
            for (path, source) in &cri_entries {
                if run.cancellation.is_cancelled() {
                    return Ok(());
                }
                if process_cri_log_file(&run, path, source, &symlink_index, &mut dedup_index, out) {
                    return Ok(());
                }
            }

            for (path, source) in &symlink_entries {
                if run.cancellation.is_cancelled() {
                    return Ok(());
                }
                if process_kubernetes_symlink(&run, path, source, &dedup_index, out) {
                    return Ok(());
                }
            }

            Ok(())
        }))
    }
}

#[cfg(test)]
mod factory_tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use forensic_rs::prelude::testing::{collect_run, InMemoryVirtualFileSystem};

    use super::*;

    /// The real definitions this factory declares, restated as an in-test catalog -- the crate
    /// cannot depend on `frnsc-artifacts` (that would invert the dependency), and a pinned copy
    /// here also fails loudly if a definition's paths change. Mirrors
    /// `unix::utmp::factory_tests::definition`.
    fn definition(name: &'static str, paths: &'static [Text]) -> ArtifactDefinition {
        ArtifactDefinition {
            name: Cow::Borrowed(name),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::File { paths: Cow::Borrowed(paths), separator: Separator::Slash },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Linux]),
            urls: Cow::Borrowed(&[]),
        }
    }

    fn catalog() -> Arc<dyn ArtifactCatalog> {
        let defs = vec![
            definition(DOCKER_CONFIG_DEFINITION, &[Cow::Borrowed("/var/lib/docker/containers/*/config.v2.json")]),
            definition(DOCKER_HOSTCONFIG_DEFINITION, &[Cow::Borrowed("/var/lib/docker/containers/*/hostconfig.json")]),
            definition(DOCKER_LOG_DEFINITION, &[Cow::Borrowed("/var/lib/docker/containers/*/*-json.log*")]),
            definition(KUBERNETES_SYMLINK_DEFINITION, &[Cow::Borrowed("/var/log/containers/*.log")]),
            definition(CRI_LOG_DEFINITION, &[Cow::Borrowed("/var/log/pods/*/*/*.log")]),
        ];
        Arc::new(SliceCatalog::new(defs).unwrap())
    }

    fn sources(vfs: InMemoryVirtualFileSystem, with_catalog: bool) -> TriageSources {
        let mut builder = TriageSources::builder().vfs(Arc::new(vfs)).acquisition(Acquisition::ImageRead);
        if with_catalog {
            builder = builder.catalog(catalog());
        }
        builder.build()
    }

    fn run(sources: &TriageSources) -> Vec<ForensicResult<ForensicData>> {
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(sources, &triage, &cancellation);
        let parser = ContainersParserFactory::new();
        assert!(parser.can_parse(&ctx));
        collect_run(parser.open(&ctx).unwrap()).unwrap()
    }

    fn field<'a>(data: &'a ForensicData, key: &str) -> Option<&'a str> {
        data.field_as_str(key)
    }

    /// A Docker container (`abc123`) whose json-file log line is split three ways, plus its
    /// `config.v2.json`/`hostconfig.json`; a CRI pod (`default/myapp-xyz/myapp`) whose log is
    /// split two ways and has a matching `/var/log/containers` symlink with byte-identical
    /// content (the duplication case); and a second symlink (`other-pod`) with no matching
    /// pods-directory file at all (the "only copy available" case).
    fn base_vfs() -> InMemoryVirtualFileSystem {
        let docker_log = concat!(
            "{\"log\":\"hel\",\"stream\":\"stdout\",\"time\":\"2023-11-15T12:34:56.000000000Z\"}\n",
            "{\"log\":\"lo w\",\"stream\":\"stdout\",\"time\":\"2023-11-15T12:34:56.100000000Z\"}\n",
            "{\"log\":\"orld\\n\",\"stream\":\"stdout\",\"time\":\"2023-11-15T12:34:56.200000000Z\"}\n",
        );
        let config_v2 = r#"{"ID":"abc123","Name":"/my-container","Config":{"Image":"nginx:latest"}}"#;
        let hostconfig = r#"{"Binds":["/host:/container:ro"]}"#;
        let cri_log = "2023-11-15T12:00:00.000000000Z stdout P partial-\n\
                        2023-11-15T12:00:00.100000000Z stdout F line\n";
        let standalone_log = "2023-11-15T13:00:00.000000000Z stdout F standalone\n";

        InMemoryVirtualFileSystem::new()
            .with_file("var/lib/docker/containers/abc123/abc123-json.log", docker_log.as_bytes().to_vec())
            .with_file("var/lib/docker/containers/abc123/config.v2.json", config_v2.as_bytes().to_vec())
            .with_file("var/lib/docker/containers/abc123/hostconfig.json", hostconfig.as_bytes().to_vec())
            .with_file("var/log/pods/default_myapp-xyz_uid1/myapp/0.log", cri_log.as_bytes().to_vec())
            .with_file(
                "var/log/containers/myapp-xyz_default_myapp-deadbeef.log",
                cri_log.as_bytes().to_vec(),
            )
            .with_file(
                "var/log/containers/other-pod_default_othercontainer-cafebabe.log",
                standalone_log.as_bytes().to_vec(),
            )
    }

    #[test]
    fn declares_every_definition_as_a_requirement() {
        let parser = ContainersParserFactory::new();
        let declared: Vec<&str> = parser
            .descriptor()
            .requirements
            .iter()
            .filter_map(|r| match r {
                Requirement::Artifact(a) => Some(a.name.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(declared, DEFINITIONS.to_vec());
    }

    #[test]
    fn without_a_catalog_the_parser_declines_instead_of_guessing_paths() {
        let sources = sources(InMemoryVirtualFileSystem::new(), false);
        let triage = TriageContext::new("TEST-HOST", "default");
        let cancellation = CancellationToken::new();
        let ctx = ParseContext::new(&sources, &triage, &cancellation);
        let parser = ContainersParserFactory::new();
        assert!(!parser.can_parse(&ctx));
        assert!(parser.open(&ctx).is_err());
    }

    #[test]
    fn an_empty_evidence_root_yields_nothing() {
        let items = run(&sources(InMemoryVirtualFileSystem::new(), true));
        assert!(items.is_empty());
    }

    #[test]
    fn docker_json_file_line_split_three_ways_is_reassembled_with_config_derived_identity() {
        let items = run(&sources(base_vfs(), true));
        let errors: Vec<&ForensicError> = items.iter().filter_map(|i| i.as_ref().err()).collect();
        assert!(
            errors.iter().all(|e| !e.to_string().contains("abc123")),
            "no docker-related error expected: {errors:?}"
        );

        let docker_line = items
            .iter()
            .filter_map(|i| i.as_ref().ok())
            .find(|d| field(d, field::RUNTIME) == Some("docker"))
            .expect("one docker log event");
        assert_eq!(field(docker_line, field::MESSAGE), Some("hello world\n"));
        assert_eq!(docker_line.field_as_u64(field::FRAGMENT_COUNT), Some(3));
        assert_eq!(docker_line.field_as_u64(field::REASSEMBLED), Some(1));
        assert_eq!(docker_line.field_as_u64(field::TRUNCATED), Some(0));
        assert_eq!(field(docker_line, field::CONTAINER_ID), Some("abc123"));
        assert_eq!(field(docker_line, field::CONTAINER_ID_SOURCE), Some("config.v2.json"));
        assert_eq!(field(docker_line, field::CONTAINER_NAME), Some("my-container"));
        assert_eq!(field(docker_line, field::IMAGE), Some("nginx:latest"));
        assert!(docker_line.field_as_date(TIMESTAMP).is_some());

        let context = items
            .iter()
            .filter_map(|i| i.as_ref().ok())
            .find(|d| d.artifact() == &Artifact::Linux(LinuxArtifacts::Other("container-config".to_string())))
            .expect("one docker context record");
        assert_eq!(field(context, field::CONTAINER_ID), Some("abc123"));
        assert_eq!(field(context, field::CONTAINER_NAME), Some("my-container"));
        assert_eq!(field(context, field::IMAGE), Some("nginx:latest"));
        assert_eq!(field(context, field::MOUNTS_RAW), Some("/host:/container:ro"));
        assert!(field(context, field::HOSTCONFIG_PATH).unwrap().ends_with("hostconfig.json"));
    }

    #[test]
    fn cri_log_is_enriched_with_the_symlink_derived_container_id_and_the_duplicate_symlink_is_not_double_emitted() {
        let items = run(&sources(base_vfs(), true));

        let cri_lines: Vec<&ForensicData> = items
            .iter()
            .filter_map(|i| i.as_ref().ok())
            .filter(|d| field(d, field::POD_NAME) == Some("myapp-xyz"))
            .collect();
        assert_eq!(cri_lines.len(), 1, "the duplicate symlink copy must not be re-emitted: {cri_lines:?}");
        let line = cri_lines[0];
        assert_eq!(field(line, field::MESSAGE), Some("partial-line"));
        assert_eq!(line.field_as_u64(field::FRAGMENT_COUNT), Some(2));
        assert_eq!(line.field_as_u64(field::REASSEMBLED), Some(1));
        assert_eq!(field(line, field::NAMESPACE), Some("default"));
        assert_eq!(field(line, field::NAMESPACE_SOURCE), Some("path"));
        assert_eq!(field(line, field::POD_UID), Some("uid1"));
        assert_eq!(field(line, field::CONTAINER_NAME), Some("myapp"));
        assert_eq!(
            field(line, field::CONTAINER_ID),
            Some("deadbeef"),
            "the pods-directory path has no container ID of its own; it must come from the symlink name"
        );
        assert_eq!(field(line, field::CONTAINER_ID_SOURCE), Some("kubernetes-symlink-name"));

        let duplicate_note = items
            .iter()
            .filter_map(|i| i.as_ref().err())
            .find(|e| e.to_string().contains("duplicates"))
            .expect("the duplication must be reported, not silently swallowed");
        assert!(duplicate_note.to_string().contains("myapp-xyz_default_myapp-deadbeef.log"));
    }

    #[test]
    fn a_symlink_with_no_matching_pods_file_is_parsed_as_the_only_copy_available() {
        let items = run(&sources(base_vfs(), true));
        let standalone: Vec<&ForensicData> = items
            .iter()
            .filter_map(|i| i.as_ref().ok())
            .filter(|d| field(d, field::CONTAINER_NAME) == Some("othercontainer"))
            .collect();
        assert_eq!(standalone.len(), 1);
        let line = standalone[0];
        assert_eq!(field(line, field::MESSAGE), Some("standalone"));
        assert_eq!(field(line, field::POD_NAME), Some("other-pod"));
        assert_eq!(field(line, field::NAMESPACE), Some("default"));
        assert_eq!(field(line, field::CONTAINER_ID), Some("cafebabe"));
        assert_eq!(field(line, field::NAMESPACE_SOURCE), Some("kubernetes-symlink-name"));
        assert_eq!(field(line, ARTIFACT_DEFINITION), Some(KUBERNETES_SYMLINK_DEFINITION));
    }
}
