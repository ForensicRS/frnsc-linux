//! `/var/log/containers/*.log`: kubelet's symlinks into
//! `/var/log/pods/<namespace>_<pod>_<uid>/<container>/N.log`, named
//! `<pod>_<namespace>_<container>-<containerID>.log` -- note the reversed `pod`/`namespace`
//! order compared to the pods directory, and the container ID that only this name carries.
//!
//! forensic-rs's [`FileSystem`](forensic_rs::traits::vfs::FileSystem) trait has no way to read a
//! symlink's target today (a documented gap, see `core/fs/walk.rs`), so a dangling-vs-duplicated
//! symlink can't be told apart by resolving it. Byte-for-byte content comparison against the
//! pods-directory files (done by the caller in `containers/mod.rs`) is the fallback that works
//! regardless of whether the collector preserved a real symlink, left a dangling one, or
//! followed it and copied the target's bytes into a plain file.

/// Identity parsed from a `/var/log/containers/*.log` file name alone -- the container ID this
/// carries has no equivalent in the pods-directory path layout, so it is strictly additional
/// information, not a replacement for [`super::cri::PodPathIdentity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SymlinkNameIdentity {
    pub pod: String,
    pub namespace: String,
    pub container: String,
    pub container_id: String,
}

/// Parses `<pod>_<namespace>_<container>-<containerID>.log`. `None` when the name doesn't have
/// the `.log` suffix, has no `-` to split the container name from the ID, the trailing segment
/// isn't a plausible hex container ID, or the remainder doesn't split into exactly three
/// `_`-separated parts. Kubernetes pod/namespace/container names are DNS-1123 labels and never
/// contain `_`, and a real container ID never contains `-`, so both splits are unambiguous when
/// the name really is kubelet's convention.
pub(crate) fn identity_from_symlink_name(file_name: &str) -> Option<SymlinkNameIdentity> {
    let stem = file_name.strip_suffix(".log")?;
    let dash = stem.rfind('-')?;
    let container_id = &stem[dash + 1..];
    if container_id.is_empty() || !container_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let prefix = &stem[..dash];
    let mut parts = prefix.splitn(3, '_');
    let pod = parts.next()?;
    let namespace = parts.next()?;
    let container = parts.next()?;
    if pod.is_empty() || namespace.is_empty() || container.is_empty() {
        return None;
    }
    Some(SymlinkNameIdentity {
        pod: pod.to_string(),
        namespace: namespace.to_string(),
        container: container.to_string(),
        container_id: container_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_symlink_name() {
        let identity = identity_from_symlink_name(
            "coredns-6d4b75cb6d-abcde_kube-system_coredns-a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90.log",
        )
        .unwrap();
        assert_eq!(identity.pod, "coredns-6d4b75cb6d-abcde");
        assert_eq!(identity.namespace, "kube-system");
        assert_eq!(identity.container, "coredns");
        assert_eq!(
            identity.container_id,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        );
    }

    #[test]
    fn hyphens_in_the_pod_name_do_not_confuse_the_split() {
        let identity =
            identity_from_symlink_name("my-app-7f8d9-xyz12_default_my-app-deadbeef.log").unwrap();
        assert_eq!(identity.pod, "my-app-7f8d9-xyz12");
        assert_eq!(identity.namespace, "default");
        assert_eq!(identity.container, "my-app");
        assert_eq!(identity.container_id, "deadbeef");
    }

    #[test]
    fn missing_log_suffix_yields_no_identity() {
        assert!(identity_from_symlink_name("pod_ns_container-deadbeef").is_none());
    }

    #[test]
    fn a_non_hex_trailing_segment_yields_no_identity() {
        assert!(identity_from_symlink_name("pod_ns_container-not-hex-at-all.log").is_none());
    }

    #[test]
    fn missing_underscore_separators_yields_no_identity() {
        assert!(identity_from_symlink_name("justoneword-deadbeef.log").is_none());
    }

    #[test]
    fn an_empty_container_id_yields_no_identity() {
        assert!(identity_from_symlink_name("pod_ns_container-.log").is_none());
    }
}
