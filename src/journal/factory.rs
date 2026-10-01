//! `FormatFactory` implementation: sniffs the `LPKSHHRH` signature and mounts a `.journal` file as
//! a [`Mounted::EventLog`]. This lets a `.journal` file be recognized generically wherever
//! [`forensic_rs::core::resolver::MountResolver`] is used (e.g. nested inside a container) — the
//! main pipeline integration for `frnsc-linux` is [`crate::journal::parser::JournalParserFactory`]
//! instead, which locates `.journal` files through the artifact catalog and never goes through
//! `Mounted` at all (see that module's docs).

use std::io::{Read, SeekFrom};
use std::sync::Arc;

use forensic_rs::prelude::*;
use forensic_rs::traits::format::{FormatFactory, MountContext, MountKind, Mounted, ProbeScore};

use crate::journal::header::SIGNATURE;
use crate::journal::reader::JournalEventLogReader;

#[derive(Debug, Default, Clone, Copy)]
pub struct JournalFormatFactory;

impl JournalFormatFactory {
    pub fn new() -> Self {
        Self
    }
}

impl FormatFactory for JournalFormatFactory {
    fn name(&self) -> &'static str {
        "frnsc-linux-journal"
    }

    fn yields(&self) -> MountKind {
        MountKind::EventLog
    }

    fn extensions(&self) -> &[&'static str] {
        &["journal"]
    }

    /// Reads just the 8-byte signature. Per [`FormatFactory::probe`]'s contract, restores the
    /// stream position before returning on every path, including a short/truncated-read return —
    /// a file too short to hold the signature is simply "not this format", not a probe error.
    fn probe(
        &self,
        file: &mut dyn VirtualFile,
        _ctx: &MountContext<'_>,
    ) -> ForensicResult<ProbeScore> {
        let initial_pos = file.stream_position().unwrap_or(0);
        let mut magic = [0u8; 8];
        let read_result = file.read_exact(&mut magic);
        let seek_result = file.seek(SeekFrom::Start(initial_pos)).map_err(|e| {
            ForensicError::io_error_with_source(e, "restoring stream position after probing")
        });
        if read_result.is_err() {
            seek_result.ok();
            return Ok(ProbeScore::No);
        }
        seek_result?;
        if magic == SIGNATURE {
            Ok(ProbeScore::Exact)
        } else {
            Ok(ProbeScore::No)
        }
    }

    /// Reads the whole file and hands it to [`JournalEventLogReader::from_bytes`]. Journal files
    /// are read wholesale rather than streamed (matching `frnsc-winevt`'s `.evtx` mount, and for
    /// the same reason: the indexed/recovery walk in `crate::journal::reader` needs random access
    /// by absolute offset, which a `Read`-only handle cannot give without buffering it anyway).
    fn mount(
        &self,
        mut file: Box<dyn VirtualFile>,
        _ctx: &MountContext<'_>,
    ) -> ForensicResult<Mounted> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| {
            ForensicError::io_error_with_source(e, "reading journal file for mount")
        })?;
        let reader = JournalEventLogReader::from_bytes(bytes)?;
        Ok(Mounted::EventLog(Arc::new(reader)))
    }
}

#[cfg(test)]
mod tests {
    use forensic_rs::core::limits::{Limits, MemorySpillStore};
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    use super::*;

    fn ctx<'a>(
        fs: &'a Arc<dyn FileSystem>,
        locator: &'a EvidenceLocator,
        limits: &'a Limits,
        spill: &'a MemorySpillStore,
        cancellation: &'a forensic_rs::bridge::CancellationToken,
    ) -> MountContext<'a> {
        MountContext::new(fs, locator, limits, 0, spill, None, cancellation)
    }

    #[test]
    fn probe_scores_exact_on_the_real_signature_and_restores_position() {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0u8; 264]);
        let fs: Arc<dyn FileSystem> =
            Arc::new(InMemoryVirtualFileSystem::new().with_file("j", bytes));
        let mut file = fs.open(FPath::new("j")).unwrap();
        let locator = EvidenceLocator::root();
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = JournalFormatFactory::new();
        let pos_before = file.stream_position().unwrap();
        let score = factory.probe(file.as_mut(), &mount_ctx).unwrap();
        assert_eq!(score, ProbeScore::Exact);
        assert_eq!(pos_before, file.stream_position().unwrap());
    }

    #[test]
    fn probe_scores_no_on_the_wrong_magic() {
        let fs: Arc<dyn FileSystem> = Arc::new(
            InMemoryVirtualFileSystem::new().with_file("j", b"not a journal file".to_vec()),
        );
        let mut file = fs.open(FPath::new("j")).unwrap();
        let locator = EvidenceLocator::root();
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = JournalFormatFactory::new();
        let score = factory.probe(file.as_mut(), &mount_ctx).unwrap();
        assert_eq!(score, ProbeScore::No);
    }

    #[test]
    fn probe_scores_no_on_a_file_too_short_for_the_signature_not_an_error() {
        let fs: Arc<dyn FileSystem> =
            Arc::new(InMemoryVirtualFileSystem::new().with_file("j", vec![1, 2, 3]));
        let mut file = fs.open(FPath::new("j")).unwrap();
        let locator = EvidenceLocator::root();
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let mount_ctx = ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = JournalFormatFactory::new();
        let score = factory.probe(file.as_mut(), &mount_ctx).unwrap();
        assert_eq!(score, ProbeScore::No);
    }
}
