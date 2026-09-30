//! Integration tests against real-world artifacts from the shared test corpus.
//!
//! Register the samples this crate needs in `forensic-testenv/manifest/artifacts.toml`
//! (with `used_by = ["frnsc-linux"]`), then fetch them with
//! `forensic-testenv/tools/fetch.py --crate frnsc-linux`. Tests skip when a sample has
//! not been fetched, and fail under `FORENSIC_TESTDATA_STRICT=1` (CI).

use frnsc_linux::unix::utmp;

#[test]
fn real_sample_does_not_panic() {
    // Registered by FOR-29 (forensic-testenv Linux fixtures); skips until then.
    let path = forensic_testdata::artifact_or_skip!("frnsc-linux-utmp-sample");
    let data = std::fs::read(path).unwrap();
    // Scanning must never panic, whatever layout or truncation the real sample has.
    let _ = utmp::scan_records(&data);
}
