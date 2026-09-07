//! Runs the same comparison `tests/compare_with_c2pa_rs.rs` does for one
//! file, over every file in a directory tree — the shape a real,
//! hundreds-or-thousands-of-assets conformance run would take.
//!
//! ```sh
//! cargo run --release --example compare_corpus -- /path/to/a/corpus
//! ```
//!
//! Point it at a directory of C2PA-signed assets — a checkout of a public
//! conformance corpus (for instance c2pa-org's `public-testfiles`
//! repository), or any local collection — and it reports how many files
//! were compared and lists every one where real c2pa-rs and
//! [`contentauth_c2pa_rs_compat`] disagreed, including one succeeding
//! while the other failed. Exits non-zero if any mismatch was found, so it
//! can be dropped straight into a CI job once there is a corpus worth
//! running it against continuously.

use std::{path::Path, process::ExitCode};

use c2pa_rs_compat_conformance::compare_corpus;

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: compare_corpus <directory>");
        return ExitCode::FAILURE;
    };

    let (total, mismatches) = compare_corpus(Path::new(&dir));

    println!(
        "{total} file(s) compared, {} matched, {} mismatched",
        total - mismatches.len(),
        mismatches.len()
    );

    for mismatch in &mismatches {
        println!("\nMISMATCH: {}", mismatch.path.display());
        println!("  c2pa-rs: {:?}", mismatch.c2pa_rs);
        println!("  compat:  {:?}", mismatch.compat);
    }

    if mismatches.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
