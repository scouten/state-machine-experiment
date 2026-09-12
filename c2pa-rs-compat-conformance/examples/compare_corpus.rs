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
//! while the other failed. Exits non-zero if any mismatch was found *or*
//! if any path could not even be read — an unreadable path was never
//! compared, so silently treating that as a pass would misreport how much
//! of the corpus this run actually checked. So it can be dropped straight
//! into a CI job once there is a corpus worth running it against
//! continuously.

use std::{path::Path, process::ExitCode};

use c2pa_rs_compat_conformance::compare_corpus;

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: compare_corpus <directory>");
        return ExitCode::FAILURE;
    };

    let report = compare_corpus(Path::new(&dir));

    println!(
        "{} file(s) compared, {} matched, {} mismatched, {} unreadable",
        report.compared,
        report.compared - report.mismatches.len(),
        report.mismatches.len(),
        report.unreadable.len(),
    );

    for mismatch in &report.mismatches {
        println!("\nMISMATCH: {}", mismatch.path.display());
        println!("  c2pa-rs: {:?}", mismatch.c2pa_rs);
        println!("  compat:  {:?}", mismatch.compat);
    }

    for (path, reason) in &report.unreadable {
        println!("\nUNREADABLE: {} ({reason})", path.display());
    }

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
