//! Exercises `compare_corpus`'s own error handling, as opposed to
//! `tests/compare_with_c2pa_rs.rs`'s single-file backend-agreement check:
//! a directory symlink cycle must not send the walk into an infinite
//! loop, and a path it cannot read must be reported, not silently folded
//! into a clean pass.

use std::path::Path;

use c2pa_rs_compat_conformance::compare_corpus;

#[test]
fn an_unreadable_root_directory_is_reported_rather_than_silently_passed() {
    let missing = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/this-directory-does-not-exist"
    ));

    let report = compare_corpus(missing);

    assert_eq!(report.compared, 0);
    assert!(report.mismatches.is_empty());
    assert_eq!(report.unreadable.len(), 1);
    assert_eq!(report.unreadable[0].0, missing);
    assert!(!report.is_clean());
}

#[cfg(unix)]
#[test]
fn a_directory_symlink_cycle_does_not_loop_forever() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("symlink_cycle");
    std::fs::create_dir_all(&dir).expect("should create the test directory");

    // A symlink whose target is its own parent: walking into it (were it
    // ever followed) would list `dir`'s own entries again — including
    // this same symlink — forever.
    let cycle = dir.join("loop");
    let _ = std::fs::remove_file(&cycle);
    std::os::unix::fs::symlink(&dir, &cycle).expect("should create a directory symlink cycle");

    // Returning at all is the real assertion here; the counts just
    // confirm the cycle contributed nothing rather than something
    // unexpected.
    let report = compare_corpus(&dir);

    assert_eq!(report.compared, 0);
    assert!(report.unreadable.is_empty());
    assert!(report.is_clean());
}
