//! Differential testing: does [`contentauth_c2pa_rs_compat::Reader`] report
//! the same thing as the real [`c2pa::Reader`] for the same file?
//!
//! [`ReadForComparison`] is implemented for both readers, over the slice of
//! fields [`contentauth_c2pa_rs_compat`] currently reproduces (see its own
//! crate docs for what that is and isn't). [`read_and_summarize`] is the
//! "same client code" for either one — it never names which backend it is
//! talking to, only the trait — so `tests/compare_with_c2pa_rs.rs` can call
//! it once per backend on the same path and assert the two [`Summary`]
//! values are equal.
//!
//! [`compare_file`] and [`compare_corpus`] generalize that one-file check
//! to a whole directory tree, for running this at the scale of a real
//! corpus (hundreds or thousands of assets) rather than one fixture — see
//! `examples/compare_corpus.rs` and this crate's README for how to point
//! that at one.

use std::path::{Path, PathBuf};

/// The fields this experiment claims parity on, extracted from either
/// reader into a common, backend-agnostic shape.
///
/// Deliberately not the full `Manifest`/`Reader` surface: just what
/// [`contentauth_c2pa_rs_compat::Reader`] itself reproduces today. Growing
/// that crate's own surface (see its README) is what would grow this
/// struct, not the other way around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// `Reader::validation_state()`, by name (`"Trusted"`/`"Valid"`/
    /// `"Invalid"`) rather than either crate's own enum type, since the two
    /// types are unrelated and this is the only thing that needs comparing.
    pub validation_state: &'static str,

    /// `Reader::active_label()`.
    pub active_label: Option<String>,

    /// The active manifest's `title()`, if any.
    pub title: Option<String>,

    /// The active manifest's `format()`, if any.
    pub format: Option<String>,

    /// The active manifest's `instance_id()`.
    pub instance_id: Option<String>,

    /// The active manifest's `claim_generator()`, if any.
    pub claim_generator: Option<String>,
}

/// Implemented for both the real `c2pa::Reader` and
/// [`contentauth_c2pa_rs_compat::Reader`], so [`read_and_summarize`] can
/// drive either one through identical code.
pub trait ReadForComparison: Sized {
    /// Reads and validates `path`, as a caller using this backend directly
    /// would.
    fn read(path: &Path) -> Result<Self, String>;

    /// Extracts the comparable [`Summary`] of what was read.
    fn summarize(&self) -> Summary;
}

impl ReadForComparison for c2pa::Reader {
    fn read(path: &Path) -> Result<Self, String> {
        // The non-deprecated equivalent of `Reader::from_file` per that
        // method's own doc comment (`from_file` delegates to this same call
        // internally, but is deprecated in favor of naming the `Context`
        // step explicitly).
        c2pa::Reader::default()
            .with_file(path)
            .map_err(|err| err.to_string())
    }

    fn summarize(&self) -> Summary {
        let active = self.active_manifest();
        Summary {
            validation_state: match self.validation_state() {
                c2pa::ValidationState::Trusted => "Trusted",
                c2pa::ValidationState::Valid => "Valid",
                c2pa::ValidationState::Invalid => "Invalid",
            },
            active_label: self.active_label().map(str::to_string),
            title: active.and_then(|m| m.title()).map(str::to_string),
            format: active.and_then(|m| m.format()).map(str::to_string),
            instance_id: active.map(|m| m.instance_id().to_string()),
            claim_generator: active.and_then(|m| m.claim_generator()).map(str::to_string),
        }
    }
}

impl ReadForComparison for contentauth_c2pa_rs_compat::Reader {
    fn read(path: &Path) -> Result<Self, String> {
        contentauth_c2pa_rs_compat::Reader::from_file(path).map_err(|err| err.to_string())
    }

    fn summarize(&self) -> Summary {
        let active = self.active_manifest();
        Summary {
            validation_state: match self.validation_state() {
                contentauth_c2pa_rs_compat::ValidationState::Trusted => "Trusted",
                contentauth_c2pa_rs_compat::ValidationState::Valid => "Valid",
                contentauth_c2pa_rs_compat::ValidationState::Invalid => "Invalid",
                // `#[non_exhaustive]`; no other variant exists today.
                _ => "Invalid",
            },
            active_label: self.active_label().map(str::to_string),
            title: active.and_then(|m| m.title()).map(str::to_string),
            format: active.and_then(|m| m.format()).map(str::to_string),
            instance_id: active.map(|m| m.instance_id().to_string()),
            claim_generator: active.and_then(|m| m.claim_generator()).map(str::to_string),
        }
    }
}

/// Reads and summarizes `path` through backend `R` — the "same client
/// code" for whichever backend the caller names at the type-parameter
/// level, per this crate's whole point.
pub fn read_and_summarize<R: ReadForComparison>(path: &Path) -> Result<Summary, String> {
    Ok(R::read(path)?.summarize())
}

/// The outcome of comparing one file's [`Summary`] through both backends,
/// kept only when they disagree.
#[derive(Debug)]
pub struct Mismatch {
    /// The file that produced differing results.
    pub path: PathBuf,

    /// What reading it through real c2pa-rs produced.
    pub c2pa_rs: Result<Summary, String>,

    /// What reading it through the compat reader produced.
    pub compat: Result<Summary, String>,
}

/// Compares one file through both backends, returning `Some` only if they
/// disagree — including one succeeding while the other fails.
pub fn compare_file(path: &Path) -> Option<Mismatch> {
    let c2pa_rs = read_and_summarize::<c2pa::Reader>(path);
    let compat = read_and_summarize::<contentauth_c2pa_rs_compat::Reader>(path);

    if c2pa_rs == compat {
        None
    } else {
        Some(Mismatch {
            path: path.to_path_buf(),
            c2pa_rs,
            compat,
        })
    }
}

/// Walks `dir` recursively, comparing every regular file it finds through
/// both backends. Returns the number of files compared and every
/// disagreement found.
///
/// This is the seam for running this comparison at the scale of a real
/// corpus rather than one fixture: point `dir` at any directory of C2PA
/// test assets (a checkout of a public conformance corpus, or a directory
/// of production files) and every one of them is compared the same way, in
/// one pass. Nothing about it assumes anything C2PA-specific about a given
/// file — a non-asset or a file with no manifest just becomes a `compare_file`
/// call whose two `Err`s (most likely) still agree, which is not a
/// mismatch: c2pa-rs and this crate returning the same *kind* of "not a
/// C2PA asset" answer is itself part of what's being demonstrated.
pub fn compare_corpus(dir: &Path) -> (usize, Vec<Mismatch>) {
    let mut total = 0;
    let mut mismatches = Vec::new();
    let mut pending = vec![dir.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.is_file() {
                total += 1;
                if let Some(mismatch) = compare_file(&path) {
                    mismatches.push(mismatch);
                }
            }
        }
    }

    (total, mismatches)
}
