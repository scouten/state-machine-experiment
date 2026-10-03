// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Builds and signs a C2PA manifest store for any container format with a
//! [`contentauth_c2pa_format::FormatHandler`] — the write-side counterpart
//! to [`contentauth_c2pa_file_reader`](https://docs.rs/contentauth-c2pa-file-reader).
//!
//! # The gap this fills
//!
//! [`contentauth_c2pa_builder::BuilderSession`] never touches a container
//! format: it asks its host to embed a placeholder manifest and report
//! where it landed ([`BuilderRequest::ReservePlaceholder`]), then to
//! commit the final one over the same range
//! ([`BuilderRequest::CommitManifest`]). A [`FormatHandler`] answers
//! exactly those questions through [`FormatHandler::plan_embed`] and
//! [`FormatHandler::commit`] — but nothing in `contentauth-c2pa-format` or
//! `contentauth-c2pa-builder` connects the two, by the same design that
//! kept the reader and its format handlers apart.
//!
//! # Two ways to use this crate
//!
//! [`FileBuilderSession`] is the primary interface: it composes a
//! handler's `plan_embed`/`commit` with a [`BuilderSession`], and speaks a
//! small request vocabulary, [`FileBuilderRequest`], to whatever host
//! drives it. It never buffers the source or output asset itself: an
//! [`EmbedPlan`](contentauth_c2pa_format::EmbedPlan)'s edits are walked
//! one at a time, each becoming a [`FileBuilderRequest::Read`] against
//! [`FileBuilderSession::SOURCE_STREAM`] or a
//! [`FileBuilderRequest::Write`] against
//! [`FileBuilderSession::OUTPUT_STREAM`] — and `AssetLength`/`AssetBytes`,
//! needed to hash the output for the hard binding, are forwarded as plain
//! reads of the output stream once it has been written. Only
//! [`FileBuilderRequest::Sign`] and [`FileBuilderRequest::Timestamp`] ever
//! reach the host as themselves: a signing key and an RFC 3161 authority
//! round trip are not things this crate, or any format handler, can stand
//! in for.
//!
//! [`build_and_sign`] and [`build_and_sign_file`] are a host for exactly
//! that session, for the common case: a caller with plain, synchronous
//! `Read + Seek` access to the source asset, `Read + Write + Seek` access
//! to write the output (read-back is needed for the hashing above), and a
//! plain signing function, and optionally a function that answers each
//! RFC 3161 timestamp request (without one, a request fails the build).
//! Reach for [`FileBuilderSession`] directly once any of
//! that stops being true — async or network-backed asset access, say.
//!
//! [`build_and_sign_file`] additionally never leaves a partial or corrupt
//! file at the requested output path: it builds into a freshly, exclusively
//! created temporary file beside it — a predictable name here would let
//! another process redirect the write by pre-creating that path as a
//! symlink — and renames it into place only once the build succeeds,
//! deleting the temporary file on any failure, rename included, instead.
//!
//! # What this does not do
//!
//! It builds one manifest into one asset — no ingredients, no update
//! manifests, no `ExistingManifest` policy for an asset that already
//! carries a store (`plan_embed` always replaces it; see
//! `contentauth-c2pa-builder`'s own README for what it builds). A host
//! that needs any of that wants the two-stream (source/output) model a
//! future orchestrator crate is expected to provide.
//!
//! [`BuilderSession`]: contentauth_c2pa_builder::BuilderSession
//! [`BuilderRequest::ReservePlaceholder`]: contentauth_c2pa_builder::BuilderRequest::ReservePlaceholder
//! [`BuilderRequest::CommitManifest`]: contentauth_c2pa_builder::BuilderRequest::CommitManifest
//! [`FormatHandler`]: contentauth_c2pa_format::FormatHandler
//! [`FormatHandler::plan_embed`]: contentauth_c2pa_format::FormatHandler::plan_embed
//! [`FormatHandler::commit`]: contentauth_c2pa_format::FormatHandler::commit

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod drive;
mod error;
mod session;

use std::{
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub use contentauth_c2pa_builder::{
    Assertion, AssertionKind, BuilderSettings, GeneratorInfo, HashAlgorithm, SigningAlg,
    TimestampSettings,
};
pub use contentauth_c2pa_format::FormatHandler;
pub use contentauth_c2pa_primitives::HostError;
pub use error::Error;
pub use session::{FileBuilderReply, FileBuilderReport, FileBuilderRequest, FileBuilderSession};

/// A function answering one RFC 3161 timestamp request, as
/// [`build_and_sign`] takes: the digest and the algorithm it was computed
/// with in, the bare `TimeStampToken` out.
pub type TimestampFn<'a> = dyn FnMut(HashAlgorithm, &[u8]) -> Result<Vec<u8>, HostError> + 'a;

/// Builds and signs a C2PA manifest store for `source`, per `settings`,
/// writing the result to `output` and calling `sign` whenever the claim
/// signature needs signing.
///
/// A synchronous host for [`FileBuilderSession`]: `handler` plans and
/// commits the embedding within `source`'s container format, `source` and
/// `output` answer every `Read`/`Length`/`Write` this session issues
/// (`output` must also support reading back what has been written to it,
/// since this session hashes the asset it assembles rather than buffering
/// it), and `sign` answers every [`FileBuilderRequest::Sign`] the build
/// issues — mirroring [`contentauth_c2pa_builder::BuilderRequest::Sign`]:
/// sign the exact bytes handed to it with the given algorithm and return
/// the raw signature.
///
/// `timestamp` answers every [`FileBuilderRequest::Timestamp`] — which the
/// build issues only if [`BuilderSettings::timestamp`] is set. Mirroring
/// [`contentauth_c2pa_builder::BuilderRequest::Timestamp`], it receives a
/// digest and the algorithm it was computed with, performs the whole
/// timestamp authority round trip, and returns the bare `TimeStampToken`
/// (not the `TimeStampResp` it arrived in).
/// [`contentauth_c2pa_primitives::tsa`] encodes the request to send and
/// unwraps the response; only the network exchange in between is the
/// caller's. Pass `None` to build without one: a timestamp request then
/// fails the build rather than silently producing an untimestamped
/// manifest, as does a `timestamp` that fails. Reach for
/// [`FileBuilderSession`] directly for source/output access that cannot be
/// driven synchronously.
///
/// This function never touches `output`'s physical length: it writes
/// exactly the bytes the plan calls for and nothing else, so anything
/// already there past the new content — from reusing a stream with old
/// data in it — is left untouched rather than truncated away. That is
/// safe for the manifest itself: the hard binding's length comes from the
/// plan, not from measuring `output`, so those leftover bytes are never
/// signed or treated as part of the asset. It is not safe for whatever
/// was in them: a caller who reads `output` back as a plain file or
/// buffer, rather than trusting only what the manifest declares, would
/// still see that old content sitting right after the new asset. If
/// disclosing that would be a problem, pass a stream that starts empty —
/// an empty `Vec`/`Cursor`, or a freshly created or explicitly truncated
/// (`File::set_len(0)`) file — rather than reusing one that already has
/// content in it. [`build_and_sign_file`] always does this for you, via a
/// fresh temporary file.
pub fn build_and_sign<H, S, O>(
    handler: H,
    source: S,
    output: O,
    settings: BuilderSettings,
    sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
    timestamp: Option<&mut TimestampFn<'_>>,
) -> Result<FileBuilderReport, Error>
where
    H: FormatHandler + Send,
    S: Read + Seek,
    O: Read + Write + Seek,
{
    drive::build(handler, source, output, settings, sign, timestamp)
}

/// Opens `source_path`, builds and signs a manifest for it as
/// [`build_and_sign`], then atomically publishes the result at
/// `output_path`.
///
/// The output is assembled in a freshly, exclusively created temporary
/// file next to `output_path`, which is renamed into place only once the
/// build succeeds. A failure of any kind — from the build itself, from
/// `sign`, or from the rename — leaves `output_path` untouched and
/// removes the temporary file rather than publishing a partial asset or
/// leaving one behind.
pub fn build_and_sign_file<H>(
    handler: H,
    source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    settings: BuilderSettings,
    sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
    timestamp: Option<&mut TimestampFn<'_>>,
) -> Result<FileBuilderReport, Error>
where
    H: FormatHandler + Send,
{
    let source_path = source_path.as_ref();
    let source = std::fs::File::open(source_path).map_err(|source| Error::Io {
        path: source_path.to_path_buf(),
        source,
    })?;

    let output_path = output_path.as_ref();
    let temp_path = temp_path_for(output_path);

    // `create_new` — never `create` + `truncate` — so this can never
    // follow a symlink (or otherwise write through) a path an attacker
    // pre-created at the name we picked: it fails outright instead.
    // `temp_path_for`'s unpredictable suffix means there is nothing
    // meaningful to pre-create in the first place.
    let temp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| Error::Io {
            path: temp_path.clone(),
            source,
        })?;

    let report = match build_and_sign(handler, source, temp_file, settings, sign, timestamp) {
        Ok(report) => report,
        Err(err) => {
            // Best effort: an inability to clean up the temporary file
            // does not change the fact that the build itself failed, and
            // `output_path` is untouched either way.
            let _ = std::fs::remove_file(&temp_path);
            return Err(err);
        }
    };

    if let Err(source) = std::fs::rename(&temp_path, output_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(Error::Io {
            path: output_path.to_path_buf(),
            source,
        });
    }

    Ok(report)
}

/// A temporary path beside `output_path` for [`build_and_sign_file`] to
/// assemble the output in before renaming it into place: unpredictable
/// (a process ID, the current time, and a per-process counter, none of
/// which need to resist a determined attacker on their own — `create_new`
/// is what actually matters — only make the name hard to guess in
/// advance) rather than a fixed suffix, so nothing meaningful can be
/// pre-created at this exact path ahead of time.
fn temp_path_for(output_path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut temp = output_path.as_os_str().to_owned();
    temp.push(format!(
        ".c2pa-tmp-{:x}-{:x}-{:x}",
        std::process::id(),
        nanos,
        count
    ));
    PathBuf::from(temp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-process counter alone already guarantees two calls in the
    /// same process never collide, whatever the clock does between them —
    /// the property `create_new` in `build_and_sign_file` relies on to
    /// never mistake a leftover or maliciously pre-created path for one
    /// of its own.
    #[test]
    fn temp_path_for_never_repeats_within_a_process() {
        let output = Path::new("/some/output.jpg");
        let paths: std::collections::HashSet<PathBuf> =
            (0..100).map(|_| temp_path_for(output)).collect();
        assert_eq!(paths.len(), 100);
    }
}
