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
//! plain signing function (no timestamping). Reach for [`FileBuilderSession`]
//! directly once any of that stops being true.
//!
//! [`build_and_sign_file`] additionally never leaves a partial or corrupt
//! file at the requested output path: it builds into a temporary file
//! beside it and renames it into place only once the build succeeds,
//! deleting the temporary file on any failure instead.
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
};

pub use contentauth_c2pa_builder::{
    Assertion, AssertionKind, BuilderSettings, GeneratorInfo, SigningAlg, TimestampSettings,
};
pub use contentauth_c2pa_format::FormatHandler;
pub use contentauth_c2pa_primitives::HostError;
pub use error::Error;
pub use session::{FileBuilderReply, FileBuilderReport, FileBuilderRequest, FileBuilderSession};

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
/// Does not support [`BuilderSettings::timestamp`]: a
/// [`FileBuilderRequest::Timestamp`] request fails outright, since
/// answering it needs a real RFC 3161 authority round trip this function
/// has no way to perform. Reach for [`FileBuilderSession`] directly for
/// that, or for source/output access that cannot be driven synchronously.
pub fn build_and_sign<H, S, O>(
    handler: H,
    source: S,
    output: O,
    settings: BuilderSettings,
    sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
) -> Result<FileBuilderReport, Error>
where
    H: FormatHandler + Send,
    S: Read + Seek,
    O: Read + Write + Seek,
{
    drive::build(handler, source, output, settings, sign)
}

/// Opens `source_path`, builds and signs a manifest for it as
/// [`build_and_sign`], then atomically publishes the result at
/// `output_path`.
///
/// The output is assembled in a temporary file next to `output_path` —
/// `output_path` with a `.c2pa-tmp` suffix — which is renamed into place
/// only once the build succeeds. A failure of any kind, including one
/// from `sign`, leaves `output_path` untouched and removes the temporary
/// file rather than publishing a partial asset.
pub fn build_and_sign_file<H>(
    handler: H,
    source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    settings: BuilderSettings,
    sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
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

    let temp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|source| Error::Io {
            path: temp_path.clone(),
            source,
        })?;

    let report = match build_and_sign(handler, source, temp_file, settings, sign) {
        Ok(report) => report,
        Err(err) => {
            // Best effort: an inability to clean up the temporary file
            // does not change the fact that the build itself failed, and
            // `output_path` is untouched either way.
            let _ = std::fs::remove_file(&temp_path);
            return Err(err);
        }
    };

    std::fs::rename(&temp_path, output_path).map_err(|source| Error::Io {
        path: output_path.to_path_buf(),
        source,
    })?;

    Ok(report)
}

/// The temporary file [`build_and_sign_file`] assembles the output in,
/// before renaming it into place at `output_path`.
fn temp_path_for(output_path: &Path) -> PathBuf {
    let mut temp = output_path.as_os_str().to_owned();
    temp.push(".c2pa-tmp");
    PathBuf::from(temp)
}
