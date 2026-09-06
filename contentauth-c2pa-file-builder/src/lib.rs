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
//! drives it. `ReservePlaceholder`, `AssetLength`, `AssetBytes`, and
//! `CommitManifest` are all answered internally — this session holds the
//! source asset (and the output it is assembling) in memory once read, so
//! none of that needs to leave the session. Only [`FileBuilderRequest::Sign`]
//! and [`FileBuilderRequest::Timestamp`] ever reach the host: a signing key
//! and an RFC 3161 authority round trip are not things this crate, or any
//! format handler, can stand in for.
//!
//! [`build_and_sign`] and [`build_and_sign_file`] are a host for exactly
//! that session, for the common case: a caller with plain, synchronous
//! `Read + Seek` access to the source asset and a plain signing function
//! (no timestamping). Reach for [`FileBuilderSession`] directly once
//! either stops being true.
//!
//! # Why the whole asset, not `Read + Seek`, on the output side
//!
//! Unlike `contentauth-c2pa-file-reader`, this crate cannot answer
//! `AssetBytes`/`AssetLength` from a `Read + Seek` source alone:
//! `EmbedPlan::materialize` — the only way this workspace's contract
//! between a session and a format handler turns a plan into bytes — takes
//! the whole source asset and produces the whole output asset, not a
//! range at a time. So this session reads the whole source into memory
//! once (one `Length` and one `Read` to its host), then holds the growing
//! output in memory itself. A future streaming orchestrator that hashes
//! straight from the plan, the way `contentauth-c2pa-format`'s own docs
//! describe, would lift this limit; nothing here needs the asset to be
//! reasonably sized in the meantime except this design choice.
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
    io::{Read, Seek},
    path::Path,
};

pub use contentauth_c2pa_builder::{
    Assertion, AssertionKind, BuilderSettings, GeneratorInfo, SigningAlg, TimestampSettings,
};
pub use contentauth_c2pa_format::FormatHandler;
pub use contentauth_c2pa_primitives::HostError;
pub use error::Error;
pub use session::{FileBuilderReply, FileBuilderReport, FileBuilderRequest, FileBuilderSession};

/// Builds and signs a C2PA manifest store for `source`, per `settings`,
/// calling `sign` whenever the claim signature needs signing.
///
/// A synchronous host for [`FileBuilderSession`]: `handler` plans and
/// commits the embedding within `source`'s container format, `source`
/// itself answers the one read this session needs to do its own work
/// (everything else it computes from the copy it keeps), and `sign`
/// answers every [`FileBuilderRequest::Sign`] the build issues — mirroring
/// [`contentauth_c2pa_builder::BuilderRequest::Sign`]: sign the exact
/// bytes handed to it with the given algorithm and return the raw
/// signature.
///
/// Does not support [`BuilderSettings::timestamp`]: a
/// [`FileBuilderRequest::Timestamp`] request fails outright, since
/// answering it needs a real RFC 3161 authority round trip this function
/// has no way to perform. Reach for [`FileBuilderSession`] directly for
/// that, or for a source that cannot be read synchronously.
pub fn build_and_sign<H, R>(
    handler: H,
    source: R,
    settings: BuilderSettings,
    sign: impl FnMut(SigningAlg, &[u8]) -> Result<Vec<u8>, HostError>,
) -> Result<FileBuilderReport, Error>
where
    H: FormatHandler + Send,
    R: Read + Seek,
{
    drive::build(handler, source, settings, sign)
}

/// Opens `source_path`, builds and signs a manifest for it as
/// [`build_and_sign`], then writes the complete output asset to
/// `output_path`.
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

    let report = build_and_sign(handler, source, settings, sign)?;

    let output_path = output_path.as_ref();
    std::fs::write(output_path, &report.asset).map_err(|source| Error::Io {
        path: output_path.to_path_buf(),
        source,
    })?;

    Ok(report)
}
