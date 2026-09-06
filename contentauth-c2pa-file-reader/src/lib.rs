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

//! Reads and validates a C2PA manifest store straight from a file — or any
//! byte buffer already in memory — for any container format with a
//! [`contentauth_c2pa_format::FormatHandler`].
//!
//! # The gap this fills
//!
//! [`contentauth_c2pa_reader::ReadSession`] never touches a container
//! format: it asks its host for "the manifest store's bytes"
//! ([`contentauth_c2pa_reader::ReadRequest::ManifestStore`]) and expects an
//! answer. A [`FormatHandler`] answers exactly that question through
//! [`FormatHandler::locate`], but nothing in `contentauth-c2pa-format` or
//! `contentauth-c2pa-reader` connects the two — by design, neither crate
//! depends on the other, and doing so was, until now, hand-written host
//! glue duplicated in every format handler crate's own tests.
//!
//! This crate is that glue, generalized to any handler and reused as
//! library code: [`read_manifest`] and [`read_manifest_from_file`] hold the
//! whole asset in memory, run a handler's `locate` operation over it to
//! find the manifest store, then drive a [`ReadSession`] over the same
//! bytes.
//!
//! # What this does not do
//!
//! It reads the whole asset into memory up front rather than streaming it,
//! and it only reads — nothing here embeds a manifest store. A production
//! host reading gigabyte-scale video, or writing as well as reading, wants
//! more than this: streaming I/O, and the two-stream (source/output) model
//! a future orchestrator crate is expected to provide. For a manifest
//! store in an already-loaded image or document, this is enough.
//!
//! [`ReadSession`]: contentauth_c2pa_reader::ReadSession
//! [`FormatHandler`]: contentauth_c2pa_format::FormatHandler
//! [`FormatHandler::locate`]: contentauth_c2pa_format::FormatHandler::locate

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod drive;
mod error;

use std::path::Path;

pub use contentauth_c2pa_format::FormatHandler;
pub use contentauth_c2pa_reader::{ReadReport, ReadSettings};
pub use error::Error;

/// Locates and reads the C2PA manifest store embedded in `bytes`,
/// validating it per `settings`.
///
/// `handler` locates the manifest store within `bytes`'s container format;
/// `bytes` also serves every [`ReadRequest::AssetBytes`] and
/// [`ReadRequest::AssetLength`] the read issues for hard-binding
/// verification, since those cover the whole asset rather than just the
/// manifest store.
///
/// [`ReadRequest::AssetBytes`]: contentauth_c2pa_reader::ReadRequest::AssetBytes
/// [`ReadRequest::AssetLength`]: contentauth_c2pa_reader::ReadRequest::AssetLength
pub fn read_manifest<H: FormatHandler>(
    handler: &H,
    bytes: &[u8],
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    drive::read(handler, bytes, settings)
}

/// Reads `path` from disk in full, then locates and reads the C2PA
/// manifest store embedded in it, as [`read_manifest`].
pub fn read_manifest_from_file<H: FormatHandler>(
    handler: &H,
    path: impl AsRef<Path>,
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    read_manifest(handler, &bytes, settings)
}
