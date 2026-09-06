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

//! Reads and validates a C2PA manifest store for any container format with
//! a [`contentauth_c2pa_format::FormatHandler`].
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
//! # Two ways to use this crate
//!
//! [`FileReadSession`] is the primary interface: it composes a handler's
//! `locate` operation with a [`ReadSession`], and speaks a single merged
//! request vocabulary, [`FileReadRequest`], to whatever host drives it —
//! a host that reads a real file synchronously, one that fetches byte
//! ranges over a network asynchronously, or one that wants to supply its
//! own clock rather than the wall clock. It performs no I/O itself, in
//! keeping with every other session in this workspace.
//!
//! [`read_manifest`] and [`read_manifest_from_file`] are a host for exactly
//! that session, for the common case: a caller with plain, synchronous
//! `Read + Seek` access to the asset and no need for anything but the wall
//! clock. Reach for [`FileReadSession`] directly once either stops being
//! true.
//!
//! # Why `Read + Seek` rather than bytes
//!
//! Both the [`IoRequest`] a format handler issues and the [`ReadRequest`]
//! a read session issues name an absolute byte range, in no particular
//! order — a large asset is hashed out of sequence when its host answers
//! that way (`contentauth-c2pa-reader` is explicitly tested against it).
//! `Read + Seek` is the smallest standard-library shape that answers any
//! such range without first loading the whole asset into memory: any
//! `std::fs::File`, an in-memory buffer wrapped in `std::io::Cursor`, or a
//! host's own reader over whatever storage it actually has, satisfies it.
//!
//! # What this does not do
//!
//! It only reads — nothing here embeds a manifest store. A host that also
//! writes wants more than this: the two-stream (source/output) model a
//! future orchestrator crate is expected to provide.
//!
//! [`ReadSession`]: contentauth_c2pa_reader::ReadSession
//! [`FormatHandler`]: contentauth_c2pa_format::FormatHandler
//! [`FormatHandler::locate`]: contentauth_c2pa_format::FormatHandler::locate
//! [`IoRequest`]: contentauth_c2pa_format::IoRequest
//! [`ReadRequest`]: contentauth_c2pa_reader::ReadRequest

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

pub use contentauth_c2pa_format::FormatHandler;
pub use contentauth_c2pa_reader::{ReadReport, ReadSettings};
pub use error::Error;
pub use session::{FileReadReply, FileReadRequest, FileReadSession};

/// Locates and reads the C2PA manifest store embedded in `source`,
/// validating it per `settings`.
///
/// A synchronous host for [`FileReadSession`]: `handler` locates the
/// manifest store within `source`'s container format, and `source` also
/// serves every byte-range and length request the read issues for
/// hard-binding verification, since those cover the whole asset rather
/// than just the manifest store. The current wall-clock time answers
/// [`FileReadRequest::CurrentDateTime`]. Neither operation assumes
/// forward-only access: both seek to whatever range they were asked for.
///
/// Reach for [`FileReadSession`] directly instead if `source` cannot be
/// read synchronously (an async or network-backed host, say), or if the
/// wall clock is not the right answer for [`FileReadRequest::CurrentDateTime`].
pub fn read_manifest<H: FormatHandler, R: Read + Seek>(
    handler: &H,
    source: R,
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    drive::read(handler, source, settings)
}

/// Opens `path`, then locates and reads the C2PA manifest store embedded
/// in it, as [`read_manifest`].
pub fn read_manifest_from_file<H: FormatHandler>(
    handler: &H,
    path: impl AsRef<Path>,
    settings: ReadSettings,
) -> Result<ReadReport, Error> {
    let path = path.as_ref();
    let file = std::fs::File::open(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    read_manifest(handler, file, settings)
}
