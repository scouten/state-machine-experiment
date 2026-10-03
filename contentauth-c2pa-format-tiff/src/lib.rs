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

//! TIFF container support for the sans-I/O C2PA sessions in this
//! workspace: a [`FormatHandler`] that locates a manifest store in a
//! TIFF's IFD tag `0xCD41`, and plans embedding one. Classic TIFF and
//! BigTIFF; either byte order; DNG and other TIFF-based files, which are
//! the same structure under another name.
//!
//! # What this crate knows
//!
//! A TIFF is not a stream of segments but a graph of offsets: a header
//! points at an IFD (a table of tagged entries), which points at the next
//! IFD, and entries point at their data wherever it lies. A C2PA manifest
//! store rides as the data of one entry, tag `0xCD41`, type `UNDEFINED`;
//! see `src/embed.rs` for the layout this crate writes and why.
//!
//! Its operations share one scan, which reads the header and then follows
//! the main IFD chain — never image data:
//!
//! * [`FormatHandler::locate`] reads the store out of its entry.
//! * [`FormatHandler::plan_embed`] describes the output as the source with
//!   one IFD appended, holding only the C2PA entry, followed by the store,
//!   and the last IFD's next-IFD pointer rewritten to reach it. Nothing
//!   already in the file moves. An existing store laid out the same way is
//!   cut off and replaced.
//! * [`FormatHandler::commit`] has nothing to patch: every byte of framing
//!   depends on the store's *length*, which the plan was given.
//!
//! # What it does not know
//!
//! * XMP. A remote manifest reference in the XMP tag is not reported.
//! * Replacing a store that is not in a trailing IFD of its own
//!   ([`FormatError::Unsupported`]) — a store written by another tool
//!   into, say, IFD 0 is read, but not replaced.
//! * Sub-IFDs (EXIF, GPS, SubIFD tags). The specification puts the store in
//!   the main chain.
//! * Classic TIFF output at 4 GiB and up ([`FormatError::Unsupported`]):
//!   a BigTIFF source takes a store of any size, but this crate does not
//!   convert one format to the other.
//!
//! # Example
//!
//! ```
//! use contentauth_c2pa_format::{test_util::MemoryHost, FormatHandler, StreamId};
//! use contentauth_c2pa_format_tiff::TiffFormat;
//!
//! // A little-endian TIFF whose one IFD holds one entry (ImageWidth = 1)
//! // — no image data, but structurally a TIFF.
//! let tiff = b"II\x2a\0\x08\0\0\0\x01\0\0\x01\x03\0\x01\0\0\0\x01\0\0\0\0\0\0\0";
//! let stream = StreamId::new(0);
//!
//! let plan = MemoryHost::new()
//!     .with_stream(stream, tiff.to_vec())
//!     .run(TiffFormat.plan_embed(stream, 1000))?;
//! // The store goes in a new IFD appended at offset 26; the excluded span
//! // starts at its `count` field, after the entry count, tag and type.
//! assert_eq!(plan.exclusion.start, 26 + 2 + 4);
//! # Ok::<(), contentauth_c2pa_format::FormatError>(())
//! ```

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod embed;
mod format;
mod locate;
mod op;
mod scan;

use contentauth_c2pa_format::{
    EmbedPlan, FormatDescriptor, FormatError, FormatHandler, Patch, Signature, StreamId,
};
pub use contentauth_c2pa_format::{FormatOp, ManifestLocation};
pub use embed::PlanEmbed;
pub use locate::Locate;

/// How TIFF identifies itself: a byte-order mark and the magic number 42
/// (classic) or 43 (BigTIFF), in either byte order.
///
/// The media types and extensions are DNG's as well: it is a TIFF.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new(
    "tiff",
    &["image/tiff", "image/dng", "image/x-adobe-dng"],
    &["tif", "tiff", "dng"],
    &[
        Signature::new(0, b"II\x2a\0"),
        Signature::new(0, b"MM\0\x2a"),
        Signature::new(0, b"II\x2b\0"),
        Signature::new(0, b"MM\0\x2b"),
    ],
);

/// The TIFF format handler.
///
/// Stateless: one value serves any number of assets. See the crate-level
/// documentation for what it does and does not handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TiffFormat;

impl FormatHandler for TiffFormat {
    type Locate = Locate;
    type PlanEmbed = PlanEmbed;

    fn descriptor(&self) -> &FormatDescriptor {
        &DESCRIPTOR
    }

    fn locate(&self, stream: StreamId) -> Locate {
        Locate::new(stream)
    }

    fn plan_embed(&self, stream: StreamId, manifest_len: u64) -> PlanEmbed {
        PlanEmbed::new(stream, manifest_len)
    }

    fn commit(&self, plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
        embed::commit(plan, manifest)
    }
}
