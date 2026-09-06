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

//! JPEG container support for the sans-I/O C2PA sessions in this
//! workspace: a [`FormatHandler`] that locates a manifest store in a
//! JPEG's `APP11` segments, and plans embedding one.
//!
//! # What this crate knows
//!
//! A C2PA manifest store rides in a JPEG as one or more `APP11` marker
//! segments, each carrying a `JP` preamble, a box instance number, a
//! packet sequence number, and a slice of the store — see `src/segment.rs`
//! for the byte layout, and for the c2pa-rs conventions this crate follows
//! so that what it writes is byte-identical to what c2pa-rs would write.
//!
//! Its two operations share one scan: walk the marker segments from `SOI`
//! to `SOS`, reading only headers and `APP11` contents (never image data),
//! and:
//!
//! * [`FormatHandler::locate`] reassembles the store from its segments —
//!   insisting on exactly what the specification requires (one store,
//!   packets `1..=n`, adjacent, each continuation repeating the superbox
//!   header, the total matching `LBox`) — and reports it with the range of
//!   the whole segment run, framing included. That range is what a
//!   `c2pa.hash.data` hard binding written for the file excludes.
//! * [`FormatHandler::plan_embed`] describes the output as the source with
//!   any existing store's segments dropped and new ones inserted where
//!   they were — or, in an unsigned file, right after the last `APP0`
//!   (JFIF) segment, or right after `SOI` if there is none.
//! * [`FormatHandler::commit`] has nothing to patch: no byte of a JPEG's
//!   framing depends on the store's content, except the superbox header
//!   continuation segments repeat, which the plan derived from the store's
//!   length and which commit verifies.
//!
//! # What it does not know
//!
//! * XMP. An `APP1` XMP packet's `dcterms:provenance` reference to a
//!   remote manifest store is not reported.
//! * Stores framed with JUMBF's 64-bit extended length field, or of 4 GiB
//!   and up ([`FormatError::Unsupported`]).
//! * Anything after `SOS`. A store placed after the first scan's data
//!   would not be found; the specification puts it in the header.
//!
//! # Example
//!
//! ```
//! use contentauth_c2pa_format::{test_util::MemoryHost, FormatHandler, StreamId};
//! use contentauth_c2pa_format_jpeg::JpegFormat;
//!
//! // Any host that answers `IoRequest`s will do; this one serves a byte
//! // slice. The JPEG here is only a header and no image.
//! let jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\0\x01\x02\0\0\x01\0\x01\0\0\xff\xd9";
//! let stream = StreamId::new(0);
//!
//! let location = MemoryHost::new()
//!     .with_stream(stream, jpeg.to_vec())
//!     .run(JpegFormat.locate(stream))?;
//! assert!(location.is_none());
//!
//! let plan = MemoryHost::new()
//!     .with_stream(stream, jpeg.to_vec())
//!     .run(JpegFormat.plan_embed(stream, 1000))?;
//! // The store goes right after the APP0 segment.
//! assert_eq!(plan.exclusion.start, 20);
//! # Ok::<(), contentauth_c2pa_format::FormatError>(())
//! ```

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod embed;
mod locate;
mod op;
mod scan;
mod segment;

use contentauth_c2pa_format::{EmbedPlan, FormatError, FormatHandler, Patch, StreamId};
pub use contentauth_c2pa_format::{FormatOp, ManifestLocation};
pub use embed::PlanEmbed;
pub use locate::Locate;

/// The JPEG format handler.
///
/// Stateless: one value serves any number of assets. See the crate-level
/// documentation for what it does and does not handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JpegFormat;

impl FormatHandler for JpegFormat {
    type Locate = Locate;
    type PlanEmbed = PlanEmbed;

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
