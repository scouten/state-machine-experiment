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

//! RIFF container support for the sans-I/O C2PA sessions in this
//! workspace: a [`FormatHandler`] that locates a manifest store in a WAV,
//! AVI, or WebP file's `C2PA` chunk, and plans embedding one.
//!
//! # What this crate knows
//!
//! A RIFF file is a 12-byte header (`RIFF`, the size of everything after
//! those eight bytes, a form type) followed by chunks: a FourCC, a
//! little-endian `u32` data size, the data, and a pad byte if the size is
//! odd. The C2PA specification puts the manifest store in the data of a
//! chunk with the FourCC `C2PA`, "the last sub-chunk of the first RIFF
//! header chunk".
//!
//! That makes RIFF the simplest large-file container to embed in, and the
//! reason it is this workspace's test of streaming performance: nothing
//! already in the file moves, and the only byte outside the new chunk that
//! depends on the embedding is the header's size field, which depends on
//! the manifest store's *length* — known from the moment the placeholder
//! is chosen — not its content. The whole output is therefore a pure
//! function of the source and the length: a rewritten 12-byte header, the
//! source's chunks copied through, and the new chunk's framing around the
//! store.
//!
//! * [`FormatHandler::locate`] walks the top-level chunks (reading
//!   headers only, many per read) and reports the `C2PA` chunk's data,
//!   with the whole chunk as its range and — as the hard binding's
//!   exclusion — its 8-byte header and its data, but not the pad byte
//!   after odd data. (That is c2pa-rs's convention, and it rejects the
//!   alternative of hashing the header.)
//! * [`FormatHandler::plan_embed`] describes the output as the source with
//!   any existing `C2PA` chunk dropped and a new one appended at the end
//!   of the RIFF chunk; anything after the RIFF chunk (a trailing tag, or
//!   a later `RIFF` chunk in an extended AVI) stays after it.
//! * [`FormatHandler::commit`] has nothing to patch.
//!
//! # What it does not know
//!
//! * XMP: a `dcterms:provenance` reference to a remote store is not
//!   reported, and a WebP `VP8X` header's XMP flag is not touched, since
//!   no XMP is written.
//! * Files whose RIFF chunk would pass 4 GiB: sizes are 32-bit, and RF64 /
//!   BW64's 64-bit extension is not handled
//!   ([`FormatError::Unsupported`]).
//! * Files whose RIFF size field disagrees with their length, other than
//!   by extra bytes after the RIFF chunk
//!   ([`FormatError::Malformed`]).
//!
//! # Example
//!
//! ```
//! use contentauth_c2pa_format::{test_util::MemoryHost, FormatHandler, StreamId};
//! use contentauth_c2pa_format_riff::RiffFormat;
//!
//! // A WAV with one tiny data chunk.
//! let wav = b"RIFF\x12\0\0\0WAVEdata\x06\0\0\0\x01\x02\x03\x04\x05\x06";
//! let stream = StreamId::new(0);
//!
//! let plan = MemoryHost::new()
//!     .with_stream(stream, wav.to_vec())
//!     .run(RiffFormat.plan_embed(stream, 1000))?;
//! // The store's chunk goes last, and its header is excluded with it.
//! assert_eq!(plan.exclusions[0].start, 26);
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

use contentauth_c2pa_format::{
    EmbedPlan, FormatDescriptor, FormatError, FormatHandler, Patch, Signature, StreamId,
};
pub use contentauth_c2pa_format::{FormatOp, ManifestLocation};
pub use embed::PlanEmbed;
pub use locate::Locate;

/// How RIFF identifies itself: the `RIFF` FourCC.
///
/// Every RIFF form type — `WAVE`, `AVI `, `WEBP`, and the rest — shares
/// it, and so this descriptor claims all of them; the media types and
/// extensions name the three the C2PA specification does.
pub const DESCRIPTOR: FormatDescriptor = FormatDescriptor::new(
    "riff",
    &[
        "audio/wav",
        "audio/x-wav",
        "audio/wave",
        "audio/vnd.wave",
        "image/webp",
        "video/avi",
        "video/msvideo",
        "video/x-msvideo",
        "application/x-troff-msvideo",
    ],
    &["wav", "avi", "webp"],
    &[Signature::new(0, b"RIFF")],
);

/// The RIFF format handler.
///
/// Stateless: one value serves any number of assets. See the crate-level
/// documentation for what it does and does not handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RiffFormat;

impl FormatHandler for RiffFormat {
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
