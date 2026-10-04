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

//! Planning an embedding, and committing one.
//!
//! # The layout
//!
//! The specification wants the store at the end of the file, in the last
//! IFD of the main chain, and — unless that IFD is the file's only one — as
//! that IFD's only entry. The one layout that satisfies every case is to
//! append a new IFD holding just the C2PA entry, followed by the store
//! (after four bytes of padding in BigTIFF, to keep it 8-byte aligned), and
//! link it onto the end of the chain:
//!
//! ```text
//!  source bytes … │ pad │ entry count │ tag │ type │ count │ value │ next │ pad │ store
//!                   (aligned) =1        CD41   7     └─ ✗ ─┘ ofs→    0   (BigTIFF)└─ ✗ ─┘
//!                          └ emitted, hashed ┘            └ hashed ┘   (✗ = excluded)
//! ```
//!
//! Three properties follow, each unlike JPEG:
//!
//! * **Nothing moves.** Every offset already in the file — strip and tile
//!   offsets, sub-IFD pointers, the lot — stays valid, because the only
//!   bytes touched are the last IFD's four-byte (BigTIFF: eight) next
//!   pointer, rewritten from 0, and the new bytes at the end.
//! * **Everything the framing depends on is known up front.** The
//!   `count` field and the offset to the store are fixed by the store's
//!   *length*, which a plan is given, so [`commit`] has nothing to patch.
//! * **Two exclusions, exactly the specification's.** The specification
//!   asks that the entry's `count` field be excluded from a
//!   `c2pa.hash.data` hard binding (so an update manifest of another size
//!   can follow), along with the store itself. They are *not* adjacent —
//!   the value offset and the next pointer sit between — and a validator
//!   (c2pa-rs's does) compares them exactly, so the plan reports both and
//!   nothing else: the offset and the next pointer stay hashed, and
//!   cannot be redirected without breaking the signature. (An earlier
//!   version of this crate reported one contiguous superset, because the
//!   contract then had room for only one exclusion range; c2pa-rs
//!   rejected it. See [`EmbedPlan::exclusions`].)
//!
//! Re-embedding into a file already laid out this way cuts it off at the
//! `count` field and writes the new framing and store there. Replacing a
//! store anywhere else would mean removing an entry from the middle of an
//! IFD (shifting everything after it) or leaving the old store behind as
//! dead bytes; this crate does neither, and says so
//! ([`FormatError::Unsupported`]).

use contentauth_c2pa_format::{ByteRange, Edit, EmbedPlan, FormatError, Patch, StreamId};

use crate::{
    format::{Endian, Flavor, C2PA_TAG, TYPE_UNDEFINED},
    op::{delegate_session, Goal, ScanOp},
    scan::Layout,
};

/// The operation [`TiffFormat`](crate::TiffFormat)'s
/// [`plan_embed`](contentauth_c2pa_format::FormatHandler::plan_embed)
/// returns: follows the TIFF's IFD chain and describes the output as an
/// [`EmbedPlan`]. See the module documentation for the layout it plans.
pub struct PlanEmbed(ScanOp<PlanEmbedGoal>);

impl PlanEmbed {
    pub(crate) fn new(stream: StreamId, manifest_len: u64) -> Self {
        Self(ScanOp::new(stream, PlanEmbedGoal { manifest_len }))
    }
}

delegate_session!(PlanEmbed, EmbedPlan);

struct PlanEmbedGoal {
    manifest_len: u64,
}

impl Goal for PlanEmbedGoal {
    type Output = EmbedPlan;

    const READS_MANIFEST: bool = false;

    fn finalize(self, layout: Layout) -> Result<EmbedPlan, FormatError> {
        plan(&layout, self.manifest_len)
    }
}

/// The entry's value offset and the (zero) next-IFD pointer: the framing
/// between the excluded `count` field and the excluded store, which stays
/// hashed.
fn offset_and_next(endian: Endian, flavor: Flavor, data_start: u64) -> Vec<u8> {
    let word = flavor.word_len() as usize;
    let mut bytes = endian.encode(data_start, word);
    bytes.extend(endian.encode(0, word));
    bytes
}

fn plan(layout: &Layout, manifest_len: u64) -> Result<EmbedPlan, FormatError> {
    let Layout {
        header, source_len, ..
    } = *layout;
    let (endian, flavor) = (header.endian, header.flavor);

    if manifest_len == 0 {
        return Err(FormatError::Unsupported(
            "an empty manifest store cannot be embedded".to_string(),
        ));
    }

    let trailing = layout.trailing_store();
    if layout.c2pa.is_some() && trailing.is_none() {
        return Err(FormatError::Unsupported(
            "the asset's existing manifest store is not in a trailing IFD of its own, \
             so it cannot be replaced"
                .to_string(),
        ));
    }

    // Where the new IFD starts, what leads up to the excluded `count`
    // field, and which source bytes survive.
    let (ifd_start, lead_in, keep, replaced) = match trailing {
        // Cut the old IFD off at its `count` field, keeping the entry
        // count, tag and type before it as they are.
        Some(old) => {
            let lead = flavor.count_len() + 4;
            (old.start - lead, Vec::new(), old.start, Some(old))
        }

        // Append after the source, aligned (TIFF wants IFDs on even
        // offsets; BigTIFF's design asks for eight bytes), and say how the
        // new IFD begins.
        None => {
            let pad = flavor.align_up(source_len) - source_len;
            let mut lead_in = vec![0u8; pad as usize];
            lead_in.extend(endian.encode(1, flavor.count_len() as usize));
            lead_in.extend(endian.encode(u64::from(C2PA_TAG), 2));
            lead_in.extend(endian.encode(u64::from(TYPE_UNDEFINED), 2));
            (source_len + pad, lead_in, source_len, None)
        }
    };

    let data_start = flavor.store_offset(ifd_start);
    let end = data_start
        .checked_add(manifest_len)
        .ok_or_else(|| FormatError::Unsupported("the output length overflows".to_string()))?;
    if end > flavor.max_word() || manifest_len > flavor.max_word() {
        return Err(FormatError::Unsupported(
            "the output is too large for classic TIFF's 32-bit offsets; it needs BigTIFF"
                .to_string(),
        ));
    }

    let count_field = ByteRange {
        start: ifd_start + flavor.count_len() + 4,
        len: flavor.word_len(),
    };
    let exclusions = vec![
        count_field,
        ByteRange {
            start: data_start,
            len: manifest_len,
        },
    ];

    let mut edits = Vec::new();
    match replaced {
        Some(_) => copy(&mut edits, 0, keep),
        None => {
            // Link the new IFD onto the chain: the last IFD's next
            // pointer, which is zero, becomes the new IFD's offset.
            let last = layout
                .ifds
                .last()
                .ok_or(FormatError::Malformed("the asset has no IFD".to_string()))?;
            let at = last.next_field(flavor);
            let width = flavor.word_len();
            copy(&mut edits, 0, at);
            edits.push(Edit::Emit(endian.encode(ifd_start, width as usize)));
            copy(&mut edits, at + width, source_len);
            edits.push(Edit::Emit(lead_in));
        }
    }
    edits.push(Edit::Emit(
        endian.encode(manifest_len, flavor.word_len() as usize),
    ));
    edits.push(Edit::Emit(offset_and_next(endian, flavor, data_start)));
    // Padding that puts the store on its alignment (BigTIFF only); hashed.
    let store_pad = data_start - (ifd_start + flavor.ifd_len(1));
    if store_pad > 0 {
        edits.push(Edit::Emit(vec![0u8; store_pad as usize]));
    }
    edits.push(Edit::Placeholder(ByteRange {
        start: 0,
        len: manifest_len,
    }));

    let plan = EmbedPlan::new(edits, manifest_len, exclusions, replaced);
    plan.check(source_len)?;
    Ok(plan)
}

/// Appends a copy of `[start, end)` of the source, unless it is empty.
fn copy(edits: &mut Vec<Edit>, start: u64, end: u64) {
    if end > start {
        edits.push(Edit::Copy(ByteRange {
            start,
            len: end - start,
        }));
    }
}

/// The handler's [`commit`](contentauth_c2pa_format::FormatHandler::commit):
/// nothing in the framing depends on the store's content — only on its
/// length, which the plan already knew — so there is nothing to patch,
/// only that length to verify.
pub(crate) fn commit(plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
    if manifest.len() as u64 != plan.manifest_len {
        return Err(FormatError::ManifestMismatch(
            "manifest store length differs from the plan's",
        ));
    }
    Ok(Vec::new())
}
