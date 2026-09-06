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

use contentauth_c2pa_format::{ByteRange, Edit, EmbedPlan, FormatError, Patch, StreamId};

use crate::{
    op::{delegate_session, Goal, ScanOp},
    scan::Layout,
    segment::{box_header, segment_header, BOX_HEADER_LEN, CHUNK_LEN},
};

/// The operation [`JpegFormat`](crate::JpegFormat)'s
/// [`plan_embed`](contentauth_c2pa_format::FormatHandler::plan_embed)
/// returns: scans the JPEG's header and describes the output as an
/// [`EmbedPlan`].
///
/// The store's segments go where an existing store's were, or — in an
/// unsigned file — right after the last `APP0` (JFIF) segment, or right
/// after `SOI` if there is none: the c2pa-rs rule, so a JFIF file stays a
/// JFIF file.
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

    fn finalize(self, layout: Layout) -> Result<EmbedPlan, FormatError> {
        let run = layout.manifest_run()?;
        let insert_at = layout.insertion_point(run.as_ref());

        EmbedPlan::splice(
            layout.source_len,
            run.map(|run| run.range),
            insert_at,
            self.manifest_len,
            framing(self.manifest_len)?,
        )
    }
}

/// The `APP11` segments that carry a store of `manifest_len` bytes: for
/// each [`CHUNK_LEN`] slice of the store, a segment header (plus, from the
/// second segment on, a copy of the store's 8-byte superbox header) and a
/// placeholder slot for the slice itself.
///
/// The superbox header is the one part of the store's *content* the
/// framing has to know before the content exists. It is fully determined
/// by the length — `LBox` is the length, `TBox` is always `jumb` — and
/// [`commit`] checks the real store agrees.
fn framing(manifest_len: u64) -> Result<Vec<Edit>, FormatError> {
    if manifest_len == 0 {
        return Err(FormatError::Unsupported(
            "an empty manifest store cannot be embedded".to_string(),
        ));
    }
    let lbox = u32::try_from(manifest_len).map_err(|_| {
        FormatError::Unsupported(
            "a manifest store of 4 GiB or more cannot be carried in a JPEG".to_string(),
        )
    })?;

    let mut edits = Vec::new();
    let mut offset = 0u64;
    let mut z = 1u32;

    while offset < manifest_len {
        let chunk = CHUNK_LEN.min(manifest_len - offset);

        let repeat_header = z > 1;
        let payload_len = chunk as usize + if repeat_header { BOX_HEADER_LEN } else { 0 };
        let mut header = segment_header(payload_len, z)?;
        if repeat_header {
            header.extend_from_slice(&box_header(lbox));
        }

        edits.push(Edit::Emit(header));
        edits.push(Edit::Placeholder(ByteRange {
            start: offset,
            len: chunk,
        }));

        offset += chunk;
        z += 1;
    }

    Ok(edits)
}

/// The handler's [`commit`](contentauth_c2pa_format::FormatHandler::commit):
/// nothing in a JPEG's framing depends on the store's content beyond the
/// superbox header the plan already assumed, so there is nothing to
/// patch — only that assumption to verify.
pub(crate) fn commit(plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
    if manifest.len() as u64 != plan.manifest_len {
        return Err(FormatError::ManifestMismatch(
            "manifest store length differs from the plan's",
        ));
    }

    let expected = u32::try_from(plan.manifest_len)
        .map(box_header)
        .map_err(|_| FormatError::Unsupported("a manifest store of 4 GiB or more".to_string()))?;
    if manifest.get(..BOX_HEADER_LEN) != Some(&expected[..]) {
        return Err(FormatError::ManifestMismatch(
            "manifest store does not begin with the JUMBF superbox header its segments repeat",
        ));
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::scan::tests::store;

    /// Splits framing into (header, slot) pairs.
    fn segments(edits: &[Edit]) -> Vec<(&[u8], ByteRange)> {
        edits
            .chunks(2)
            .map(|pair| match pair {
                [Edit::Emit(header), Edit::Placeholder(slot)] => (header.as_slice(), *slot),
                other => panic!("unexpected framing shape: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn a_small_store_takes_one_segment() {
        let edits = framing(500).unwrap();
        let segments = segments(&edits);

        assert_eq!(segments.len(), 1);
        let (header, slot) = segments[0];
        assert_eq!(header.len(), 12);
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 2 + 8 + 500);
        assert_eq!(&header[8..12], &[0, 0, 0, 1]);
        assert_eq!(slot, ByteRange { start: 0, len: 500 });
    }

    #[test]
    fn a_large_store_is_chunked_with_repeated_headers() {
        let len = 2 * CHUNK_LEN + 1;
        let edits = framing(len).unwrap();
        let segments = segments(&edits);

        assert_eq!(segments.len(), 3);

        let (first, slot) = segments[0];
        assert_eq!(first.len(), 12);
        assert_eq!(
            slot,
            ByteRange {
                start: 0,
                len: CHUNK_LEN
            }
        );

        let (second, slot) = segments[1];
        assert_eq!(second.len(), 20);
        assert_eq!(&second[8..12], &[0, 0, 0, 2]);
        assert_eq!(&second[12..20], &box_header(len as u32));
        assert_eq!(
            u16::from_be_bytes([second[2], second[3]]),
            2 + 8 + 8 + CHUNK_LEN as u16
        );
        assert_eq!(
            slot,
            ByteRange {
                start: CHUNK_LEN,
                len: CHUNK_LEN
            }
        );

        let (third, slot) = segments[2];
        assert_eq!(&third[8..12], &[0, 0, 0, 3]);
        assert_eq!(
            slot,
            ByteRange {
                start: 2 * CHUNK_LEN,
                len: 1
            }
        );
    }

    #[test]
    fn impossible_stores_are_refused() {
        assert!(matches!(framing(0), Err(FormatError::Unsupported(_))));
        assert!(matches!(
            framing(u64::from(u32::MAX) + 1),
            Err(FormatError::Unsupported(_))
        ));
    }

    #[test]
    fn commit_verifies_the_store_against_the_plan() {
        let store = store(300);
        let plan = EmbedPlan::splice(100, None, 2, 300, framing(300).unwrap()).unwrap();

        assert_eq!(commit(&plan, &store).unwrap(), []);

        assert!(matches!(
            commit(&plan, &store[..299]),
            Err(FormatError::ManifestMismatch(m)) if m.contains("length")
        ));

        let mut wrong_header = store.clone();
        wrong_header[3] = 0;
        assert!(matches!(
            commit(&plan, &wrong_header),
            Err(FormatError::ManifestMismatch(m)) if m.contains("superbox header")
        ));
    }
}
