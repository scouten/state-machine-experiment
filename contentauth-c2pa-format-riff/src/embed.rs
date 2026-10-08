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
    scan::{Layout, C2PA_CHUNK_ID, CHUNK_HEADER_LEN, HEADER_LEN},
};

/// The operation [`RiffFormat`](crate::RiffFormat)'s
/// [`plan_embed`](contentauth_c2pa_format::FormatHandler::plan_embed)
/// returns: walks the RIFF chunk's top-level chunks and describes the
/// output as an [`EmbedPlan`].
///
/// The output is the source with a rewritten 12-byte header (the RIFF size
/// field is the one thing the embedding changes outside the new chunk), any
/// existing `C2PA` chunk dropped, and the new chunk appended as the last
/// sub-chunk of the RIFF chunk, as the specification requires. Whatever
/// follows the RIFF chunk in the source follows it in the output.
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

    const READ_MANIFEST: bool = false;

    fn finalize(self, layout: Layout) -> Result<EmbedPlan, FormatError> {
        plan(&layout, self.manifest_len)
    }
}

/// Data size rounded up to the even boundary RIFF aligns chunks to.
fn padded(len: u64) -> u64 {
    len + (len & 1)
}

fn plan(layout: &Layout, manifest_len: u64) -> Result<EmbedPlan, FormatError> {
    if manifest_len == 0 {
        return Err(FormatError::Unsupported(
            "an empty manifest store cannot be embedded".to_string(),
        ));
    }
    let data_size = u32::try_from(manifest_len).map_err(|_| {
        FormatError::Unsupported(
            "a manifest store of 4 GiB or more cannot be carried in a RIFF chunk".to_string(),
        )
    })?;

    let replaced = layout.manifest.as_ref().map(|chunk| chunk.range);

    // The RIFF chunk's contents with the old store cut out.
    let mut kept = Vec::with_capacity(2);
    let mut kept_len = 0u64;
    let mut keep = |start: u64, end: u64| {
        if end > start {
            kept.push(Edit::Copy(ByteRange {
                start,
                len: end - start,
            }));
            kept_len += end - start;
        }
    };
    match replaced {
        None => keep(HEADER_LEN, layout.riff_end),
        Some(old) => {
            keep(HEADER_LEN, old.start);
            keep(old.start + old.len, layout.riff_end);
        }
    }

    // Chunks start on even offsets, so contents of odd length mean the
    // last chunk lost its pad byte; supply it, or the new chunk would
    // start misaligned.
    let pad_before = kept_len & 1;

    let chunk_len = CHUNK_HEADER_LEN + padded(manifest_len);
    let riff_len = HEADER_LEN + kept_len + pad_before + chunk_len;
    let size_field = u32::try_from(riff_len - CHUNK_HEADER_LEN).map_err(|_| {
        FormatError::Unsupported(
            "the RIFF chunk would exceed 4 GiB with the manifest store added".to_string(),
        )
    })?;

    let mut header = b"RIFF".to_vec();
    header.extend_from_slice(&size_field.to_le_bytes());
    header.extend_from_slice(&layout.form);

    let mut chunk_header = C2PA_CHUNK_ID.to_vec();
    chunk_header.extend_from_slice(&data_size.to_le_bytes());

    let mut edits = Vec::with_capacity(kept.len() + 6);
    edits.push(Edit::Emit(header));
    edits.extend(kept);
    if pad_before == 1 {
        edits.push(Edit::Emit(vec![0]));
    }
    edits.push(Edit::Emit(chunk_header));
    edits.push(Edit::Placeholder(ByteRange {
        start: 0,
        len: manifest_len,
    }));
    if manifest_len & 1 == 1 {
        edits.push(Edit::Emit(vec![0]));
    }
    if layout.source_len > layout.riff_end {
        edits.push(Edit::Copy(ByteRange {
            start: layout.riff_end,
            len: layout.source_len - layout.riff_end,
        }));
    }

    // The chunk's header and data, but not the pad byte after odd data:
    // the range c2pa-rs writes and insists on when it validates.
    let exclusion = ByteRange {
        start: riff_len - chunk_len,
        len: CHUNK_HEADER_LEN + manifest_len,
    };

    let plan = EmbedPlan::new(edits, manifest_len, vec![exclusion], replaced);
    plan.check(layout.source_len)?;
    Ok(plan)
}

/// The handler's [`commit`](contentauth_c2pa_format::FormatHandler::commit):
/// nothing in a RIFF file depends on the store's content, so there is
/// nothing to patch — only the length to verify.
pub(crate) fn commit(plan: &EmbedPlan, manifest: &[u8]) -> Result<Vec<Patch>, FormatError> {
    if manifest.len() as u64 != plan.manifest_len {
        return Err(FormatError::ManifestMismatch(
            "manifest store length differs from the plan's",
        ));
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::scan::{tests::riff, StoredChunk};

    fn layout_of(file: &[u8], manifest: Option<StoredChunk>) -> Layout {
        Layout {
            source_len: file.len() as u64,
            riff_end: file.len() as u64,
            form: *b"WAVE",
            manifest,
        }
    }

    #[test]
    fn the_size_field_and_chunk_framing_follow_the_store_length() {
        let file = riff(b"WAVE", &[(b"data", &[1; 10])]);
        let plan = plan(&layout_of(&file, None), 101).unwrap();
        let out = plan.materialize(&file, &[9; 101]).unwrap();

        assert_eq!(&out[..4], b"RIFF");
        assert_eq!(
            u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize,
            out.len() - 8
        );
        assert_eq!(&out[8..12], b"WAVE");
        // Source contents, then the chunk, padded.
        let at = file.len();
        assert_eq!(&out[at..at + 4], b"C2PA");
        assert_eq!(
            u32::from_le_bytes(out[at + 4..at + 8].try_into().unwrap()),
            101
        );
        assert_eq!(out[at + 8 + 101], 0);
        assert_eq!(out.len(), at + 8 + 102);

        // The header and the 101 bytes of data; the pad byte is hashed.
        assert_eq!(
            plan.exclusions,
            vec![ByteRange {
                start: at as u64,
                len: 109
            }]
        );
    }

    #[test]
    fn an_even_store_has_no_pad_byte() {
        let file = riff(b"WAVE", &[(b"data", &[1; 10])]);
        let plan = plan(&layout_of(&file, None), 100).unwrap();
        assert_eq!(plan.output_len().unwrap(), file.len() as u64 + 8 + 100);
        assert_eq!(plan.exclusions[0].len, 108);
    }

    #[test]
    fn an_existing_store_is_cut_out_and_reported() {
        let file = riff(b"WAVE", &[(b"C2PA", &[5; 20]), (b"data", &[1; 10])]);
        let old = StoredChunk {
            range: ByteRange { start: 12, len: 28 },
            data_len: 20,
            data: Vec::new(),
        };
        let plan = plan(&layout_of(&file, Some(old)), 40).unwrap();

        assert_eq!(plan.replaced, Some(ByteRange { start: 12, len: 28 }));
        let out = plan.materialize(&file, &[9; 40]).unwrap();
        assert_eq!(out.len(), file.len() - 28 + 8 + 40);
        // `data` now comes first; the new chunk is last.
        assert_eq!(&out[12..16], b"data");
        assert_eq!(&out[out.len() - 48..out.len() - 44], b"C2PA");
    }

    #[test]
    fn trailing_bytes_follow_the_new_chunk() {
        let mut file = riff(b"WAVE", &[(b"data", &[1; 10])]);
        let riff_end = file.len() as u64;
        file.extend_from_slice(b"tail");
        let layout = Layout {
            source_len: file.len() as u64,
            riff_end,
            form: *b"WAVE",
            manifest: None,
        };
        let plan = plan(&layout, 10).unwrap();
        let out = plan.materialize(&file, &[9; 10]).unwrap();

        assert!(out.ends_with(b"tail"));
        // The size field still stops short of the tail.
        let size = u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize;
        assert_eq!(size + 8, out.len() - 4);
    }

    #[test]
    fn a_final_chunk_missing_its_pad_gets_one_before_the_new_chunk() {
        let mut file = riff(b"WAVE", &[(b"data", &[1; 5])]);
        file.pop();
        let size = (file.len() - 8) as u32;
        file[4..8].copy_from_slice(&size.to_le_bytes());

        let plan = plan(&layout_of(&file, None), 10).unwrap();
        let out = plan.materialize(&file, &[9; 10]).unwrap();
        // Everything after the 12-byte header is whole chunks again.
        assert_eq!(out.len() % 2, 0);
        assert_eq!(&out[out.len() - 18..out.len() - 14], b"C2PA");
        assert_eq!((out.len() - 18) % 2, 0);
    }

    #[test]
    fn impossible_stores_are_refused() {
        let file = riff(b"WAVE", &[]);
        let layout = layout_of(&file, None);
        assert!(matches!(plan(&layout, 0), Err(FormatError::Unsupported(_))));
        assert!(matches!(
            plan(&layout, u64::from(u32::MAX) + 1),
            Err(FormatError::Unsupported(_))
        ));
        // Fits a chunk, but not the RIFF chunk around it.
        assert!(matches!(
            plan(&layout, u64::from(u32::MAX) - 4),
            Err(FormatError::Unsupported(_))
        ));
    }

    #[test]
    fn commit_verifies_the_length_and_patches_nothing() {
        let file = riff(b"WAVE", &[]);
        let plan = plan(&layout_of(&file, None), 30).unwrap();

        assert_eq!(commit(&plan, &[0; 30]).unwrap(), []);
        assert!(matches!(
            commit(&plan, &[0; 29]),
            Err(FormatError::ManifestMismatch(_))
        ));
    }
}
