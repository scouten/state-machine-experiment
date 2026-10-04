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

//! How a handler describes an embedding without performing it.
//!
//! An [`EmbedPlan`] is a recipe for the output asset as a sequence of
//! [`Edit`]s over the source: copy this range through, emit these bytes,
//! leave a slot for this part of the manifest store. It is the only thing
//! [`FormatHandler::plan_embed`](crate::FormatHandler::plan_embed) produces,
//! and it is enough for a host to write the output ([`EmbedPlan::materialize`]
//! is the in-memory reference for that) *and* for an orchestrating session
//! to hash the output without it ever being written — a `Copy` is a read of
//! the source, an `Emit` is already in hand, and a `Placeholder` is
//! excluded from the hash by construction.

use contentauth_c2pa_primitives::ByteRange;

use crate::error::FormatError;

/// One step of an [`EmbedPlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Edit {
    /// Copy this range of the source asset through unchanged.
    Copy(ByteRange),

    /// Emit these handler-computed bytes: container framing around the
    /// manifest store, or a rewrite of some existing structure (a RIFF
    /// size field, say) that the embedding changes.
    Emit(Vec<u8>),

    /// A slot for this range of the manifest store's bytes.
    ///
    /// The range is *within the manifest store*, not the output: a handler
    /// that must split the store across container segments (JPEG) uses
    /// several of these, each covering the next piece.
    Placeholder(ByteRange),
}

impl Edit {
    /// The number of output bytes this edit produces.
    pub fn len(&self) -> u64 {
        match self {
            Self::Copy(range) | Self::Placeholder(range) => range.len,
            Self::Emit(bytes) => bytes.len() as u64,
        }
    }

    /// True if this edit produces no output bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A recipe for the output asset: the source with a manifest store of a
/// known length embedded in it.
///
/// Produced by [`FormatHandler::plan_embed`](crate::FormatHandler::plan_embed).
/// [`Self::check`] verifies the invariants every consumer relies on;
/// [`Self::splice`] builds the common "drop the old store, insert the new
/// one at this offset" shape so a handler need only supply the framing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EmbedPlan {
    /// The output, in order.
    pub edits: Vec<Edit>,

    /// The length of the manifest store this plan embeds — the same for
    /// the zero-filled placeholder a builder starts with and the final,
    /// signed store that replaces it.
    pub manifest_len: u64,

    /// The ranges of the *output* a `c2pa.hash.data` hard binding written
    /// for it excludes, in ascending order and not overlapping.
    ///
    /// Usually one: the container structure carrying the manifest store,
    /// framing included (JPEG's run of `APP11` segments). A format may
    /// need more — TIFF's specification excludes the entry's `count`
    /// field *and* the store, which sit apart — and real validators
    /// compare them exactly, so a handler reports precisely the ranges
    /// its format's specification calls for, not a convenient superset.
    ///
    /// Every [`Edit::Placeholder`] lies within one of them; no
    /// [`Edit::Copy`] overlaps any. This is also what
    /// [`FormatHandler::locate`](crate::FormatHandler::locate) reports as
    /// [`EmbeddedManifest::exclusions`](crate::EmbeddedManifest::exclusions)
    /// when run on the output.
    pub exclusions: Vec<ByteRange>,

    /// The range of the *source* occupied by a manifest store this plan
    /// drops, if the source already carried one.
    ///
    /// Reported rather than acted on: whether replacing an existing store
    /// is acceptable, or whether it should first be validated and carried
    /// forward as a parent, is the caller's policy.
    pub replaced: Option<ByteRange>,
}

/// Returns the exclusive end of a range, or `None` if it overflows.
fn range_end(range: ByteRange) -> Option<u64> {
    range.start.checked_add(range.len)
}

impl EmbedPlan {
    /// Assembles a plan from its parts. Call [`Self::check`] before
    /// relying on it.
    pub fn new(
        edits: Vec<Edit>,
        manifest_len: u64,
        exclusions: Vec<ByteRange>,
        replaced: Option<ByteRange>,
    ) -> Self {
        Self {
            edits,
            manifest_len,
            exclusions,
            replaced,
        }
    }

    /// Builds the plan most container formats need: the source with
    /// `replace` (an existing manifest store's range, if any) removed and
    /// `wrapped` — the handler's framing around [`Edit::Placeholder`]
    /// slots for a store of `manifest_len` bytes — inserted at source
    /// offset `insert_at`.
    ///
    /// `insert_at` may not fall strictly inside `replace`; it typically
    /// equals `replace.start`, putting the new store where the old one
    /// was. The one exclusion range is the output span of `wrapped`. The
    /// result has already passed [`Self::check`].
    pub fn splice(
        source_len: u64,
        replace: Option<ByteRange>,
        insert_at: u64,
        manifest_len: u64,
        wrapped: Vec<Edit>,
    ) -> Result<Self, FormatError> {
        if insert_at > source_len {
            return Err(FormatError::InvalidPlan(
                "insertion point lies past the end of the source",
            ));
        }

        if let Some(replace) = replace {
            let end =
                range_end(replace).ok_or(FormatError::InvalidPlan("replaced range overflows"))?;
            if end > source_len {
                return Err(FormatError::InvalidPlan(
                    "replaced range reaches past the end of the source",
                ));
            }
            if insert_at > replace.start && insert_at < end {
                return Err(FormatError::InvalidPlan(
                    "insertion point lies inside the replaced range",
                ));
            }
        }

        let mut edits = Vec::with_capacity(wrapped.len() + 2);
        copy_excluding(&mut edits, 0, insert_at, replace);

        // Bounded by `source_len`, so cannot overflow.
        let exclusion_start: u64 = edits.iter().map(Edit::len).sum();
        let exclusion_len = wrapped
            .iter()
            .try_fold(0u64, |total, edit| total.checked_add(edit.len()))
            .ok_or(FormatError::InvalidPlan("output length overflows"))?;

        edits.extend(wrapped);
        copy_excluding(&mut edits, insert_at, source_len, replace);

        let plan = Self {
            edits,
            manifest_len,
            exclusions: vec![ByteRange {
                start: exclusion_start,
                len: exclusion_len,
            }],
            replaced: replace,
        };
        plan.check(source_len)?;
        Ok(plan)
    }

    /// The total length of the output this plan describes, or `None` if it
    /// overflows.
    pub fn output_len(&self) -> Option<u64> {
        self.edits
            .iter()
            .try_fold(0u64, |total, edit| total.checked_add(edit.len()))
    }

    /// Verifies the invariants every consumer of a plan relies on, and
    /// returns the output length.
    ///
    /// * The exclusions are in ascending order, do not overlap, and lie
    ///   within the output.
    /// * Every [`Edit::Copy`] lies within the source, and none of its
    ///   output lies within an exclusion: bytes carried over from the
    ///   asset are exactly what the hard binding exists to protect, so an
    ///   exclusion wide enough to swallow any of them is a plan bug, never
    ///   something a consumer should hash around.
    /// * The [`Edit::Placeholder`] slots, taken in order, cover
    ///   `[0, manifest_len)` exactly once with no gaps or overlaps.
    /// * Every placeholder slot lies within one exclusion. (Handler-emitted
    ///   framing may be excluded too; the manifest bytes must be.)
    /// * `replaced`, if set, lies within the source.
    ///
    /// A violation is [`FormatError::InvalidPlan`] — a bug in the handler
    /// that produced the plan.
    pub fn check(&self, source_len: u64) -> Result<u64, FormatError> {
        let mut previous_end = 0u64;
        for exclusion in &self.exclusions {
            let end = range_end(*exclusion)
                .ok_or(FormatError::InvalidPlan("exclusion range overflows"))?;
            if exclusion.start < previous_end {
                return Err(FormatError::InvalidPlan(
                    "exclusion ranges are out of order or overlap",
                ));
            }
            previous_end = end;
        }

        let mut output_len = 0u64;
        let mut next_slot = 0u64;

        for edit in &self.edits {
            let start = output_len;
            output_len = output_len
                .checked_add(edit.len())
                .ok_or(FormatError::InvalidPlan("output length overflows"))?;

            match edit {
                Edit::Copy(range) => {
                    let end = range_end(*range)
                        .ok_or(FormatError::InvalidPlan("a copy range overflows"))?;
                    if end > source_len {
                        return Err(FormatError::InvalidPlan(
                            "a copy reaches past the end of the source",
                        ));
                    }

                    // Non-empty overlap of [start, output_len) with an
                    // exclusion. (Ends were checked not to overflow.)
                    if self
                        .exclusions
                        .iter()
                        .any(|e| start < e.start + e.len && output_len > e.start)
                    {
                        return Err(FormatError::InvalidPlan(
                            "a copy of asset bytes lies inside the exclusion range",
                        ));
                    }
                }

                Edit::Emit(_) => {}

                Edit::Placeholder(range) => {
                    if range.start != next_slot {
                        return Err(FormatError::InvalidPlan(
                            "placeholder slots are out of order, overlap, or leave a gap",
                        ));
                    }
                    next_slot = range_end(*range)
                        .ok_or(FormatError::InvalidPlan("a placeholder range overflows"))?;

                    if !self
                        .exclusions
                        .iter()
                        .any(|e| start >= e.start && output_len <= e.start + e.len)
                    {
                        return Err(FormatError::InvalidPlan(
                            "a placeholder slot lies outside the exclusion range",
                        ));
                    }
                }
            }
        }

        if next_slot != self.manifest_len {
            return Err(FormatError::InvalidPlan(
                "placeholder slots do not cover the manifest store exactly",
            ));
        }

        if previous_end > output_len {
            return Err(FormatError::InvalidPlan(
                "exclusion range reaches past the end of the output",
            ));
        }

        if let Some(replaced) = self.replaced {
            let end =
                range_end(replaced).ok_or(FormatError::InvalidPlan("replaced range overflows"))?;
            if end > source_len {
                return Err(FormatError::InvalidPlan(
                    "replaced range reaches past the end of the source",
                ));
            }
        }

        Ok(output_len)
    }

    /// True if `range` lies entirely within one of the plan's exclusions.
    ///
    /// What a [`Patch`] must satisfy: bytes outside every exclusion have
    /// already been hashed into the hard binding.
    pub fn excludes(&self, range: ByteRange) -> bool {
        self.exclusions
            .iter()
            .any(|e| match (range_end(range), range_end(*e)) {
                (Some(end), Some(e_end)) => range.start >= e.start && end <= e_end,
                _ => false,
            })
    }

    /// Produces the output in memory: the reference implementation of
    /// what a host does with a plan, for hosts whose assets fit in memory
    /// and for tests.
    ///
    /// `manifest` fills the placeholder slots — the zero-filled placeholder
    /// or the final store, whichever the caller has — and must be exactly
    /// [`Self::manifest_len`] bytes.
    pub fn materialize(&self, source: &[u8], manifest: &[u8]) -> Result<Vec<u8>, FormatError> {
        let output_len = self.check(source.len() as u64)?;

        if manifest.len() as u64 != self.manifest_len {
            return Err(FormatError::ManifestMismatch(
                "manifest store length differs from the plan's",
            ));
        }

        let capacity = usize::try_from(output_len)
            .map_err(|_| FormatError::InvalidPlan("output does not fit in memory"))?;
        let mut output = Vec::with_capacity(capacity);

        for edit in &self.edits {
            match edit {
                // Bounds were established by `check`, against slices
                // whose lengths fit `usize`.
                Edit::Copy(range) => {
                    let start = range.start as usize;
                    let end = start + range.len as usize;
                    output.extend_from_slice(&source[start..end]);
                }
                Edit::Emit(bytes) => output.extend_from_slice(bytes),
                Edit::Placeholder(range) => {
                    let start = range.start as usize;
                    let end = start + range.len as usize;
                    output.extend_from_slice(&manifest[start..end]);
                }
            }
        }

        Ok(output)
    }
}

/// Appends copies of `[start, end)` of the source to `edits`, leaving out
/// whatever part of it `replace` covers.
fn copy_excluding(edits: &mut Vec<Edit>, start: u64, end: u64, replace: Option<ByteRange>) {
    let mut push = |start: u64, end: u64| {
        if end > start {
            edits.push(Edit::Copy(ByteRange {
                start,
                len: end - start,
            }));
        }
    };

    match replace {
        None => push(start, end),
        Some(replace) => {
            // Validated by the caller not to overflow.
            let replace_end = replace.start.saturating_add(replace.len);
            push(start, end.min(replace.start));
            push(start.max(replace_end), end);
        }
    }
}

/// A rewrite of some bytes of the output, produced by
/// [`FormatHandler::commit`](crate::FormatHandler::commit) once the final
/// manifest bytes are known.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Patch {
    /// Offset within the output.
    pub offset: u64,

    /// The bytes to write there.
    pub bytes: Vec<u8>,
}

impl Patch {
    /// A patch writing `bytes` at `offset` of the output.
    pub fn new(offset: u64, bytes: Vec<u8>) -> Self {
        Self { offset, bytes }
    }

    /// The range of the output this patch rewrites.
    pub fn range(&self) -> ByteRange {
        ByteRange {
            start: self.offset,
            len: self.bytes.len() as u64,
        }
    }

    /// True if this patch lies entirely within `range`.
    ///
    /// Every patch a handler returns must lie within one of the plan's
    /// exclusions ([`EmbedPlan::excludes`]): anything outside them has
    /// already been hashed into the hard binding.
    pub fn lies_within(&self, range: ByteRange) -> bool {
        match (range_end(self.range()), range_end(range)) {
            (Some(end), Some(range_end)) => self.offset >= range.start && end <= range_end,
            _ => false,
        }
    }

    /// Writes this patch into an in-memory output.
    pub fn apply(&self, output: &mut [u8]) -> Result<(), FormatError> {
        let end = range_end(self.range())
            .filter(|end| *end <= output.len() as u64)
            .ok_or(FormatError::InvalidPlan(
                "a patch reaches past the end of the output",
            ))?;
        output[self.offset as usize..end as usize].copy_from_slice(&self.bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn range(start: u64, len: u64) -> ByteRange {
        ByteRange { start, len }
    }

    /// Framing for a toy container: a 4-byte header, the store, a 2-byte
    /// trailer.
    fn wrapped(manifest_len: u64) -> Vec<Edit> {
        vec![
            Edit::Emit(vec![0xaa; 4]),
            Edit::Placeholder(range(0, manifest_len)),
            Edit::Emit(vec![0xbb; 2]),
        ]
    }

    #[test]
    fn splice_inserts_into_an_unsigned_source() {
        let plan = EmbedPlan::splice(100, None, 10, 5, wrapped(5)).unwrap();

        assert_eq!(
            plan.edits,
            [
                Edit::Copy(range(0, 10)),
                Edit::Emit(vec![0xaa; 4]),
                Edit::Placeholder(range(0, 5)),
                Edit::Emit(vec![0xbb; 2]),
                Edit::Copy(range(10, 90)),
            ]
        );
        assert_eq!(plan.exclusions, [range(10, 11)]);
        assert_eq!(plan.replaced, None);
        assert_eq!(plan.output_len(), Some(111));
    }

    #[test]
    fn splice_drops_a_replaced_range_wherever_it_lies() {
        // Replacing in place: the new store lands where the old one was.
        let plan = EmbedPlan::splice(100, Some(range(20, 30)), 20, 5, wrapped(5)).unwrap();
        assert_eq!(
            plan.edits,
            [
                Edit::Copy(range(0, 20)),
                Edit::Emit(vec![0xaa; 4]),
                Edit::Placeholder(range(0, 5)),
                Edit::Emit(vec![0xbb; 2]),
                Edit::Copy(range(50, 50)),
            ]
        );
        assert_eq!(plan.exclusions, [range(20, 11)]);
        assert_eq!(plan.replaced, Some(range(20, 30)));

        // The old store before the insertion point.
        let plan = EmbedPlan::splice(100, Some(range(20, 30)), 70, 5, wrapped(5)).unwrap();
        assert_eq!(
            plan.edits,
            [
                Edit::Copy(range(0, 20)),
                Edit::Copy(range(50, 20)),
                Edit::Emit(vec![0xaa; 4]),
                Edit::Placeholder(range(0, 5)),
                Edit::Emit(vec![0xbb; 2]),
                Edit::Copy(range(70, 30)),
            ]
        );
        assert_eq!(plan.exclusions, [range(40, 11)]);

        // The old store after the insertion point.
        let plan = EmbedPlan::splice(100, Some(range(60, 30)), 10, 5, wrapped(5)).unwrap();
        assert_eq!(
            plan.edits,
            [
                Edit::Copy(range(0, 10)),
                Edit::Emit(vec![0xaa; 4]),
                Edit::Placeholder(range(0, 5)),
                Edit::Emit(vec![0xbb; 2]),
                Edit::Copy(range(10, 50)),
                Edit::Copy(range(90, 10)),
            ]
        );

        // Inserting right after the old store is allowed too.
        let plan = EmbedPlan::splice(100, Some(range(20, 30)), 50, 5, wrapped(5)).unwrap();
        assert_eq!(plan.exclusions, [range(20, 11)]);
    }

    #[test]
    fn splice_at_the_edges_of_the_source() {
        let plan = EmbedPlan::splice(100, None, 0, 5, wrapped(5)).unwrap();
        assert_eq!(plan.edits[0], Edit::Emit(vec![0xaa; 4]));
        assert_eq!(plan.exclusions, [range(0, 11)]);

        let plan = EmbedPlan::splice(100, None, 100, 5, wrapped(5)).unwrap();
        assert_eq!(plan.edits.last(), Some(&Edit::Emit(vec![0xbb; 2])));
        assert_eq!(plan.exclusions, [range(100, 11)]);

        // Replacing a store that is the entire source.
        let plan = EmbedPlan::splice(100, Some(range(0, 100)), 0, 5, wrapped(5)).unwrap();
        assert_eq!(plan.edits.len(), 3);
        assert_eq!(plan.output_len(), Some(11));
    }

    #[test]
    fn splice_rejects_impossible_geometry() {
        assert!(matches!(
            EmbedPlan::splice(100, None, 101, 5, wrapped(5)),
            Err(FormatError::InvalidPlan(
                "insertion point lies past the end of the source"
            ))
        ));
        assert!(matches!(
            EmbedPlan::splice(100, Some(range(90, 20)), 0, 5, wrapped(5)),
            Err(FormatError::InvalidPlan(
                "replaced range reaches past the end of the source"
            ))
        ));
        assert!(matches!(
            EmbedPlan::splice(100, Some(range(20, 30)), 25, 5, wrapped(5)),
            Err(FormatError::InvalidPlan(
                "insertion point lies inside the replaced range"
            ))
        ));
        assert!(matches!(
            EmbedPlan::splice(100, Some(range(u64::MAX, 1)), 0, 5, wrapped(5)),
            Err(FormatError::InvalidPlan("replaced range overflows"))
        ));
    }

    #[test]
    fn check_catches_each_invariant() {
        let ok = EmbedPlan::splice(100, None, 10, 5, wrapped(5)).unwrap();
        assert_eq!(ok.check(100).unwrap(), 111);

        // A copy past the end of the source.
        assert!(matches!(
            ok.check(50),
            Err(FormatError::InvalidPlan(
                "a copy reaches past the end of the source"
            ))
        ));

        // Placeholder slots that do not add up to the manifest.
        let mut short = ok.clone();
        short.manifest_len = 6;
        assert!(matches!(
            short.check(100),
            Err(FormatError::InvalidPlan(
                "placeholder slots do not cover the manifest store exactly"
            ))
        ));

        // Slots out of order.
        let mut reordered = ok.clone();
        reordered.edits.insert(3, Edit::Placeholder(range(0, 1)));
        assert!(matches!(
            reordered.check(100),
            Err(FormatError::InvalidPlan(
                "placeholder slots are out of order, overlap, or leave a gap"
            ))
        ));

        // A slot outside the exclusion.
        let mut outside = ok.clone();
        outside.exclusions = vec![range(11, 5)];
        assert!(matches!(
            outside.check(100),
            Err(FormatError::InvalidPlan(
                "a placeholder slot lies outside the exclusion range"
            ))
        ));

        // An exclusion wide enough to swallow copied asset bytes — one
        // byte before the framing, and one byte after it.
        for exclusion in [range(9, 12), range(10, 12)] {
            let mut too_wide = ok.clone();
            too_wide.exclusions = vec![exclusion];
            let result = too_wide.check(100);
            assert!(
                matches!(
                    result,
                    Err(FormatError::InvalidPlan(
                        "a copy of asset bytes lies inside the exclusion range"
                    ))
                ),
                "exclusion {exclusion:?}: {result:?}"
            );
        }

        // Whereas an exclusion that stops exactly at the copies is fine,
        // and an empty copy adjacent to it never overlaps.
        let mut tight = ok.clone();
        tight.edits.insert(1, Edit::Copy(range(10, 0)));
        assert_eq!(tight.check(100).unwrap(), 111);

        // An exclusion past the end of the output — on a plan with the
        // framing at the very end, so no copied bytes fall inside it and
        // the overrun is the only violation.
        let mut long = EmbedPlan::splice(100, None, 100, 5, wrapped(5)).unwrap();
        long.exclusions = vec![range(100, 200)];
        assert!(matches!(
            long.check(100),
            Err(FormatError::InvalidPlan(
                "exclusion range reaches past the end of the output"
            ))
        ));

        // A replaced range past the end of the source.
        let mut replaced = ok.clone();
        replaced.replaced = Some(range(90, 20));
        assert!(matches!(
            replaced.check(100),
            Err(FormatError::InvalidPlan(
                "replaced range reaches past the end of the source"
            ))
        ));

        // Arithmetic that would wrap.
        let mut overflow = ok.clone();
        overflow.edits.push(Edit::Copy(range(u64::MAX, 1)));
        assert!(matches!(
            overflow.check(u64::MAX),
            Err(FormatError::InvalidPlan("a copy range overflows"))
        ));
        let mut overflow = ok;
        overflow.exclusions = vec![range(u64::MAX, 1)];
        assert!(matches!(
            overflow.check(100),
            Err(FormatError::InvalidPlan("exclusion range overflows"))
        ));
    }

    #[test]
    fn materialize_produces_the_described_output() {
        let source: Vec<u8> = (0..100).collect();
        let manifest = [1, 2, 3, 4, 5];
        let plan = EmbedPlan::splice(100, Some(range(20, 30)), 20, 5, wrapped(5)).unwrap();

        let output = plan.materialize(&source, &manifest).unwrap();

        let mut expected = source[..20].to_vec();
        expected.extend([0xaa; 4]);
        expected.extend(manifest);
        expected.extend([0xbb; 2]);
        expected.extend(&source[50..]);
        assert_eq!(output, expected);

        assert!(matches!(
            plan.materialize(&source, &[1, 2, 3]),
            Err(FormatError::ManifestMismatch(_))
        ));
        assert!(matches!(
            plan.materialize(&source[..50], &manifest),
            Err(FormatError::InvalidPlan(_))
        ));
    }

    #[test]
    fn patches_know_their_bounds() {
        let patch = Patch::new(10, vec![9; 4]);
        assert_eq!(patch.range(), range(10, 4));

        assert!(patch.lies_within(range(10, 4)));
        assert!(patch.lies_within(range(0, 100)));
        assert!(!patch.lies_within(range(11, 4)));
        assert!(!patch.lies_within(range(0, 13)));
        assert!(!patch.lies_within(range(u64::MAX, 1)));

        let mut output = vec![0u8; 14];
        patch.apply(&mut output).unwrap();
        assert_eq!(&output[10..], [9, 9, 9, 9]);

        let mut short = vec![0u8; 13];
        assert!(matches!(
            patch.apply(&mut short),
            Err(FormatError::InvalidPlan(_))
        ));
        assert!(matches!(
            Patch::new(u64::MAX, vec![1]).apply(&mut short),
            Err(FormatError::InvalidPlan(_))
        ));
    }

    #[test]
    fn edits_report_their_lengths() {
        assert_eq!(Edit::Copy(range(0, 7)).len(), 7);
        assert_eq!(Edit::Emit(vec![0; 3]).len(), 3);
        assert_eq!(Edit::Placeholder(range(5, 0)).len(), 0);
        assert!(Edit::Placeholder(range(5, 0)).is_empty());
        assert!(!Edit::Emit(vec![0]).is_empty());
    }

    /// A plan shaped like TIFF's: a 4-byte field excluded, 4 bytes hashed,
    /// then the store excluded.
    fn two_apart() -> EmbedPlan {
        EmbedPlan::new(
            vec![
                Edit::Copy(range(0, 10)),
                Edit::Emit(vec![1; 4]),
                Edit::Emit(vec![2; 4]),
                Edit::Placeholder(range(0, 6)),
            ],
            6,
            vec![range(10, 4), range(18, 6)],
            None,
        )
    }

    #[test]
    fn exclusions_may_be_several_ranges_with_hashed_bytes_between() {
        let plan = two_apart();
        assert_eq!(plan.check(10).unwrap(), 24);
        assert_eq!(plan.materialize(&[7; 10], &[9; 6]).unwrap().len(), 24);
    }

    #[test]
    fn a_patch_must_lie_within_one_exclusion() {
        let plan = two_apart();
        assert!(plan.excludes(range(10, 4)));
        assert!(plan.excludes(range(20, 2)));
        // In the gap between them, spanning both, or off the end.
        assert!(!plan.excludes(range(14, 4)));
        assert!(!plan.excludes(range(12, 8)));
        assert!(!plan.excludes(range(22, 4)));
        assert!(!plan.excludes(range(u64::MAX, 2)));
    }

    #[test]
    fn exclusions_must_be_ordered_and_disjoint() {
        let mut plan = two_apart();
        plan.exclusions = vec![range(18, 6), range(10, 4)];
        assert!(matches!(
            plan.check(10),
            Err(FormatError::InvalidPlan(m)) if m.contains("out of order")
        ));

        plan.exclusions = vec![range(10, 10), range(18, 6)];
        assert!(matches!(
            plan.check(10),
            Err(FormatError::InvalidPlan(m)) if m.contains("overlap")
        ));
    }

    #[test]
    fn a_copy_inside_any_exclusion_is_refused() {
        let mut plan = two_apart();
        // Excluding the hashed gap bytes' neighbor swallows nothing, but
        // an exclusion over the copied bytes does.
        plan.exclusions = vec![range(8, 6), range(18, 6)];
        assert!(matches!(
            plan.check(10),
            Err(FormatError::InvalidPlan(m)) if m.contains("copy")
        ));
    }

    #[test]
    fn the_store_must_be_excluded_even_when_the_framing_is_too() {
        let mut plan = two_apart();
        plan.exclusions = vec![range(10, 4)];
        assert!(matches!(
            plan.check(10),
            Err(FormatError::InvalidPlan(m)) if m.contains("outside")
        ));
    }
}
