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

//! Hashing an asset from chunks the host streams in.
//!
//! # Why this is not "parallel hashing"
//!
//! SHA-2 is a Merkle–Damgård construction: each block folds into the
//! previous chaining value, so the *hashing* is irreducibly sequential.
//! What can overlap is the *fetching* — the host may service several
//! [`RequestKind::AssetBytes`] requests concurrently and fulfil them in any
//! order, which is usually where the latency is anyway.
//!
//! # How the bytes are reassembled correctly
//!
//! This module chooses every range, so the host never decides where bytes
//! belong:
//!
//! * each chunk request is remembered against its position in the sequence,
//!   so a reply is placed by its request ID rather than by arrival order;
//! * a reply whose length differs from the requested range is rejected
//!   outright — a short read would otherwise silently shift every
//!   subsequent byte;
//! * chunks are folded into the hasher strictly in order, with
//!   early arrivals buffered until their turn;
//! * the total folded is checked against the total requested before the
//!   digest is finalized.
//!
//! Deliberately *not* relied upon: the eventual hash comparison. It would
//! catch a reassembly bug, but it cannot tell one apart from a genuinely
//! altered asset — so the bug would surface to a user as "your content is
//! invalid", which is the worst way to report it. The invariants above
//! stand on their own; the hash only answers the question it is for.
//!
//! # Memory
//!
//! At most [`WINDOW`] chunks are in play at once (outstanding plus
//! buffered), bounding peak memory at `WINDOW × CHUNK_SIZE` no matter how
//! large the asset is.

use contentauth_state_machine::{ProtocolError, RequestId, SessionCore};

use crate::{
    error::Error,
    hash::Hasher,
    request::{HostReply, RequestKind},
    types::{ByteRange, HashAlgorithm, StreamId},
};

/// Bytes requested per chunk.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Maximum chunks in play (outstanding or buffered) at any moment.
///
/// This is what lets the host overlap reads while keeping memory bounded.
const WINDOW: usize = 8;

/// Accumulates a digest over host-streamed chunks of an asset.
#[derive(Debug)]
pub(crate) struct HashStream {
    hasher: Hasher,

    /// Every chunk to be hashed, in the order they must be folded.
    chunks: Vec<ByteRange>,

    /// Index of the next chunk to request.
    next_to_issue: usize,

    /// Index of the next chunk to fold into the hasher.
    next_to_fold: usize,

    /// Maximum chunks in play at once.
    window: usize,

    /// Requests the host has not yet answered, with the chunk each covers.
    outstanding: Vec<(RequestId, usize)>,

    /// Chunks that arrived before their turn.
    buffered: Vec<(usize, Vec<u8>)>,

    /// Bytes folded so far, checked against the total on completion.
    folded: u64,

    /// Total bytes this stream must hash.
    total: u64,
}

impl HashStream {
    /// Prepares to hash the given ranges, in order.
    pub(crate) fn new(algorithm: HashAlgorithm, ranges: &[ByteRange]) -> Self {
        Self::with_limits(algorithm, ranges, CHUNK_SIZE, WINDOW)
    }

    /// Prepares to hash with explicit chunking limits, so tests can drive
    /// many chunks through a small window.
    pub(crate) fn with_limits(
        algorithm: HashAlgorithm,
        ranges: &[ByteRange],
        chunk_size: u64,
        window: usize,
    ) -> Self {
        let mut chunks = Vec::new();

        for range in ranges {
            let mut offset = range.start;
            let end = range.start.saturating_add(range.len);

            while offset < end {
                let len = chunk_size.min(end - offset);
                chunks.push(ByteRange { start: offset, len });
                offset += len;
            }
        }

        Self {
            hasher: Hasher::new(algorithm),
            total: chunks.iter().map(|c| c.len).sum(),
            chunks,
            next_to_issue: 0,
            next_to_fold: 0,
            window: window.max(1),
            outstanding: Vec::new(),
            buffered: Vec::new(),
            folded: 0,
        }
    }

    /// Issues chunk requests until the window is full.
    pub(crate) fn issue(&mut self, core: &mut SessionCore<RequestKind>, stream: StreamId) {
        while self.next_to_issue < self.chunks.len()
            && self.next_to_issue - self.next_to_fold < self.window
        {
            let index = self.next_to_issue;
            let id = core.issue(RequestKind::AssetBytes {
                stream,
                range: self.chunks[index],
            });

            self.outstanding.push((id, index));
            self.next_to_issue += 1;
        }
    }

    /// Consumes whatever replies the host has provided, folding them in
    /// order and buffering any that arrived early.
    pub(crate) fn absorb(&mut self, core: &mut SessionCore<RequestKind>) -> Result<(), Error> {
        let mut position = 0;

        while position < self.outstanding.len() {
            let (id, index) = self.outstanding[position];

            match core.take_reply(id) {
                None => position += 1,

                Some(HostReply::AssetBytes(bytes)) => {
                    self.outstanding.remove(position);

                    let expected = self.chunks[index].len;
                    let actual = bytes.len() as u64;

                    // A short or long read would shift every byte after
                    // it, so this can never be tolerated.
                    if actual != expected {
                        return Err(Error::AssetBytesLengthMismatch {
                            range: self.chunks[index],
                            actual,
                        });
                    }

                    self.place(index, bytes);
                }

                Some(HostReply::Failed(source)) => {
                    self.outstanding.remove(position);
                    return Err(Error::HostFailure { id, source });
                }

                // `RequestTracker::fulfill` rejects mismatched reply
                // payloads, so this arm is unreachable in practice.
                Some(_) => {
                    self.outstanding.remove(position);
                    return Err(ProtocolError::ReplyMismatch {
                        id,
                        expected: "AssetBytes",
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    /// True once every chunk has been folded.
    pub(crate) fn is_complete(&self) -> bool {
        self.next_to_fold == self.chunks.len()
    }

    /// Finalizes the digest, checking that everything expected was folded.
    pub(crate) fn finish(self) -> Result<Vec<u8>, Error> {
        if !self.is_complete() || self.folded != self.total {
            return Err(Error::IncompleteAssetHash {
                folded: self.folded,
                expected: self.total,
            });
        }

        Ok(self.hasher.finish())
    }

    /// Places a chunk: folds it if it is next, otherwise buffers it, then
    /// drains anything the fold unblocked.
    fn place(&mut self, index: usize, bytes: Vec<u8>) {
        if index != self.next_to_fold {
            self.buffered.push((index, bytes));
            return;
        }

        self.fold(&bytes);

        while let Some(position) = self
            .buffered
            .iter()
            .position(|(index, _)| *index == self.next_to_fold)
        {
            let (_, bytes) = self.buffered.remove(position);
            self.fold(&bytes);
        }
    }

    /// Folds one chunk into the hasher and advances the cursor.
    fn fold(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.folded += bytes.len() as u64;
        self.next_to_fold += 1;
    }
}

/// Computes the ranges an asset hash covers: everything outside the
/// exclusions.
///
/// Returns `None` if the exclusions are not a sane description of the
/// asset — overlapping, or reaching past its end — which makes the hard
/// binding malformed rather than merely unmatched.
pub(crate) fn included_ranges(exclusions: &[ByteRange], asset_len: u64) -> Option<Vec<ByteRange>> {
    let mut sorted: Vec<ByteRange> = exclusions.to_vec();
    sorted.sort_by_key(|range| range.start);

    let mut included = Vec::new();
    let mut cursor = 0u64;

    for exclusion in sorted {
        let end = exclusion.start.checked_add(exclusion.len)?;

        if end > asset_len || exclusion.start < cursor {
            // Reaches past the asset, or overlaps the previous exclusion.
            return None;
        }

        if exclusion.start > cursor {
            included.push(ByteRange {
                start: cursor,
                len: exclusion.start - cursor,
            });
        }

        cursor = end;
    }

    if cursor < asset_len {
        included.push(ByteRange {
            start: cursor,
            len: asset_len - cursor,
        });
    }

    Some(included)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{error::HostError, types::HashAlgorithm};

    fn range(start: u64, len: u64) -> ByteRange {
        ByteRange { start, len }
    }

    #[test]
    fn included_ranges_are_the_complement_of_exclusions() {
        assert_eq!(
            included_ranges(&[range(20, 45884)], 132518).unwrap(),
            [range(0, 20), range(45904, 86614)]
        );

        // No exclusions: the whole asset.
        assert_eq!(included_ranges(&[], 100).unwrap(), [range(0, 100)]);

        // An exclusion at the very start, and one running to the end.
        assert_eq!(
            included_ranges(&[range(0, 10)], 100).unwrap(),
            [range(10, 90)]
        );
        assert_eq!(
            included_ranges(&[range(10, 90)], 100).unwrap(),
            [range(0, 10)]
        );

        // Excluding everything leaves nothing to hash.
        assert!(included_ranges(&[range(0, 100)], 100).unwrap().is_empty());
    }

    #[test]
    fn included_ranges_accepts_unsorted_exclusions() {
        assert_eq!(
            included_ranges(&[range(50, 10), range(10, 10)], 100).unwrap(),
            [range(0, 10), range(20, 30), range(60, 40)]
        );
    }

    #[test]
    fn included_ranges_rejects_nonsense_exclusions() {
        // Past the end of the asset.
        assert_eq!(included_ranges(&[range(90, 20)], 100), None);

        // Overlapping each other.
        assert_eq!(included_ranges(&[range(0, 30), range(20, 10)], 100), None);

        // Arithmetic that would wrap.
        assert_eq!(included_ranges(&[range(u64::MAX, 2)], 100), None);
    }

    /// Drives a stream to completion, fulfilling chunks in the order the
    /// given permutation names, and returns the digest.
    fn run(order: impl Fn(usize) -> Vec<usize>, chunk_size: u64, window: usize) -> Vec<u8> {
        let asset: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        let mut core = SessionCore::default();
        let mut stream =
            HashStream::with_limits(HashAlgorithm::Sha256, &[range(0, 1000)], chunk_size, window);

        while !stream.is_complete() {
            stream.issue(&mut core, StreamId(0));

            // Collect what is outstanding, then answer in the requested
            // order to simulate a host completing reads out of order.
            let pending: Vec<(RequestId, ByteRange)> = core
                .outstanding_requests()
                .iter()
                .map(|request| match request.kind {
                    RequestKind::AssetBytes { range, .. } => (request.id, range),
                    _ => unreachable!(),
                })
                .collect();

            // Absorb after each individual reply, so a later chunk really
            // does reach the stream before an earlier one and has to be
            // buffered until its turn.
            for position in order(pending.len()) {
                let (id, range) = pending[position];
                let start = range.start as usize;
                let bytes = asset[start..start + range.len as usize].to_vec();
                core.fulfill(id, HostReply::AssetBytes(bytes)).unwrap();
                stream.absorb(&mut core).unwrap();
            }
        }

        stream.finish().unwrap()
    }

    #[test]
    fn out_of_order_fulfilment_yields_an_identical_digest() {
        let expected = HashAlgorithm::Sha256
            .digest(&(0..1000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>());

        // In order.
        assert_eq!(run(|n| (0..n).collect(), 100, 4), expected);

        // Fully reversed.
        assert_eq!(run(|n| (0..n).rev().collect(), 100, 4), expected);

        // Interleaved: odds before evens.
        assert_eq!(
            run(
                |n| (0..n)
                    .filter(|i| i % 2 == 1)
                    .chain((0..n).filter(|i| i % 2 == 0))
                    .collect(),
                100,
                4
            ),
            expected
        );

        // A single chunk covering everything, and a window of one.
        assert_eq!(run(|n| (0..n).collect(), 4096, 1), expected);

        // Many tiny chunks.
        assert_eq!(run(|n| (0..n).rev().collect(), 7, 8), expected);
    }

    #[test]
    fn no_more_than_the_window_is_ever_in_play() {
        let mut core = SessionCore::default();
        let mut stream = HashStream::with_limits(HashAlgorithm::Sha256, &[range(0, 1000)], 100, 3);

        stream.issue(&mut core, StreamId(0));
        assert_eq!(
            core.outstanding_requests().len(),
            3,
            "issuing must stop at the window"
        );

        // Answer the newest chunk only: it cannot be folded yet, so the
        // window stays full and nothing new is issued.
        let last = core.outstanding_requests()[2].id;
        let range = range(200, 100);
        core.fulfill(last, HostReply::AssetBytes(vec![0u8; range.len as usize]))
            .unwrap();
        stream.absorb(&mut core).unwrap();
        stream.issue(&mut core, StreamId(0));

        assert_eq!(
            core.outstanding_requests().len(),
            2,
            "a buffered chunk still occupies the window"
        );
    }

    #[test]
    fn a_wrong_length_reply_is_rejected() {
        let mut core = SessionCore::default();
        let mut stream = HashStream::with_limits(HashAlgorithm::Sha256, &[range(0, 100)], 100, 4);

        stream.issue(&mut core, StreamId(0));
        let id = core.outstanding_requests()[0].id;

        // One byte short: tolerating this would shift every later byte.
        core.fulfill(id, HostReply::AssetBytes(vec![0u8; 99]))
            .unwrap();

        assert!(matches!(
            stream.absorb(&mut core),
            Err(Error::AssetBytesLengthMismatch { actual: 99, .. })
        ));
    }

    #[test]
    fn a_mismatched_stored_reply_is_defensively_rejected() {
        let mut core = SessionCore::default();
        let mut stream = HashStream::with_limits(HashAlgorithm::Sha256, &[range(0, 100)], 100, 4);

        stream.issue(&mut core, StreamId(0));
        let id = core.outstanding_requests()[0].id;

        // Bypass `fulfill`'s payload validation to reach the stream's own
        // defence-in-depth check.
        core.fulfill_unchecked(id, HostReply::CurrentDateTime(0));

        assert!(matches!(
            stream.absorb(&mut core),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "AssetBytes",
                ..
            }))
        ));
    }

    #[test]
    fn a_host_failure_propagates() {
        let mut core = SessionCore::default();
        let mut stream = HashStream::with_limits(HashAlgorithm::Sha256, &[range(0, 100)], 100, 4);

        stream.issue(&mut core, StreamId(0));
        let id = core.outstanding_requests()[0].id;
        core.fulfill(id, HostReply::Failed(HostError::new("unreadable")))
            .unwrap();

        assert!(matches!(
            stream.absorb(&mut core),
            Err(Error::HostFailure { .. })
        ));
    }

    #[test]
    fn finishing_early_is_refused() {
        let stream = HashStream::with_limits(HashAlgorithm::Sha256, &[range(0, 100)], 100, 4);

        assert!(matches!(
            stream.finish(),
            Err(Error::IncompleteAssetHash {
                folded: 0,
                expected: 100
            })
        ));
    }

    #[test]
    fn an_empty_range_set_completes_immediately() {
        let stream = HashStream::with_limits(HashAlgorithm::Sha256, &[], 100, 4);
        assert!(stream.is_complete());
        assert_eq!(stream.finish().unwrap(), HashAlgorithm::Sha256.digest(b""));
    }
}
