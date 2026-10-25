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

//! Hashing an asset from chunks the host streams in, to compute the hard
//! binding this crate is about to sign.
//!
//! The write-side twin of `contentauth-c2pa-reader`'s own `hash_stream`
//! module — the same windowed, order-independent chunk protocol — but
//! written as an `async fn` over the session's [`Host`], where the
//! reader's is a hand-written state machine with its own table of which
//! chunk each outstanding request covers, and its own buffer for chunks
//! that arrive before their turn. Here a queue of [`PendingReply`]s is
//! that table. All replies in the window are polled so failures and wrong
//! lengths surface promptly; valid chunks wait in shared buffers until
//! their turn to be hashed.
//!
//! [`PendingReply`]: contentauth_sans_io_core::PendingReply
//!
//! # Memory
//!
//! At most [`WINDOW`] chunks are in play at once (requested but not yet
//! folded), bounding peak memory at `WINDOW × CHUNK_SIZE` no matter how
//! large the asset is.

use std::{
    collections::VecDeque,
    future::{poll_fn, Future},
    pin::Pin,
    task::Poll,
};

use contentauth_c2pa_primitives::{hash::Hasher, ByteRange, Bytes, HashAlgorithm, StreamId};
use contentauth_sans_io_core::{Host, PendingReply, ProtocolError};

use crate::{
    error::Error,
    request::{BuilderHostReply, BuilderRequest},
};

/// Bytes requested per chunk.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Maximum chunks in play (outstanding or arrived but not yet folded) at
/// any moment.
///
/// This is what lets the host overlap reads while keeping memory bounded.
const WINDOW: usize = 8;

/// Hashes `ranges` of `stream`, in order, from chunks the host reads.
pub(crate) async fn hash(
    host: &Host<BuilderRequest>,
    stream: StreamId,
    algorithm: HashAlgorithm,
    ranges: &[ByteRange],
) -> Result<Vec<u8>, Error> {
    hash_with_limits(host, stream, algorithm, ranges, CHUNK_SIZE, WINDOW).await
}

/// [`hash`] with explicit chunking limits, so tests can drive many chunks
/// through a small window.
async fn hash_with_limits(
    host: &Host<BuilderRequest>,
    stream: StreamId,
    algorithm: HashAlgorithm,
    ranges: &[ByteRange],
    chunk_size: u64,
    window: usize,
) -> Result<Vec<u8>, Error> {
    let mut chunks = ranges
        .iter()
        .flat_map(|range| chunks_of(*range, chunk_size));
    let mut hasher = Hasher::new(algorithm);
    let mut in_flight: VecDeque<(ByteRange, PendingReply<BuilderRequest>, Option<Bytes>)> =
        VecDeque::new();

    loop {
        while in_flight.len() < window.max(1) {
            let Some(range) = chunks.next() else { break };
            let pending = host.request(BuilderRequest::AssetBytes { stream, range });
            in_flight.push_back((range, pending, None));
        }

        if in_flight.is_empty() {
            return Ok(hasher.finish());
        }

        let bytes = poll_fn(|cx| {
            for (range, pending, buffered) in &mut in_flight {
                if buffered.is_some() {
                    continue;
                }
                let id = pending.id();
                let bytes = match Pin::new(pending).poll(cx) {
                    Poll::Pending => continue,
                    Poll::Ready(BuilderHostReply::AssetBytes(bytes)) => bytes,
                    Poll::Ready(BuilderHostReply::Failed(source)) => {
                        return Poll::Ready(Err(Error::HostFailure { id, source }));
                    }
                    Poll::Ready(_) => {
                        return Poll::Ready(Err(ProtocolError::ReplyMismatch {
                            id,
                            expected: "AssetBytes",
                        }
                        .into()));
                    }
                };
                let actual = bytes.len() as u64;
                if actual != range.len {
                    return Poll::Ready(Err(Error::AssetBytesLengthMismatch {
                        range: *range,
                        actual,
                    }));
                }
                *buffered = Some(bytes);
            }
            match in_flight.front_mut().and_then(|(_, _, bytes)| bytes.take()) {
                Some(bytes) => Poll::Ready(Ok(bytes)),
                None => Poll::Pending,
            }
        })
        .await?;
        in_flight.pop_front();
        hasher.update(&bytes);
    }
}

/// Splits `range` into consecutive chunks of at most `chunk_size` bytes.
fn chunks_of(range: ByteRange, chunk_size: u64) -> impl Iterator<Item = ByteRange> {
    let end = range.start.saturating_add(range.len);
    let chunk_size = chunk_size.max(1);

    std::iter::successors(Some(range.start), move |offset| {
        offset.checked_add(chunk_size)
    })
    .take_while(move |offset| *offset < end)
    .map(move |start| ByteRange {
        start,
        len: chunk_size.min(end - start),
    })
}

/// Computes the ranges an asset hash covers: everything outside the
/// exclusions.
///
/// Returns `None` if the exclusions are not a sane description of the
/// asset — overlapping, or reaching past its end.
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

    use contentauth_c2pa_primitives::HostError;
    use contentauth_sans_io_core::{CoroutineWorkflow, RequestId, Step, Workflow};

    use super::*;

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

    type HashSession = CoroutineWorkflow<BuilderRequest, Vec<u8>, Error>;

    /// A hash over `ranges` of a 1000-byte asset, run as a session of its
    /// own: an `async fn` sub-workflow needs no session around it to be
    /// tested.
    fn session(ranges: &[ByteRange], chunk_size: u64, window: usize) -> HashSession {
        let ranges = ranges.to_vec();
        CoroutineWorkflow::new(move |host| async move {
            hash_with_limits(
                &host,
                StreamId::new(0),
                HashAlgorithm::Sha256,
                &ranges,
                chunk_size,
                window,
            )
            .await
        })
    }

    fn asset() -> Vec<u8> {
        (0..1000u32).map(|i| (i % 251) as u8).collect()
    }

    /// Drives a hash to completion, answering each round's outstanding
    /// chunks in the order the given permutation names, and returns the
    /// digest.
    fn run(order: impl Fn(usize) -> Vec<usize>, chunk_size: u64, window: usize) -> Vec<u8> {
        let asset = asset();
        let mut session = session(&[range(0, 1000)], chunk_size, window);

        loop {
            if session.advance().unwrap() == Step::Complete {
                return session.finish().unwrap();
            }

            let pending: Vec<(RequestId, ByteRange)> = session
                .outstanding_requests()
                .iter()
                .map(|request| match request.kind {
                    BuilderRequest::AssetBytes { range, .. } => (request.id, range),
                    _ => unreachable!(),
                })
                .collect();

            // Advance after each individual reply, so a later chunk really
            // does arrive before an earlier one and has to wait its turn.
            for position in order(pending.len()) {
                let (id, range) = pending[position];
                let start = range.start as usize;
                let bytes = asset[start..start + range.len as usize].to_vec();
                session
                    .fulfill(id, BuilderHostReply::AssetBytes(bytes.into()))
                    .unwrap();
                session.advance().unwrap();
            }
        }
    }

    #[test]
    fn out_of_order_fulfilment_yields_an_identical_digest() {
        let expected = HashAlgorithm::Sha256.digest(&asset());

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
        let mut session = session(&[range(0, 1000)], 100, 3);

        session.advance().unwrap();
        assert_eq!(
            session.outstanding_requests().len(),
            3,
            "issuing must stop at the window"
        );

        // Answer the newest chunk only: it cannot be folded yet, so the
        // window stays full and nothing new is issued.
        let last = session.outstanding_requests()[2].id;
        session
            .fulfill(last, BuilderHostReply::AssetBytes(vec![0u8; 100].into()))
            .unwrap();
        assert_eq!(session.advance().unwrap(), Step::AwaitHost);

        assert_eq!(
            session.outstanding_requests().len(),
            2,
            "an arrived but unfolded chunk still occupies the window"
        );
    }

    #[test]
    fn several_ranges_are_hashed_as_one_in_order() {
        let asset = asset();
        let mut session = session(&[range(0, 10), range(900, 100)], 64, 8);

        session.advance().unwrap();
        let requested: Vec<ByteRange> = session
            .outstanding_requests()
            .iter()
            .map(|request| match request.kind {
                BuilderRequest::AssetBytes { range, .. } => range,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(requested, [range(0, 10), range(900, 64), range(964, 36)]);

        for request in session.outstanding_requests().to_vec() {
            let BuilderRequest::AssetBytes { range, .. } = request.kind else {
                unreachable!()
            };
            let start = range.start as usize;
            let bytes = asset[start..start + range.len as usize].to_vec();
            session
                .fulfill(request.id, BuilderHostReply::AssetBytes(bytes.into()))
                .unwrap();
        }

        assert_eq!(session.advance().unwrap(), Step::Complete);
        let mut included = asset[..10].to_vec();
        included.extend_from_slice(&asset[900..]);
        assert_eq!(
            session.finish().unwrap(),
            HashAlgorithm::Sha256.digest(&included)
        );
    }

    #[test]
    fn a_wrong_length_reply_is_rejected() {
        let mut session = session(&[range(0, 100)], 100, 4);
        session.advance().unwrap();
        let id = session.outstanding_requests()[0].id;

        // One byte short: tolerating this would shift every later byte.
        session
            .fulfill(id, BuilderHostReply::AssetBytes(vec![0u8; 99].into()))
            .unwrap();

        assert!(matches!(
            session.advance(),
            Err(Error::AssetBytesLengthMismatch { actual: 99, .. })
        ));
    }

    #[test]
    fn a_mismatched_stored_reply_is_defensively_rejected() {
        let mut session = session(&[range(0, 100)], 100, 4);
        session.advance().unwrap();
        let id = session.outstanding_requests()[0].id;

        // Bypass `fulfill`'s payload validation to reach the hash's own
        // defence-in-depth check.
        session.fulfill_unchecked(id, BuilderHostReply::AssetLength(0));

        assert!(matches!(
            session.advance(),
            Err(Error::Protocol(ProtocolError::ReplyMismatch {
                expected: "AssetBytes",
                ..
            }))
        ));
    }

    #[test]
    fn a_host_failure_propagates() {
        let mut session = session(&[range(0, 100)], 100, 4);
        session.advance().unwrap();
        let id = session.outstanding_requests()[0].id;
        session
            .fulfill(id, BuilderHostReply::Failed(HostError::new("unreadable")))
            .unwrap();

        assert!(matches!(session.advance(), Err(Error::HostFailure { .. })));
    }

    #[test]
    fn a_later_chunk_failure_is_reported_without_waiting_for_earlier_chunks() {
        let mut session = session(&[range(0, 1000)], 100, 4);
        session.advance().unwrap();
        let id = session.outstanding_requests()[2].id;
        session
            .fulfill(id, BuilderHostReply::Failed(HostError::new("unreadable")))
            .unwrap();
        assert!(matches!(
            session.advance(),
            Err(Error::HostFailure { id: failed, .. }) if failed == id
        ));
        assert!(session.outstanding_requests().is_empty());
    }

    #[test]
    fn a_later_chunk_with_the_wrong_length_is_reported_immediately() {
        for len in [99, 101] {
            let mut session = session(&[range(0, 1000)], 100, 4);
            session.advance().unwrap();
            let id = session.outstanding_requests()[2].id;
            session
                .fulfill(id, BuilderHostReply::AssetBytes(vec![0; len].into()))
                .unwrap();
            assert!(matches!(
                session.advance(),
                Err(Error::AssetBytesLengthMismatch { range: failed, actual })
                    if failed == range(200, 100) && actual == len as u64
            ));
        }
    }

    #[test]
    fn an_empty_range_set_completes_immediately() {
        let mut session = session(&[], 100, 4);
        assert_eq!(session.advance().unwrap(), Step::Complete);
        assert_eq!(session.finish().unwrap(), HashAlgorithm::Sha256.digest(b""));
    }
}
