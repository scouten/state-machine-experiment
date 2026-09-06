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

//! The one request vocabulary every format operation speaks.
//!
//! A handler only ever needs to *read* an asset — it describes its output
//! rather than writing it (see the crate-level documentation) — so this
//! vocabulary is deliberately tiny, and the same for every format. An
//! orchestrating session can forward it to its own host without knowing
//! which handler issued it.

use contentauth_c2pa_primitives::{ByteRange, HostError, StreamId};
use contentauth_state_machine::{ProtocolError, Request, RequestId, SessionCore};

use crate::error::FormatError;

/// The operations a format operation may ask its host to perform.
///
/// Each variant documents the [`IoReply`] variant that fulfills it. Any
/// request may also be fulfilled with [`IoReply::Failed`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IoRequest {
    /// Read a range of bytes from a stream. Reply with [`IoReply::Bytes`],
    /// carrying exactly `range.len` bytes.
    Read {
        /// The stream to read from.
        stream: StreamId,

        /// The byte range to read.
        range: ByteRange,
    },

    /// Report the total length of a stream, in bytes. Reply with
    /// [`IoReply::Length`].
    Length {
        /// The stream to measure.
        stream: StreamId,
    },
}

impl Request for IoRequest {
    type Reply = IoReply;

    /// Describes the reply payload this request expects, for diagnostics.
    fn expected_reply(&self) -> &'static str {
        match self {
            Self::Read { .. } => "Bytes",
            Self::Length { .. } => "Length",
        }
    }

    /// Reports whether `reply` is an acceptable fulfillment of this
    /// request.
    fn accepts(&self, reply: &IoReply) -> bool {
        matches!(
            (self, reply),
            (_, IoReply::Failed(_))
                | (Self::Read { .. }, IoReply::Bytes(_))
                | (Self::Length { .. }, IoReply::Length(_))
        )
    }
}

/// The host's report of the outcome of one [`IoRequest`].
#[derive(Debug)]
#[non_exhaustive]
pub enum IoReply {
    /// Answers [`IoRequest::Read`]: the requested bytes.
    Bytes(Vec<u8>),

    /// Answers [`IoRequest::Length`]: the stream's total length in bytes.
    Length(u64),

    /// Reports that the host could not perform the requested operation.
    /// Valid for any request.
    Failed(HostError),
}

/// Consumes the reply to a [`IoRequest::Read`] for `range`, if the host has
/// provided one.
///
/// Returns `Ok(None)` while the request is still outstanding. A reply of
/// the wrong length is [`FormatError::ReadLengthMismatch`], never
/// tolerated; a [`IoReply::Failed`] is [`FormatError::HostFailure`].
///
/// For handler authors: the sequential "read a header, decide, read the
/// next thing" shape most container parsers take is exactly one of these
/// per phase.
pub fn take_bytes(
    core: &mut SessionCore<IoRequest>,
    id: RequestId,
    range: ByteRange,
) -> Result<Option<Vec<u8>>, FormatError> {
    match core.take_reply(id) {
        None => Ok(None),

        Some(IoReply::Bytes(bytes)) => {
            let actual = bytes.len() as u64;
            if actual != range.len {
                return Err(FormatError::ReadLengthMismatch { range, actual });
            }
            Ok(Some(bytes))
        }

        Some(IoReply::Failed(source)) => Err(FormatError::HostFailure { id, source }),

        // `RequestTracker::fulfill` rejects mismatched reply payloads, so
        // this arm is unreachable in practice; kept as defense in depth.
        Some(_) => Err(ProtocolError::ReplyMismatch {
            id,
            expected: "Bytes",
        }
        .into()),
    }
}

/// Consumes the reply to a [`IoRequest::Length`], if the host has provided
/// one.
///
/// Returns `Ok(None)` while the request is still outstanding.
pub fn take_length(
    core: &mut SessionCore<IoRequest>,
    id: RequestId,
) -> Result<Option<u64>, FormatError> {
    match core.take_reply(id) {
        None => Ok(None),
        Some(IoReply::Length(len)) => Ok(Some(len)),
        Some(IoReply::Failed(source)) => Err(FormatError::HostFailure { id, source }),
        Some(_) => Err(ProtocolError::ReplyMismatch {
            id,
            expected: "Length",
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn all_requests() -> Vec<IoRequest> {
        let stream = StreamId::new(0);
        vec![
            IoRequest::Read {
                stream,
                range: ByteRange { start: 0, len: 16 },
            },
            IoRequest::Length { stream },
        ]
    }

    fn all_replies() -> Vec<(IoReply, &'static str)> {
        vec![
            (IoReply::Bytes(vec![1]), "Bytes"),
            (IoReply::Length(1024), "Length"),
            (IoReply::Failed(HostError::new("nope")), ""),
        ]
    }

    /// Every request accepts exactly the reply named by its
    /// `expected_reply` string, plus `Failed`.
    #[test]
    fn accepts_matches_expected_reply_exactly() {
        for request in &all_requests() {
            for (reply, answers) in all_replies() {
                let should_accept =
                    matches!(reply, IoReply::Failed(_)) || *answers == *request.expected_reply();
                assert_eq!(
                    request.accepts(&reply),
                    should_accept,
                    "request {request:?} vs reply {reply:?}"
                );
            }
        }
    }

    #[test]
    fn take_bytes_reports_outstanding_wrong_length_and_failure() {
        let stream = StreamId::new(0);
        let range = ByteRange { start: 4, len: 3 };
        let mut core = SessionCore::default();

        let id = core.issue(IoRequest::Read { stream, range });
        assert!(take_bytes(&mut core, id, range).unwrap().is_none());

        core.fulfill(id, IoReply::Bytes(vec![0; 2])).unwrap();
        assert!(matches!(
            take_bytes(&mut core, id, range),
            Err(FormatError::ReadLengthMismatch { actual: 2, .. })
        ));

        let id = core.issue(IoRequest::Read { stream, range });
        core.fulfill(id, IoReply::Failed(HostError::new("unreadable")))
            .unwrap();
        assert!(matches!(
            take_bytes(&mut core, id, range),
            Err(FormatError::HostFailure { .. })
        ));

        let id = core.issue(IoRequest::Read { stream, range });
        core.fulfill(id, IoReply::Bytes(vec![7; 3])).unwrap();
        assert_eq!(take_bytes(&mut core, id, range).unwrap(), Some(vec![7; 3]));
    }

    #[test]
    fn take_length_reports_outstanding_and_failure() {
        let stream = StreamId::new(0);
        let mut core = SessionCore::default();

        let id = core.issue(IoRequest::Length { stream });
        assert!(take_length(&mut core, id).unwrap().is_none());
        core.fulfill(id, IoReply::Length(99)).unwrap();
        assert_eq!(take_length(&mut core, id).unwrap(), Some(99));

        let id = core.issue(IoRequest::Length { stream });
        core.fulfill(id, IoReply::Failed(HostError::new("no such stream")))
            .unwrap();
        assert!(matches!(
            take_length(&mut core, id),
            Err(FormatError::HostFailure { .. })
        ));
    }

    #[test]
    fn a_mismatched_stored_reply_is_defensively_rejected() {
        let stream = StreamId::new(0);
        let range = ByteRange { start: 0, len: 1 };
        let mut core = SessionCore::default();

        let id = core.issue(IoRequest::Read { stream, range });
        core.fulfill_unchecked(id, IoReply::Length(1));
        assert!(matches!(
            take_bytes(&mut core, id, range),
            Err(FormatError::Protocol(ProtocolError::ReplyMismatch {
                expected: "Bytes",
                ..
            }))
        ));

        let id = core.issue(IoRequest::Length { stream });
        core.fulfill_unchecked(id, IoReply::Bytes(vec![]));
        assert!(matches!(
            take_length(&mut core, id),
            Err(FormatError::Protocol(ProtocolError::ReplyMismatch {
                expected: "Length",
                ..
            }))
        ));
    }
}
