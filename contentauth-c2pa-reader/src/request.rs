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

//! The request/reply vocabulary spoken between [`ReadSession`](crate::ReadSession)
//! and its host.
//!
//! When the session cannot make further progress synchronously, it issues
//! one or more requests through the
//! [`contentauth_state_machine`] engine — see
//! [`contentauth_state_machine::HostRequest`]. The host services them —
//! possibly concurrently, using whatever async machinery its runtime
//! provides — and reports each outcome back via
//! [`Session::fulfill`](contentauth_state_machine::Session::fulfill) with a
//! matching [`ReadHostReply`] (or [`ReadHostReply::Failed`]).
//!
//! [`ReadRequest`] implements [`contentauth_state_machine::Request`], which
//! is what lets the engine's [`contentauth_state_machine::RequestTracker`]
//! validate replies without knowing what the requests mean.

use contentauth_c2pa_primitives::{ByteRange, StreamId};
use contentauth_state_machine::Request;

use crate::error::HostError;

/// The operations a read session may ask its host to perform.
///
/// Each variant documents the [`ReadHostReply`] variant that fulfills it. Any
/// request may also be fulfilled with [`ReadHostReply::Failed`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ReadRequest {
    /// Locate the C2PA manifest store within the asset's container format
    /// and return its raw (JUMBF) bytes.
    ///
    /// The host owns all knowledge of the container format (JPEG, PNG, BMFF,
    /// …). Reply with [`ReadHostReply::ManifestStore`]; use `None` if the asset
    /// contains no manifest store.
    ManifestStore {
        /// The asset stream to inspect.
        stream: StreamId,
    },

    /// Read a range of bytes from a stream and return them to the crate.
    ///
    /// Used to feed asset bytes into the crate's internal hashing (hard
    /// binding validation). Reply with [`ReadHostReply::AssetBytes`].
    AssetBytes {
        /// The stream to read from.
        stream: StreamId,

        /// The byte range to read.
        range: ByteRange,
    },

    /// Report the total length of a stream, in bytes.
    ///
    /// Needed to hash an asset: the hard binding names the ranges to
    /// *exclude*, so the crate must know where the asset ends to work out
    /// what to include. Reply with [`ReadHostReply::AssetLength`], or with
    /// [`ReadHostReply::Failed`] if no asset is available — reading a detached
    /// manifest, say — in which case the hard binding is reported as
    /// unchecked rather than failed.
    AssetLength {
        /// The stream to measure.
        stream: StreamId,
    },

    /// Report the current wall-clock time.
    ///
    /// This crate reads no clock of its own; certificate validity windows
    /// and similar checks use time supplied by the host. Reply with
    /// [`ReadHostReply::CurrentDateTime`].
    CurrentDateTime,
}

impl Request for ReadRequest {
    type Reply = ReadHostReply;

    /// Describes the reply payload this request expects, for diagnostics.
    fn expected_reply(&self) -> &'static str {
        match self {
            Self::ManifestStore { .. } => "ManifestStore",
            Self::AssetBytes { .. } => "AssetBytes",
            Self::AssetLength { .. } => "AssetLength",
            Self::CurrentDateTime => "CurrentDateTime",
        }
    }

    /// Reports whether `reply` is an acceptable fulfillment of this request.
    fn accepts(&self, reply: &ReadHostReply) -> bool {
        matches!(
            (self, reply),
            (_, ReadHostReply::Failed(_))
                | (Self::ManifestStore { .. }, ReadHostReply::ManifestStore(_))
                | (Self::AssetBytes { .. }, ReadHostReply::AssetBytes(_))
                | (Self::AssetLength { .. }, ReadHostReply::AssetLength(_))
                | (Self::CurrentDateTime, ReadHostReply::CurrentDateTime(_))
        )
    }
}

/// The host's report of the outcome of one host request.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadHostReply {
    /// Answers [`ReadRequest::ManifestStore`]: the manifest store bytes, or
    /// `None` if the asset contains no manifest store.
    ManifestStore(Option<Vec<u8>>),

    /// Answers [`ReadRequest::AssetBytes`]: the requested bytes.
    AssetBytes(Vec<u8>),

    /// Answers [`ReadRequest::AssetLength`]: the stream's total length in
    /// bytes.
    AssetLength(u64),

    /// Answers [`ReadRequest::CurrentDateTime`]: seconds since the Unix
    /// epoch (UTC).
    CurrentDateTime(i64),

    /// Reports that the host could not perform the requested operation.
    /// Valid for any request.
    Failed(HostError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;

    /// One instance of every request kind.
    fn all_requests() -> Vec<ReadRequest> {
        let stream = StreamId::new(0);
        let range = ByteRange { start: 0, len: 16 };

        vec![
            ReadRequest::ManifestStore { stream },
            ReadRequest::AssetBytes { stream, range },
            ReadRequest::AssetLength { stream },
            ReadRequest::CurrentDateTime,
        ]
    }

    /// One instance of every reply, paired with the `expected_reply` string
    /// of the request(s) it answers (empty for `Failed`, which answers
    /// anything).
    fn all_replies() -> Vec<(ReadHostReply, &'static str)> {
        vec![
            (ReadHostReply::ManifestStore(None), "ManifestStore"),
            (ReadHostReply::AssetBytes(vec![1]), "AssetBytes"),
            (ReadHostReply::AssetLength(1024), "AssetLength"),
            (
                ReadHostReply::CurrentDateTime(1_756_400_000),
                "CurrentDateTime",
            ),
            (ReadHostReply::Failed(HostError::new("nope")), ""),
        ]
    }

    /// Every request accepts exactly the reply named by its
    /// `expected_reply` string, plus `Failed`.
    #[test]
    fn accepts_matches_expected_reply_exactly() {
        for request in &all_requests() {
            for (reply, answers) in all_replies() {
                let should_accept = matches!(reply, ReadHostReply::Failed(_))
                    || *answers == *request.expected_reply();
                assert_eq!(
                    request.accepts(&reply),
                    should_accept,
                    "request {request:?} vs reply {reply:?}"
                );
            }
        }
    }
}
