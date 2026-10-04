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

//! The request/reply vocabulary spoken between
//! [`BuilderSession`](crate::BuilderSession) and its host.
//!
//! When the session cannot make further progress synchronously, it issues
//! one or more requests through the [`contentauth_state_machine`] engine —
//! see [`contentauth_state_machine::HostRequest`]. The host services them
//! and reports each outcome back via
//! [`Session::fulfill`](contentauth_state_machine::Session::fulfill) with a
//! matching [`BuilderHostReply`] (or [`BuilderHostReply::Failed`]).

use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, HostError, SigningAlg, StreamId};
use contentauth_state_machine::Request;

/// The operations a builder session may ask its host to perform.
///
/// Each variant documents the [`BuilderHostReply`] variant that fulfills
/// it. Any request may also be fulfilled with [`BuilderHostReply::Failed`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum BuilderRequest {
    /// Embed `placeholder` — a complete C2PA manifest store, zero-filled
    /// wherever its content is still pending — into the asset, replacing
    /// any existing manifest store.
    ///
    /// The host owns all knowledge of the container format (JPEG, PNG,
    /// BMFF, …), exactly as [`ReadRequest::ManifestStore`] does for
    /// reading — typically by way of a `contentauth-c2pa-format` handler.
    /// Reply with [`BuilderHostReply::PlaceholderReserved`], naming the
    /// byte ranges the hard binding must exclude — usually the one range
    /// of the container structure that now carries the placeholder,
    /// *framing included* (for a JPEG, the whole run of `APP11` segments,
    /// markers and headers and all), but exactly what the container
    /// format's specification calls for: TIFF excludes a length field and
    /// the store, which are not adjacent. They become the hard binding's
    /// exclusions, so together they may total more than the placeholder
    /// but never less.
    ///
    /// [`ReadRequest::ManifestStore`]: https://docs.rs/contentauth-c2pa-reader/latest/contentauth_c2pa_reader/enum.ReadRequest.html#variant.ManifestStore
    ReservePlaceholder {
        /// The asset stream to embed the placeholder into.
        stream: StreamId,

        /// The placeholder bytes to embed verbatim.
        placeholder: Vec<u8>,
    },

    /// Report the total length of a stream, in bytes.
    ///
    /// Needed once the placeholder has been embedded: the hard binding
    /// covers everything the asset now contains outside the reserved
    /// range, so the session must know where the asset ends. Reply with
    /// [`BuilderHostReply::AssetLength`].
    AssetLength {
        /// The stream to measure.
        stream: StreamId,
    },

    /// Read a range of bytes from a stream and return them to the crate.
    ///
    /// Used to feed the asset — now containing the embedded placeholder —
    /// into this crate's internal hashing, to compute the hard binding.
    /// Reply with [`BuilderHostReply::AssetBytes`].
    AssetBytes {
        /// The stream to read from.
        stream: StreamId,

        /// The byte range to read.
        range: ByteRange,
    },

    /// Sign `data` — a COSE `Sig_structure` — with `alg`.
    ///
    /// Mirrors `c2pa_raw_crypto::RawSigner::sign`: the host is responsible
    /// for however it holds or reaches the signing key. Reply with
    /// [`BuilderHostReply::Signature`], carrying exactly `alg`'s fixed
    /// signature length, or the configured RSA modulus size for an
    /// RSASSA-PSS algorithm (see
    /// [`BuilderSettings::rsa_signature_len`](crate::BuilderSettings::rsa_signature_len)).
    Sign {
        /// The algorithm to sign with.
        alg: SigningAlg,

        /// The exact bytes to sign (a COSE `Sig_structure`).
        data: Vec<u8>,
    },

    /// Obtain an RFC 3161 countersignature over `digest`.
    ///
    /// The host is responsible for the full timestamp authority round
    /// trip — building the request, sending it, and unwrapping the
    /// response — and for reporting the outcome as a bare `TimeStampToken`
    /// (not the full `TimeStampResp` it arrives in). Reply with
    /// [`BuilderHostReply::Timestamp`].
    Timestamp {
        /// The digest the timestamp must cover.
        digest: Vec<u8>,

        /// The algorithm `digest` was computed with.
        hash_alg: HashAlgorithm,
    },

    /// Replace the previously reserved placeholder with the final manifest
    /// bytes.
    ///
    /// `manifest` is guaranteed byte-identical in length to the
    /// placeholder embedded by an earlier [`Self::ReservePlaceholder`], so
    /// the container's framing around it need not change. Reply with
    /// [`BuilderHostReply::ManifestCommitted`].
    CommitManifest {
        /// The asset stream to patch.
        stream: StreamId,

        /// The hard binding's exclusions, from
        /// [`BuilderHostReply::PlaceholderReserved`].
        exclusions: Vec<ByteRange>,

        /// The final manifest store bytes.
        manifest: Vec<u8>,
    },
}

impl Request for BuilderRequest {
    type Reply = BuilderHostReply;

    /// Describes the reply payload this request expects, for diagnostics.
    fn expected_reply(&self) -> &'static str {
        match self {
            Self::ReservePlaceholder { .. } => "PlaceholderReserved",
            Self::AssetLength { .. } => "AssetLength",
            Self::AssetBytes { .. } => "AssetBytes",
            Self::Sign { .. } => "Signature",
            Self::Timestamp { .. } => "Timestamp",
            Self::CommitManifest { .. } => "ManifestCommitted",
        }
    }

    /// Reports whether `reply` is an acceptable fulfillment of this
    /// request.
    fn accepts(&self, reply: &BuilderHostReply) -> bool {
        matches!(
            (self, reply),
            (_, BuilderHostReply::Failed(_))
                | (
                    Self::ReservePlaceholder { .. },
                    BuilderHostReply::PlaceholderReserved(_)
                )
                | (Self::AssetLength { .. }, BuilderHostReply::AssetLength(_))
                | (Self::AssetBytes { .. }, BuilderHostReply::AssetBytes(_))
                | (Self::Sign { .. }, BuilderHostReply::Signature(_))
                | (Self::Timestamp { .. }, BuilderHostReply::Timestamp(_))
                | (
                    Self::CommitManifest { .. },
                    BuilderHostReply::ManifestCommitted
                )
        )
    }
}

/// The host's report of the outcome of one host request.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuilderHostReply {
    /// Answers [`BuilderRequest::ReservePlaceholder`]: the byte ranges the
    /// hard binding excludes, in ascending order and not overlapping —
    /// the container structure now carrying the placeholder, framing
    /// included, and anything else the format's specification excludes.
    /// At most [`MAX_EXCLUSIONS`](crate::MAX_EXCLUSIONS) of them.
    PlaceholderReserved(Vec<ByteRange>),

    /// Answers [`BuilderRequest::AssetLength`]: the stream's total length
    /// in bytes.
    AssetLength(u64),

    /// Answers [`BuilderRequest::AssetBytes`]: the requested bytes.
    AssetBytes(Vec<u8>),

    /// Answers [`BuilderRequest::Sign`]: the raw signature bytes.
    Signature(Vec<u8>),

    /// Answers [`BuilderRequest::Timestamp`]: the bare `TimeStampToken`
    /// bytes.
    Timestamp(Vec<u8>),

    /// Answers [`BuilderRequest::CommitManifest`]: the host has patched
    /// the asset in place.
    ManifestCommitted,

    /// Reports that the host could not perform the requested operation.
    /// Valid for any request.
    Failed(HostError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;

    /// One instance of every request kind.
    fn all_requests() -> Vec<BuilderRequest> {
        let stream = StreamId::new(0);
        let range = ByteRange { start: 0, len: 16 };

        vec![
            BuilderRequest::ReservePlaceholder {
                stream,
                placeholder: vec![0; 4],
            },
            BuilderRequest::AssetLength { stream },
            BuilderRequest::AssetBytes { stream, range },
            BuilderRequest::Sign {
                alg: SigningAlg::Es256,
                data: vec![1, 2, 3],
            },
            BuilderRequest::Timestamp {
                digest: vec![4, 5, 6],
                hash_alg: HashAlgorithm::Sha256,
            },
            BuilderRequest::CommitManifest {
                stream,
                exclusions: vec![range],
                manifest: vec![0; 4],
            },
        ]
    }

    /// One instance of every reply, paired with the `expected_reply`
    /// string of the request(s) it answers (empty for `Failed`, which
    /// answers anything).
    fn all_replies() -> Vec<(BuilderHostReply, &'static str)> {
        vec![
            (
                BuilderHostReply::PlaceholderReserved(vec![ByteRange { start: 0, len: 4 }]),
                "PlaceholderReserved",
            ),
            (BuilderHostReply::AssetLength(1024), "AssetLength"),
            (BuilderHostReply::AssetBytes(vec![1]), "AssetBytes"),
            (BuilderHostReply::Signature(vec![0; 64]), "Signature"),
            (BuilderHostReply::Timestamp(vec![9; 8]), "Timestamp"),
            (BuilderHostReply::ManifestCommitted, "ManifestCommitted"),
            (BuilderHostReply::Failed(HostError::new("nope")), ""),
        ]
    }

    /// Every request accepts exactly the reply named by its
    /// `expected_reply` string, plus `Failed`.
    #[test]
    fn accepts_matches_expected_reply_exactly() {
        for request in &all_requests() {
            for (reply, answers) in all_replies() {
                let should_accept = matches!(reply, BuilderHostReply::Failed(_))
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
