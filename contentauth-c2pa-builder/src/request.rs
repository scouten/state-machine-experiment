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

/// What a [`BuilderRequest::Sign`] is a signature *for*.
///
/// The host answers a request with a signature whatever the purpose; the
/// purpose exists so that it can pick the key.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignPurpose {
    /// The claim signature, made with the key whose certificates are
    /// [`BuilderSettings::certificates`](crate::BuilderSettings::certificates).
    Claim,

    /// The signature of a CAWG identity assertion, made with the key of
    /// the credential in the matching
    /// [`BuilderSettings::identities`](crate::BuilderSettings::identities)
    /// entry.
    Identity {
        /// The identity assertion's label: `cawg.identity` for the first
        /// entry, `cawg.identity__1` for the second, and so on.
        label: String,
    },
}

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
    /// A host that writes the asset itself can save the session a second
    /// pass over it: hash the asset with `hash_alg` *as it writes* —
    /// everything outside the ranges it reports, in order — and put the
    /// digest in the reply ([`BuilderHostReply::PlaceholderReserved`]'s
    /// `hash`). The session then signs at once, without asking for
    /// [`Self::AssetLength`] or [`Self::AssetBytes`]. A host that does
    /// not (one that cannot hash as it goes, or does not own the bytes)
    /// leaves `hash` empty and answers those requests as before.
    ///
    /// [`ReadRequest::ManifestStore`]: https://docs.rs/contentauth-c2pa-reader/latest/contentauth_c2pa_reader/enum.ReadRequest.html#variant.ManifestStore
    ReservePlaceholder {
        /// The asset stream to embed the placeholder into.
        stream: StreamId,

        /// The placeholder bytes to embed verbatim.
        placeholder: Vec<u8>,

        /// The algorithm the hard binding is computed with: the one a
        /// host that supplies the digest itself must use.
        hash_alg: HashAlgorithm,
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
        /// What is being signed, and so whose key is wanted.
        ///
        /// A host with a single key can ignore this. One that holds
        /// several — an identity assertion's signer is generally not the
        /// claim's — chooses by it.
        purpose: SignPurpose,

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
                    BuilderHostReply::PlaceholderReserved { .. }
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
    ///
    /// `hash` is optional: the digest, under the request's `hash_alg`, of
    /// every byte of the asset *outside* `exclusions`, in order, as the
    /// asset now stands with the placeholder in it. A host that computed
    /// it while writing the asset supplies it and spares the session a
    /// pass over the asset; with `None`, the session asks for the asset's
    /// length and bytes and hashes them itself. The session signs whatever
    /// digest it is given — the host that wrote the bytes is the one
    /// party who knows what they are — but refuses one of the wrong
    /// length.
    PlaceholderReserved {
        /// The ranges the hard binding excludes.
        exclusions: Vec<ByteRange>,

        /// The digest of the rest of the asset, if the host computed it.
        hash: Option<Vec<u8>>,
    },

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
                hash_alg: HashAlgorithm::Sha256,
            },
            BuilderRequest::AssetLength { stream },
            BuilderRequest::AssetBytes { stream, range },
            BuilderRequest::Sign {
                purpose: SignPurpose::Claim,
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
                BuilderHostReply::PlaceholderReserved {
                    exclusions: vec![ByteRange { start: 0, len: 4 }],
                    hash: None,
                },
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
