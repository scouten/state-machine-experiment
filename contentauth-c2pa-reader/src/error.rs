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

//! Error types for the sans-I/O reader.

use contentauth_state_machine::{ProtocolError, RequestId};

/// Errors surfaced by [`ReadSession`](crate::ReadSession).
///
/// Two broad families live here:
///
/// * [`Self::Protocol`] means the host used the session API incorrectly
///   (fulfilling an unknown request, replying with the wrong payload type,
///   driving a completed session, …) — see
///   [`contentauth_state_machine::ProtocolError`]. These indicate a bug in
///   the host binding, not a problem with the asset.
/// * The rest mean the workflow itself cannot proceed (a host operation
///   failed and the workflow cannot continue without it, or — in this
///   experimental crate — the required logic is not yet implemented).
///
/// Note that most _validation_ problems (invalid signatures, hash
/// mismatches, untrusted credentials, …) are deliberately **not** errors:
/// they are recorded as validation statuses in the [`ReadReport`] so that a
/// read workflow always produces a complete report when possible. This
/// mirrors the c2pa-rs philosophy of reporting validation state rather than
/// failing early.
///
/// [`ReadReport`]: crate::read::ReadReport
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The host used the [`contentauth_state_machine::Session`] API
    /// incorrectly.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// The manifest store's JUMBF structure could not be read.
    ///
    /// This is structural damage, not a validation finding: the bytes the
    /// host supplied are not a well-formed manifest store at all.
    #[error("malformed manifest store: {0}")]
    MalformedManifestStore(#[from] jumbf::parser::Error),

    /// The bytes parsed as JUMBF, but the outermost box is not a C2PA
    /// manifest store.
    #[error("not a C2PA manifest store")]
    NotAManifestStore,

    /// A manifest within the store was structurally incomplete.
    #[error("malformed manifest {manifest:?}: {reason}")]
    MalformedManifest {
        /// JUMBF label of the offending manifest, empty if it had none.
        manifest: String,

        /// What was wrong with it.
        reason: &'static str,
    },

    /// One of the trust anchors in the session's settings is not a
    /// well-formed X.509 certificate.
    ///
    /// A configuration mistake rather than a validation finding, and so an
    /// error: an anchor that cannot be decoded cannot be consulted, and
    /// skipping it would silently downgrade every manifest that should have
    /// chained to it.
    #[error("{list} anchor {index} is not a valid certificate: {source}", list = if *timestamp { "timestamp trust" } else { "trust" })]
    MalformedTrustAnchor {
        /// Position of the offending anchor within its list.
        index: usize,

        /// True if it came from
        /// [`ReadSettings::timestamp_trust_anchors`] rather than
        /// [`ReadSettings::trust_anchors`].
        ///
        /// [`ReadSettings::timestamp_trust_anchors`]: crate::read::ReadSettings::timestamp_trust_anchors
        /// [`ReadSettings::trust_anchors`]: crate::read::ReadSettings::trust_anchors
        timestamp: bool,

        /// Why it could not be decoded.
        source: crate::cert::CertError,
    },

    /// A manifest's claim could not be decoded.
    #[error("malformed claim in manifest {manifest:?}: {source}")]
    MalformedClaim {
        /// JUMBF label of the manifest carrying the claim.
        manifest: String,

        /// Why the claim could not be decoded.
        source: crate::claim::ClaimError,
    },

    /// The host returned a different number of bytes than the range it was
    /// asked for.
    ///
    /// This is never tolerated: a short or long read would shift every
    /// subsequent byte of a streamed hash, silently producing a digest over
    /// the wrong content.
    #[error("host returned {actual} bytes for a request of {} at offset {}", range.len, range.start)]
    AssetBytesLengthMismatch {
        /// The range that was requested.
        range: crate::types::ByteRange,

        /// How many bytes the host actually returned.
        actual: u64,
    },

    /// A streamed asset hash was finalized before every byte was folded in.
    ///
    /// This indicates a bug in this crate's own chunk bookkeeping rather
    /// than anything wrong with the asset.
    #[error("asset hash folded {folded} of {expected} bytes")]
    IncompleteAssetHash {
        /// Bytes folded into the hasher.
        folded: u64,

        /// Bytes that should have been folded.
        expected: u64,
    },

    /// A host operation failed and the workflow cannot continue without it.
    #[error("host reported failure for {id}: {source}")]
    HostFailure {
        /// ID of the request the host could not fulfill.
        id: RequestId,

        /// Failure description reported by the host.
        source: HostError,
    },

    /// The code path is not yet implemented in this experimental crate.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}

/// Describes a failure that occurred in the host environment while servicing
/// a host request.
///
/// The host reports failures by fulfilling a request with
/// [`HostReply::Failed`]. Depending on the request and the workflow, the
/// crate may be able to continue (recording a validation status) or may
/// terminate the session with [`Error::HostFailure`].
///
/// [`HostReply::Failed`]: crate::request::HostReply::Failed
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
#[non_exhaustive]
pub struct HostError {
    /// Human-readable description of the failure, intended for logs and
    /// error reports.
    pub message: String,
}

impl HostError {
    /// Creates a new host error with the given description.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
