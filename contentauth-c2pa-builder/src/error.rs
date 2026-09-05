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

//! Error types for the sans-I/O builder.

use contentauth_c2pa_primitives::{HostError, SigningAlg};
use contentauth_state_machine::{ProtocolError, RequestId};

/// Errors surfaced by [`BuilderSession`](crate::BuilderSession).
///
/// Unlike [`contentauth_c2pa_reader`](https://docs.rs/contentauth-c2pa-reader),
/// which treats most problems as validation findings so a read always
/// completes with a report, every host failure here is fatal: an
/// incomplete or wrongly bound manifest is far more consequential to
/// persist than an incomplete read report, so this session fails outright
/// rather than degrading silently.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The host used the [`contentauth_state_machine::Session`] API
    /// incorrectly.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// [`BuilderSettings::signing_alg`](crate::BuilderSettings::signing_alg)
    /// is an RSASSA-PSS algorithm, whose signature length depends on the
    /// signing key's modulus size, and
    /// [`BuilderSettings::rsa_signature_len`](crate::BuilderSettings::rsa_signature_len)
    /// was not supplied.
    #[error(
        "signing algorithm {0:?} needs an explicit signature length (see \
         `BuilderSettings::rsa_signature_len`)"
    )]
    MissingRsaSignatureLen(SigningAlg),

    /// [`BuilderSettings::certificates`](crate::BuilderSettings::certificates)
    /// was empty.
    #[error("no signing certificate supplied (see `BuilderSettings::certificates`)")]
    NoCertificates,

    /// [`BuilderSettings::claim_generator_info`](crate::BuilderSettings::claim_generator_info)
    /// did not name exactly one generator.
    ///
    /// A v1 simplification: c2pa-rs itself requires exactly one for v2
    /// claims, and this crate does not yet support more than one for any
    /// claim version.
    #[error("exactly one claim_generator_info entry is required, found {0}")]
    InvalidGeneratorInfoCount(usize),

    /// The host reported a placeholder byte range, or an asset length,
    /// that cannot be used to compute a hard binding.
    #[error("host-reported range is unusable: {0}")]
    PlaceholderRangeInvalid(&'static str),

    /// The host returned a different number of bytes than the range it was
    /// asked for.
    ///
    /// Never tolerated: a short or long read would shift every subsequent
    /// byte of the hard-binding hash, silently producing a digest over the
    /// wrong content.
    #[error(
        "host returned {actual} bytes for a request of {} at offset {}",
        range.len, range.start
    )]
    AssetBytesLengthMismatch {
        /// The range that was requested.
        range: contentauth_c2pa_primitives::ByteRange,

        /// How many bytes the host actually returned.
        actual: u64,
    },

    /// A streamed asset hash was finalized before every byte was folded in.
    ///
    /// Indicates a bug in this crate's own chunk bookkeeping rather than
    /// anything wrong with the asset.
    #[error("asset hash folded {folded} of {expected} bytes")]
    IncompleteAssetHash {
        /// Bytes folded into the hasher.
        folded: u64,

        /// Bytes that should have been folded.
        expected: u64,
    },

    /// The host's signature was not exactly the expected length.
    #[error("host returned a signature of {actual} bytes; expected exactly {expected}")]
    SignatureLengthMismatch {
        /// The length this algorithm (and settings) require.
        expected: usize,

        /// The length the host actually returned.
        actual: usize,
    },

    /// The RFC 3161 token the host returned is larger than the configured
    /// reserve.
    #[error(
        "timestamp token is {actual} bytes, which exceeds the configured reserve of {reserve} \
         bytes"
    )]
    TimestampTooLarge {
        /// The configured reserve
        /// ([`TimestampSettings::reserve_size`](crate::TimestampSettings::reserve_size)).
        reserve: usize,

        /// The token's actual length.
        actual: usize,
    },

    /// A host operation failed and the workflow cannot continue without
    /// it.
    #[error("host reported failure for {id}: {source}")]
    HostFailure {
        /// ID of the request the host could not fulfill.
        id: RequestId,

        /// Failure description reported by the host.
        source: HostError,
    },

    /// A placeholder's real encoding did not total the same length as its
    /// reserved size.
    ///
    /// Indicates a bug in this crate's own two-pass size accounting, not a
    /// problem with the caller's settings or the asset.
    #[error("internal invariant violated: {0}")]
    PlaceholderSizeMismatch(&'static str),

    /// A CBOR value could not be encoded.
    #[error("CBOR encoding failed: {0}")]
    Cbor(#[from] c2pa_cbor::Error),

    /// Assembling the manifest's JUMBF structure failed.
    ///
    /// The `jumbf` crate's builder reports its own internal misuse (for
    /// example, replacing a placeholder before it has been written) as a
    /// plain I/O error; reaching this indicates a bug in how this crate
    /// drives that builder, not a problem with the caller's settings.
    #[error("JUMBF assembly failed: {0}")]
    Jumbf(#[from] std::io::Error),
}
