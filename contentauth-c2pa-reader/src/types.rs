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

//! Foundation types shared by the read state machine.
//!
//! [`contentauth_state_machine::RequestId`] is this crate's request-ID type
//! too — see the crate root for the re-export — so it is not duplicated
//! here.

use std::fmt;

/// Identifies one byte stream (typically one asset file) within a session.
///
/// [`ReadSession`](crate::ReadSession) never opens or names files; it refers
/// to streams the host has introduced (the primary asset being read) by
/// these opaque handles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StreamId(pub(crate) u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream #{}", self.0)
    }
}

/// A contiguous range of bytes within a stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ByteRange {
    /// Offset of the first byte of the range from the start of the stream.
    pub start: u64,

    /// Number of bytes in the range.
    pub len: u64,
}

/// Cryptographic hash algorithms the crate can compute internally.
///
/// Mirrors the algorithms accepted by c2pa-rs for hard bindings.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,
}

/// Signature algorithms supported for C2PA claim signatures.
///
/// Mirrors `SigningAlg` in c2pa-rs. This crate never holds key material;
/// this is used to describe the signature the host's claim signer produced
/// and to assemble/validate the corresponding COSE structures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SigningAlg {
    /// ECDSA with SHA-256 (P-256)
    Es256,

    /// ECDSA with SHA-384 (P-384)
    Es384,

    /// ECDSA with SHA-512 (P-521)
    Es512,

    /// RSASSA-PSS with SHA-256
    Ps256,

    /// RSASSA-PSS with SHA-384
    Ps384,

    /// RSASSA-PSS with SHA-512
    Ps512,

    /// EdDSA (Ed25519)
    Ed25519,
}

impl SigningAlg {
    /// Maps a COSE algorithm identifier (RFC 9053) to a signing algorithm.
    ///
    /// Returns `None` for anything outside the set the C2PA specification
    /// permits — including algorithms that are real but not allowed here,
    /// which a reader must report as unsupported rather than attempt.
    pub fn from_cose_alg(alg: i64) -> Option<Self> {
        match alg {
            -7 => Some(Self::Es256),
            -35 => Some(Self::Es384),
            -36 => Some(Self::Es512),
            -37 => Some(Self::Ps256),
            -38 => Some(Self::Ps384),
            -39 => Some(Self::Ps512),
            -8 => Some(Self::Ed25519),
            _ => None,
        }
    }

    /// The COSE algorithm identifier for this algorithm.
    pub fn cose_alg(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::Es512 => -36,
            Self::Ps256 => -37,
            Self::Ps384 => -38,
            Self::Ps512 => -39,
            Self::Ed25519 => -8,
        }
    }

    /// The hash algorithm a claim signed with this algorithm uses for its
    /// assertion hashes and hard binding.
    ///
    /// Derived rather than configured: C2PA pairs the claim's digest
    /// strength with the signature's, and letting them drift apart invites
    /// a manifest whose binding is weaker than the signature protecting
    /// it. Ed25519 names no hash of its own, so it takes the
    /// specification's default. If a caller ever needs them decoupled,
    /// this becomes a setting.
    pub fn claim_hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::Es256 | Self::Ps256 | Self::Ed25519 => HashAlgorithm::Sha256,
            Self::Es384 | Self::Ps384 => HashAlgorithm::Sha384,
            Self::Es512 | Self::Ps512 => HashAlgorithm::Sha512,
        }
    }

    /// The corresponding algorithm in the raw-crypto backend.
    ///
    /// This crate keeps its own `SigningAlg` rather than re-exporting the
    /// backend's: this one is part of the public API and derives `Hash`,
    /// which the backend's does not. The match is exhaustive
    /// over *our* variants, so adding one here fails to compile until it
    /// is mapped; the backend gaining a variant we do not know about is
    /// harmless, since an algorithm we cannot name is one we must refuse.
    pub(crate) fn raw(self) -> c2pa_raw_crypto::SigningAlg {
        use c2pa_raw_crypto::SigningAlg as Raw;

        match self {
            Self::Es256 => Raw::Es256,
            Self::Es384 => Raw::Es384,
            Self::Es512 => Raw::Es512,
            Self::Ps256 => Raw::Ps256,
            Self::Ps384 => Raw::Ps384,
            Self::Ps512 => Raw::Ps512,
            Self::Ed25519 => Raw::Ed25519,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every algorithm the C2PA specification permits.
    const ALL_ALGS: [SigningAlg; 7] = [
        SigningAlg::Es256,
        SigningAlg::Es384,
        SigningAlg::Es512,
        SigningAlg::Ps256,
        SigningAlg::Ps384,
        SigningAlg::Ps512,
        SigningAlg::Ed25519,
    ];

    #[test]
    fn cose_algorithm_identifiers_round_trip() {
        for alg in ALL_ALGS {
            assert_eq!(
                SigningAlg::from_cose_alg(alg.cose_alg()),
                Some(alg),
                "{alg:?} does not survive the round trip"
            );
        }

        // The identifiers are RFC 9053's, not ours to choose.
        assert_eq!(SigningAlg::Es256.cose_alg(), -7);
        assert_eq!(SigningAlg::Es384.cose_alg(), -35);
        assert_eq!(SigningAlg::Es512.cose_alg(), -36);
        assert_eq!(SigningAlg::Ps256.cose_alg(), -37);
        assert_eq!(SigningAlg::Ps384.cose_alg(), -38);
        assert_eq!(SigningAlg::Ps512.cose_alg(), -39);
        assert_eq!(SigningAlg::Ed25519.cose_alg(), -8);

        // Algorithms outside the C2PA set are refused rather than mapped
        // to a near neighbour: -257 is RS256, real but not permitted here.
        assert_eq!(SigningAlg::from_cose_alg(-257), None);
        assert_eq!(SigningAlg::from_cose_alg(0), None);
    }

    #[test]
    fn every_algorithm_names_a_claim_hash() {
        // The pairing is the specification's, not ours to vary.
        assert_eq!(
            SigningAlg::Es256.claim_hash_algorithm(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            SigningAlg::Es384.claim_hash_algorithm(),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            SigningAlg::Es512.claim_hash_algorithm(),
            HashAlgorithm::Sha512
        );
        assert_eq!(
            SigningAlg::Ps256.claim_hash_algorithm(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            SigningAlg::Ps384.claim_hash_algorithm(),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            SigningAlg::Ps512.claim_hash_algorithm(),
            HashAlgorithm::Sha512
        );

        // Ed25519 names no hash of its own and takes the default.
        assert_eq!(
            SigningAlg::Ed25519.claim_hash_algorithm(),
            HashAlgorithm::Sha256
        );
    }

    #[test]
    fn every_algorithm_maps_to_a_backend_validator() {
        for alg in ALL_ALGS {
            assert!(
                c2pa_raw_crypto::validator_for_signing_alg(alg.raw()).is_some(),
                "{alg:?} has no validator in the raw-crypto backend"
            );
        }
    }

    #[test]
    fn display_impls_identify_their_subjects() {
        assert_eq!(StreamId(0).to_string(), "stream #0");
    }
}
