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

//! Cryptographic hashing.
//!
//! Hashing is always performed here, over bytes the caller supplies,
//! whether that caller is validating a hash it was told to expect or
//! computing one to record. A digest computed elsewhere would let a buggy
//! or hostile host layer vouch for content the session never saw, so
//! outcomes must not depend on host arithmetic.
//!
//! Hashing is incremental internally, so that a digest over a large asset
//! can be accumulated from host-streamed chunks without ever holding the
//! whole asset in memory.

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::types::HashAlgorithm;

impl HashAlgorithm {
    /// Resolves a C2PA algorithm name (`"sha256"`, `"sha384"`, `"sha512"`)
    /// to an algorithm that can be computed here.
    ///
    /// Returns `None` for names that are not implemented, so callers can
    /// report the omission rather than silently substituting a different
    /// algorithm.
    pub fn from_c2pa_name(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Resolves an algorithm from the DER content octets of its OID.
    ///
    /// ASN.1 structures name a digest by OID rather than by the C2PA
    /// string — an RFC 3161 message imprint and a CMS `digestAlgorithm`
    /// both do — so the same three algorithms need a second way in.
    /// Matching on the encoded octets keeps this free of any ASN.1 type.
    ///
    /// Returns `None` for anything else, including the SHA-1 and MD5 OIDs
    /// that a legacy token might carry: a digest that cannot be computed
    /// here is reported, never quietly swapped for one that can.
    pub fn from_oid(content_octets: &[u8]) -> Option<Self> {
        match content_octets {
            SHA256_OID => Some(Self::Sha256),
            SHA384_OID => Some(Self::Sha384),
            SHA512_OID => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The C2PA name for this algorithm.
    pub fn c2pa_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest length, in bytes, this algorithm produces.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Computes the digest of `bytes` in one shot.
    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(self);
        hasher.update(bytes);
        hasher.finish()
    }
}

/// `2.16.840.1.101.3.4.2.1` — SHA-256, as DER content octets.
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// `2.16.840.1.101.3.4.2.2` — SHA-384.
const SHA384_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// `2.16.840.1.101.3.4.2.3` — SHA-512.
const SHA512_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// An incremental hasher, so a digest can be accumulated from chunks a host
/// streams in rather than from one contiguous buffer.
#[derive(Debug)]
pub enum Hasher {
    /// SHA-256
    Sha256(Sha256),

    /// SHA-384
    Sha384(Sha384),

    /// SHA-512
    Sha512(Sha512),
}

impl Hasher {
    /// Starts a hash using the given algorithm.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    /// Feeds the next chunk of input.
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Sha384(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }

    /// Consumes the hasher and returns the digest.
    pub fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// NIST test vectors for the empty string, which pin down that each
    /// variant really is the algorithm it claims to be.
    #[test]
    fn digests_match_known_vectors() {
        assert_eq!(
            hex(&HashAlgorithm::Sha256.digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&HashAlgorithm::Sha384.digest(b""))[..32],
            *"38b060a751ac96384cd9327eb1b1e36a"
        );
        assert_eq!(
            hex(&HashAlgorithm::Sha512.digest(b""))[..32],
            *"cf83e1357eefb8bdf1542850d66d8007"
        );
    }

    #[test]
    fn incremental_hashing_matches_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";

        for algorithm in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ] {
            let mut hasher = Hasher::new(algorithm);
            for chunk in data.chunks(7) {
                hasher.update(chunk);
            }

            assert_eq!(
                hasher.finish(),
                algorithm.digest(data),
                "{} chunked vs one-shot",
                algorithm.c2pa_name()
            );
        }
    }

    #[test]
    fn algorithm_names_round_trip() {
        for algorithm in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ] {
            assert_eq!(
                HashAlgorithm::from_c2pa_name(algorithm.c2pa_name()),
                Some(algorithm)
            );
        }

        assert_eq!(HashAlgorithm::from_c2pa_name("sha1"), None);
        assert_eq!(HashAlgorithm::from_c2pa_name("md5"), None);
        assert_eq!(HashAlgorithm::from_c2pa_name(""), None);
    }

    #[test]
    fn algorithms_resolve_from_their_oids() {
        // The DER content octets of 2.16.840.1.101.3.4.2.{1,2,3}.
        let sha256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let sha384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        let sha512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

        assert_eq!(HashAlgorithm::from_oid(sha256), Some(HashAlgorithm::Sha256));
        assert_eq!(HashAlgorithm::from_oid(sha384), Some(HashAlgorithm::Sha384));
        assert_eq!(HashAlgorithm::from_oid(sha512), Some(HashAlgorithm::Sha512));

        // 1.3.14.3.2.26 is SHA-1: a real OID a legacy token might name,
        // and one that is not implemented here. It must come back `None`
        // rather than being rounded up to something stronger.
        assert_eq!(
            HashAlgorithm::from_oid(&[0x2b, 0x0e, 0x03, 0x02, 0x1a]),
            None
        );
        assert_eq!(HashAlgorithm::from_oid(&[]), None);

        // Every algorithm the C2PA name maps to also has an OID mapping,
        // so the two ways in cannot drift apart.
        for name in ["sha256", "sha384", "sha512"] {
            let algorithm = HashAlgorithm::from_c2pa_name(name).unwrap();
            let oid: &[u8] = match algorithm {
                HashAlgorithm::Sha256 => sha256,
                HashAlgorithm::Sha384 => sha384,
                HashAlgorithm::Sha512 => sha512,
            };
            assert_eq!(HashAlgorithm::from_oid(oid), Some(algorithm), "{name}");
        }
    }

    #[test]
    fn digest_widths_are_algorithm_specific() {
        assert_eq!(HashAlgorithm::Sha256.digest(b"x").len(), 32);
        assert_eq!(HashAlgorithm::Sha384.digest(b"x").len(), 48);
        assert_eq!(HashAlgorithm::Sha512.digest(b"x").len(), 64);
    }

    #[test]
    fn digest_len_matches_actual_output() {
        for algorithm in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ] {
            assert_eq!(algorithm.digest_len(), algorithm.digest(b"x").len());
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
