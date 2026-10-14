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

//! The `COSE_Sign1` (RFC 9052) envelope around a claim — everything about
//! the claim signature except the signing.
//!
//! The three steps a signer needs, with the host's signature between the
//! second and third:
//!
//! 1. [`protected_header`] — the algorithm and certificate chain.
//! 2. [`to_be_signed`] — the exact bytes the host signs.
//! 3. [`assemble`] — the finished, tagged `COSE_Sign1` that is the content
//!    of the manifest's `c2pa.signature` box, with the claim as a detached
//!    payload.

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::{
    cbor::{sig_structure, CONTEXT_SIGNATURE1},
    SigningAlg,
};

use crate::Error;

/// COSE header label for the signature algorithm (RFC 9052 §3.1).
const HEADER_ALG: i64 = 1;

/// COSE header label for the X.509 certificate chain (RFC 9360 §2).
const HEADER_X5CHAIN: i64 = 33;

/// CBOR tag of a `COSE_Sign1`.
const COSE_SIGN1_TAG: u64 = 18;

/// Builds the protected header: the algorithm and the certificate chain
/// (end-entity first). A lone certificate is written unwrapped, as
/// RFC 9360 permits.
pub fn protected_header(alg: SigningAlg, certificates: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    if certificates.is_empty() {
        return Err(Error::Signature("a claim signature needs a certificate"));
    }
    let chain = match certificates {
        [only] => Value::Bytes(only.clone()),
        many => Value::Array(many.iter().cloned().map(Value::Bytes).collect()),
    };
    let map = BTreeMap::from([
        (Value::Integer(HEADER_ALG), Value::Integer(alg.cose_alg())),
        (Value::Integer(HEADER_X5CHAIN), chain),
    ]);
    Ok(c2pa_cbor::to_vec(&Value::Map(map))?)
}

/// The exact bytes the host's signer must sign: the `Sig_structure` for
/// `claim_cbor` under `protected`.
pub fn to_be_signed(protected: &[u8], claim_cbor: &[u8]) -> Vec<u8> {
    sig_structure(CONTEXT_SIGNATURE1, protected, claim_cbor)
}

/// Assembles the tagged `COSE_Sign1` from the protected header and the
/// host's `signature`. The payload is detached (`nil`): the claim sits in
/// its own box, and verification reconstructs the `Sig_structure` from it.
///
/// Fails if the signature's length is wrong for `alg`, where `alg` has a
/// fixed length (ECDSA and EdDSA); RSA-PSS lengths depend on the key.
pub fn assemble(alg: SigningAlg, protected: &[u8], signature: &[u8]) -> Result<Vec<u8>, Error> {
    if let Some(expected) = alg.fixed_signature_len() {
        if signature.len() != expected {
            return Err(Error::Signature(
                "the signature is not the length its algorithm requires",
            ));
        }
    }
    let value = Value::Tag(
        COSE_SIGN1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(protected.to_vec()),
            Value::Map(BTreeMap::new()),
            Value::Null,
            Value::Bytes(signature.to_vec()),
        ])),
    );
    Ok(c2pa_cbor::to_vec(&value)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn round_trips_through_generic_cbor() {
        let protected = protected_header(SigningAlg::Ed25519, &[vec![1, 2], vec![3]]).unwrap();
        let cose = assemble(SigningAlg::Ed25519, &protected, &[7; 64]).unwrap();

        let Value::Tag(18, inner) = c2pa_cbor::from_slice::<Value>(&cose).unwrap() else {
            panic!("expected tag 18");
        };
        let Value::Array(items) = *inner else {
            panic!("expected an array");
        };
        assert_eq!(items[0], Value::Bytes(protected.clone()));
        assert_eq!(items[2], Value::Null);
        assert_eq!(items[3], Value::Bytes(vec![7; 64]));

        let header: Value = c2pa_cbor::from_slice(&protected).unwrap();
        assert_eq!(
            header.as_map().unwrap().get(&Value::Integer(1)),
            Some(&Value::Integer(-8))
        );
    }

    #[test]
    fn wrong_length_signatures_and_missing_certs_are_refused() {
        assert!(assemble(SigningAlg::Es256, &[], &[0; 10]).is_err());
        assert!(protected_header(SigningAlg::Es256, &[]).is_err());
    }

    #[test]
    fn to_be_signed_is_the_shared_sig_structure() {
        assert_eq!(
            to_be_signed(b"p", b"claim"),
            sig_structure(CONTEXT_SIGNATURE1, b"p", b"claim")
        );
    }
}
