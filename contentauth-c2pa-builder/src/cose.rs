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

//! COSE_Sign1 assembly for claim signatures (RFC 9052). The counterpart to
//! `contentauth-c2pa-reader`'s `cose` module, which only decodes.
//!
//! # What stays fixed-length, and what needs padding
//!
//! The protected header (algorithm + certificate chain) and the signature
//! are both fixed-length once the signing algorithm and certificates are
//! known — see [`protected_header`] and [`signature_len`] — so neither
//! changes size between this crate's placeholder and final passes. The
//! unprotected header does, when a timestamp is requested: the RFC 3161
//! token's length depends on the timestamp authority's response, which
//! this crate cannot predict. [`unprotected_header`] handles that the same
//! way `contentauth-c2pa-builder`'s `data_hash` module handles its own
//! variable-length fields — see that module's docs — reserving
//! [`TimestampSettings::reserve_size`](crate::TimestampSettings::reserve_size)
//! bytes up front and topping up two padding fields to keep the total
//! invariant once the real token is known.

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::{
    cbor::{pad_lens_for_target, sig_structure, uint_head_len, CONTEXT_SIGNATURE1},
    SigningAlg,
};

use crate::error::Error;

/// COSE header label for the signature algorithm (RFC 9052 §3.1).
const HEADER_ALG: i64 = 1;

/// COSE header label for the X.509 certificate chain (RFC 9360 §2).
const HEADER_X5CHAIN: i64 = 33;

/// Unprotected-header label of a C2PA 2.x timestamp, countersigning the
/// claim signature. Matches `contentauth_c2pa_reader::cose`'s reader,
/// which prefers this over the 1.x `sigTst` header when both are present.
const SIGTST2_LABEL: &str = "sigTst2";

/// Key of the token array inside the timestamp header.
const TST_TOKENS_LABEL: &str = "tstTokens";

/// Key of one token's bytes.
const TST_VALUE_LABEL: &str = "val";

/// Key of the first padding field alongside a token's bytes.
const TST_PAD_LABEL: &str = "pad";

/// Key of the second padding field.
const TST_PAD2_LABEL: &str = "pad2";

/// Builds the protected header bytes: algorithm and certificate chain.
///
/// Fixed for the life of a signing session — computed once, at the start
/// of the workflow, and never revisited.
pub(crate) fn protected_header(
    alg: SigningAlg,
    certificates: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let chain = match certificates {
        // RFC 9360 permits a lone certificate to appear unwrapped.
        [only] => Value::Bytes(only.clone()),
        many => Value::Array(many.iter().cloned().map(Value::Bytes).collect()),
    };

    let mut map = BTreeMap::new();
    map.insert(Value::Integer(HEADER_ALG), Value::Integer(alg.cose_alg()));
    map.insert(Value::Integer(HEADER_X5CHAIN), chain);

    Ok(c2pa_cbor::to_vec(&Value::Map(map))?)
}

/// The `Sig_structure` bytes a claim signature over `claim_cbor` covers,
/// given the protected header built by [`protected_header`].
pub(crate) fn claim_to_be_signed(protected: &[u8], claim_cbor: &[u8]) -> Vec<u8> {
    sig_structure(CONTEXT_SIGNATURE1, protected, claim_cbor)
}

/// The exact signature length required for `alg`, resolving the
/// RSASSA-PSS case from a caller-supplied modulus size.
///
/// Returns [`Error::MissingRsaSignatureLen`] if `alg` is an RSASSA-PSS
/// algorithm and `rsa_signature_len` is `None`.
pub(crate) fn signature_len(
    alg: SigningAlg,
    rsa_signature_len: Option<usize>,
) -> Result<usize, Error> {
    match alg.fixed_signature_len() {
        Some(len) => Ok(len),
        None => rsa_signature_len.ok_or(Error::MissingRsaSignatureLen(alg)),
    }
}

/// Builds the unprotected header bucket: empty, unless a timestamp is
/// requested.
///
/// `token` is `None` for the placeholder pass (before any timestamp has
/// been obtained, or when none was requested at all) and `Some` once a
/// real RFC 3161 token is in hand. When timestamping is requested
/// (`reserve_size.is_some()`), both passes must produce headers of
/// identical encoded length — see the module docs.
pub(crate) fn unprotected_header(
    token: Option<&[u8]>,
    reserve_size: Option<usize>,
) -> Result<Value, Error> {
    let Some(reserve_size) = reserve_size else {
        return Ok(Value::Map(BTreeMap::new()));
    };
    let reserve_size = reserve_size as u64;

    let token_len = token.map_or(reserve_size, |t| t.len() as u64);
    if token_len > reserve_size {
        return Err(Error::TimestampTooLarge {
            reserve: reserve_size as usize,
            actual: token_len as usize,
        });
    }

    let val_bytes = token.map_or_else(|| vec![0u8; reserve_size as usize], <[u8]>::to_vec);
    let real_val_len = uint_head_len(token_len) as u64 + token_len;

    // Reserved once, worst case: the token at its maximum configured
    // size, plus an empty `pad` and `pad2` (one byte each — their own
    // one-byte, zero-length heads). The real pass's `val` is never longer
    // than this (`token_len <= reserve_size`), so there is always at
    // least this much room left for `pad`/`pad2` to grow into.
    let reserved_total = uint_head_len(reserve_size) as u64 + reserve_size + 1 + 1;
    let pads_target =
        reserved_total
            .checked_sub(real_val_len)
            .ok_or(Error::PlaceholderSizeMismatch(
                "timestamp token exceeded the width reserved for the placeholder",
            ))?;
    let (pad_len, pad2_len) = pad_lens_for_target(pads_target).ok_or(
        Error::PlaceholderSizeMismatch("could not compute an exact timestamp padding length"),
    )?;

    let mut token_map = BTreeMap::new();
    token_map.insert(
        Value::Text(TST_VALUE_LABEL.to_string()),
        Value::Bytes(val_bytes),
    );
    token_map.insert(
        Value::Text(TST_PAD_LABEL.to_string()),
        Value::Bytes(vec![0u8; pad_len as usize]),
    );
    token_map.insert(
        Value::Text(TST_PAD2_LABEL.to_string()),
        Value::Bytes(vec![0u8; pad2_len as usize]),
    );

    let mut container = BTreeMap::new();
    container.insert(
        Value::Text(TST_TOKENS_LABEL.to_string()),
        Value::Array(vec![Value::Map(token_map)]),
    );

    let mut unprotected = BTreeMap::new();
    unprotected.insert(
        Value::Text(SIGTST2_LABEL.to_string()),
        Value::Map(container),
    );

    Ok(Value::Map(unprotected))
}

/// The bytes an RFC 3161 timestamp on this claim signature must cover,
/// given the real signature.
///
/// This is the `sigTst2` form: the countersignature covers the signature
/// itself (wrapped as a CBOR byte string), not the claim — the stronger of
/// the two statements a C2PA timestamp can make, since a timestamp over
/// the claim alone could be lifted onto a different signature of the same
/// claim. Matches `contentauth_c2pa_reader::cose::ClaimSignature::countersigned`
/// for `TimestampStorage::SigTst2`.
pub(crate) fn countersigned(protected: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut wrapped = Vec::with_capacity(signature.len() + 8);
    contentauth_c2pa_primitives::cbor::byte_string(&mut wrapped, signature);
    sig_structure(
        contentauth_c2pa_primitives::cbor::CONTEXT_COUNTERSIGNATURE,
        protected,
        &wrapped,
    )
}

/// Assembles the final `COSE_Sign1` claim signature.
///
/// `protected` and `signature` are fixed-length across every pass;
/// `unprotected` is built by [`unprotected_header`], which is responsible
/// for its own length invariant.
pub(crate) fn build_cose_sign1(
    protected: &[u8],
    unprotected: Value,
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    let value = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected.to_vec()),
            unprotected,
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
    fn protected_header_wraps_a_lone_certificate_unwrapped() {
        let header = protected_header(SigningAlg::Es256, &[vec![1, 2, 3]]).unwrap();
        let decoded: Value = c2pa_cbor::from_slice(&header).unwrap();
        let map = decoded.as_map().unwrap();

        assert_eq!(
            map.get(&Value::Integer(HEADER_ALG)),
            Some(&Value::Integer(-7))
        );
        assert_eq!(
            map.get(&Value::Integer(HEADER_X5CHAIN)),
            Some(&Value::Bytes(vec![1, 2, 3]))
        );
    }

    #[test]
    fn protected_header_arrays_a_multi_certificate_chain() {
        let header = protected_header(SigningAlg::Ed25519, &[vec![1], vec![2]]).unwrap();
        let decoded: Value = c2pa_cbor::from_slice(&header).unwrap();
        let map = decoded.as_map().unwrap();

        assert_eq!(
            map.get(&Value::Integer(HEADER_X5CHAIN)),
            Some(&Value::Array(vec![
                Value::Bytes(vec![1]),
                Value::Bytes(vec![2])
            ]))
        );
    }

    #[test]
    fn signature_len_resolves_fixed_algorithms_without_a_hint() {
        assert_eq!(signature_len(SigningAlg::Es256, None).unwrap(), 64);
        assert_eq!(signature_len(SigningAlg::Ed25519, None).unwrap(), 64);
    }

    #[test]
    fn signature_len_requires_a_hint_for_rsa() {
        assert!(matches!(
            signature_len(SigningAlg::Ps256, None),
            Err(Error::MissingRsaSignatureLen(SigningAlg::Ps256))
        ));
        assert_eq!(signature_len(SigningAlg::Ps256, Some(256)).unwrap(), 256);
    }

    #[test]
    fn no_timestamp_means_an_empty_unprotected_header() {
        let header = unprotected_header(None, None).unwrap();
        assert_eq!(header, Value::Map(BTreeMap::new()));
    }

    #[test]
    fn placeholder_and_real_timestamp_headers_are_the_same_length() {
        let placeholder = unprotected_header(None, Some(10_000)).unwrap();
        let placeholder_bytes = c2pa_cbor::to_vec(&placeholder).unwrap();

        for token_len in [0usize, 1, 255, 256, 9_999, 10_000] {
            let token = vec![0x42u8; token_len];
            let real = unprotected_header(Some(&token), Some(10_000)).unwrap();
            let real_bytes = c2pa_cbor::to_vec(&real).unwrap();

            assert_eq!(
                placeholder_bytes.len(),
                real_bytes.len(),
                "token_len {token_len}"
            );

            // And the real token is genuinely recoverable from the header.
            let Value::Map(unprotected) = &real else {
                panic!("expected a map");
            };
            let Some(Value::Map(container)) =
                unprotected.get(&Value::Text(SIGTST2_LABEL.to_string()))
            else {
                panic!("expected a sigTst2 container");
            };
            let Some(Value::Array(tokens)) =
                container.get(&Value::Text(TST_TOKENS_LABEL.to_string()))
            else {
                panic!("expected a tstTokens array");
            };
            let Value::Map(entry) = &tokens[0] else {
                panic!("expected a token map");
            };
            assert_eq!(
                entry.get(&Value::Text(TST_VALUE_LABEL.to_string())),
                Some(&Value::Bytes(token))
            );
        }
    }

    #[test]
    fn a_token_larger_than_the_reserve_is_refused() {
        assert!(matches!(
            unprotected_header(Some(&[0u8; 11]), Some(10)),
            Err(Error::TimestampTooLarge {
                reserve: 10,
                actual: 11
            })
        ));
    }

    #[test]
    fn build_cose_sign1_round_trips_through_the_reader() {
        let protected = protected_header(SigningAlg::Es256, &[vec![9, 9, 9]]).unwrap();
        let signature = vec![0xab; 64];
        let cose = build_cose_sign1(
            &protected,
            unprotected_header(None, None).unwrap(),
            &signature,
        )
        .unwrap();

        // Decoded generically, as the reader's own `cose::parse` would.
        let decoded: Value = c2pa_cbor::from_slice(&cose).unwrap();
        let Value::Tag(18, inner) = decoded else {
            panic!("expected a tag-18 COSE_Sign1");
        };
        let Value::Array(items) = *inner else {
            panic!("expected a four-element array");
        };
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], Value::Bytes(protected));
        assert_eq!(items[2], Value::Null);
        assert_eq!(items[3], Value::Bytes(signature));
    }

    #[test]
    fn claim_to_be_signed_matches_the_shared_sig_structure() {
        let protected = protected_header(SigningAlg::Es256, &[vec![1]]).unwrap();
        let tbs = claim_to_be_signed(&protected, b"the claim");
        assert_eq!(
            tbs,
            sig_structure(CONTEXT_SIGNATURE1, &protected, b"the claim")
        );
    }

    #[test]
    fn countersigned_wraps_the_signature_as_a_byte_string() {
        let protected = protected_header(SigningAlg::Es256, &[vec![1]]).unwrap();
        let signature = vec![7u8; 64];
        let tbs = countersigned(&protected, &signature);

        let mut wrapped = Vec::new();
        contentauth_c2pa_primitives::cbor::byte_string(&mut wrapped, &signature);
        assert_eq!(
            tbs,
            sig_structure(
                contentauth_c2pa_primitives::cbor::CONTEXT_COUNTERSIGNATURE,
                &protected,
                &wrapped
            )
        );
    }
}
