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

//! COSE_Sign1 framing for claim signatures (RFC 9052).
//!
//! A C2PA claim signature is a tagged `COSE_Sign1` with a *detached*
//! payload: the signed bytes are the claim itself, which lives in its own
//! JUMBF box, so the COSE structure carries `nil` where the payload would
//! be. Verification therefore has to reassemble the `Sig_structure` from
//! two boxes that sit side by side in the manifest.
//!
//! # Why the `Sig_structure` is encoded by hand
//!
//! [`sig_structure`] writes the four-element array itself rather than going
//! through a serializer. RFC 9052 requires deterministic encoding, and the
//! structure is fixed: one text string and three byte strings. Writing the
//! heads directly makes shortest-form lengths a property of ten auditable
//! lines instead of an assumption about a general-purpose encoder — and a
//! mistake here does not fail loudly, it silently produces a digest over
//! the wrong bytes and reports a valid signature as broken.

use c2pa_cbor::Value;

use crate::types::SigningAlg;

/// COSE header label for the signature algorithm (RFC 9052 §3.1).
const HEADER_ALG: i64 = 1;

/// COSE header label for the X.509 certificate chain (RFC 9360 §2).
const HEADER_X5CHAIN: i64 = 33;

/// A decoded claim signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimSignature {
    /// The algorithm named in the protected header.
    pub(crate) alg: SigningAlg,

    /// DER-encoded certificates from the `x5chain` header, signer first.
    pub(crate) certificates: Vec<Vec<u8>>,

    /// The protected header bucket exactly as it was encoded.
    ///
    /// Kept verbatim rather than re-encoded from the decoded map: it is
    /// signed input, and a re-encoding that differed by even one byte —
    /// map ordering, integer width — would break verification.
    protected: Vec<u8>,

    /// The signature bytes.
    pub(crate) signature: Vec<u8>,

    /// What the unprotected header offers by way of an RFC 3161 timestamp.
    pub(crate) timestamp: TimestampHeader,
}

impl ClaimSignature {
    /// Builds the `Sig_structure` bytes this signature commits to, given
    /// the detached payload (the claim).
    pub(crate) fn to_be_signed(&self, payload: &[u8]) -> Vec<u8> {
        sig_structure(CONTEXT_SIGNATURE1, &self.protected, payload)
    }

    /// Builds the bytes a timestamp on this signature must cover, given the
    /// detached payload (the claim).
    ///
    /// What is countersigned differs between the two headers, and the
    /// difference is the point of the second one: `sigTst` covers the claim,
    /// so the timestamp says *this claim* existed by then, while `sigTst2`
    /// covers the signature, so it says *this signature* did. The second is
    /// the stronger statement — a timestamp over the claim alone could be
    /// lifted onto a different signature of the same claim.
    pub(crate) fn countersigned(&self, payload: &[u8], storage: TimestampStorage) -> Vec<u8> {
        match storage {
            TimestampStorage::SigTst => {
                sig_structure(CONTEXT_COUNTERSIGNATURE, &self.protected, payload)
            }

            // The payload is the signature wrapped as a CBOR byte string,
            // not the raw bytes: the countersignature covers an encoded
            // value, and the encoding is part of what it commits to.
            TimestampStorage::SigTst2 => {
                let mut wrapped = Vec::with_capacity(self.signature.len() + 8);
                byte_string(&mut wrapped, &self.signature);
                sig_structure(CONTEXT_COUNTERSIGNATURE, &self.protected, &wrapped)
            }
        }
    }
}

/// Which unprotected header carried a timestamp, and so what it covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimestampStorage {
    /// `sigTst`, whose token is a whole RFC 3161 `TimeStampResp` and which
    /// countersigns the claim.
    SigTst,

    /// `sigTst2`, whose token is a bare `TimeStampToken` and which
    /// countersigns the claim signature.
    SigTst2,
}

/// What a claim signature's unprotected header offers by way of a
/// timestamp.
///
/// Three states rather than an `Option`, for the same reason
/// [`crate::validation::SignatureBox`] has three: a header that is absent
/// and a header that is present but unreadable are different findings, and
/// collapsing them would report "no timestamp" for a manifest that plainly
/// carries one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TimestampHeader {
    /// Neither `sigTst` nor `sigTst2` is present.
    Absent,

    /// One of them is present but is not shaped like a timestamp.
    Malformed(&'static str),

    /// A token, and the rule for what it covers.
    Present {
        /// The token bytes, exactly as the header carried them.
        token: Vec<u8>,

        /// Which header carried it.
        storage: TimestampStorage,
    },
}

/// Context string of a `COSE_Sign1` signature (RFC 9052 §4.4).
pub(crate) const CONTEXT_SIGNATURE1: &str = "Signature1";

/// Context string of a countersignature (RFC 9052 §4.5), which is what an
/// RFC 3161 timestamp on a C2PA claim signature is.
pub(crate) const CONTEXT_COUNTERSIGNATURE: &str = "CounterSignature";

/// Builds the `Sig_structure` a COSE signature or countersignature covers.
///
/// `context` selects which structure this is. The countersignature form
/// used here is the four-element one, with no `sign_protected` bucket:
/// verified against a real timestamp in `tests/read_fixture.rs`, whose
/// message imprint only reproduces this way.
pub(crate) fn sig_structure(context: &str, protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protected.len() + payload.len() + 32);

    // Sig_structure = [ context, body_protected, external_aad, payload ]
    head(&mut out, MAJOR_ARRAY, 4);
    head(&mut out, MAJOR_TEXT, context.len() as u64);
    out.extend_from_slice(context.as_bytes());
    byte_string(&mut out, protected);
    // C2PA supplies no external additional authenticated data.
    byte_string(&mut out, &[]);
    byte_string(&mut out, payload);

    out
}

const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;

/// Writes a CBOR definite-length head in shortest form.
fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;

    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, argument as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// Writes a CBOR byte string.
fn byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    head(out, MAJOR_BYTES, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Decodes a `COSE_Sign1` claim signature.
///
/// Returns the reason it could not be read, for the caller to attach to
/// whichever manifest it came from.
pub(crate) fn parse(bytes: &[u8]) -> Result<ClaimSignature, &'static str> {
    let value: Value = c2pa_cbor::from_slice(bytes).map_err(|_| "signature is not valid CBOR")?;

    // `COSE_Sign1` carries tag 18; C2PA claim signatures use it. A
    // `COSE_Sign` (tag 98) is otherwise the same shape — a four-element
    // array — so it is rejected by its tag rather than left to be caught
    // later by its fourth element being an array of signatures instead of
    // a byte string.
    let value = match value {
        Value::Tag(18, inner) => *inner,
        Value::Tag(_, _) => return Err("signature does not carry the COSE_Sign1 tag"),
        untagged => untagged,
    };

    let Value::Array(items) = value else {
        return Err("signature is not a COSE_Sign1 array");
    };

    let [protected, unprotected, payload, signature] = <[Value; 4]>::try_from(items)
        .map_err(|_| "COSE_Sign1 does not have exactly four elements")?;

    let Value::Bytes(protected) = protected else {
        return Err("COSE_Sign1 protected header is not a byte string");
    };

    let Value::Bytes(signature) = signature else {
        return Err("COSE_Sign1 signature is not a byte string");
    };

    // C2PA detaches the payload: the claim lives in its own JUMBF box, so
    // an embedded one would be a second, unverifiable copy.
    if !matches!(payload, Value::Null) {
        return Err("COSE_Sign1 payload is not detached");
    }

    let headers: Value =
        c2pa_cbor::from_slice(&protected).map_err(|_| "protected header is not valid CBOR")?;
    let Value::Map(headers) = headers else {
        return Err("protected header is not a map");
    };

    let alg = match headers.get(&Value::Integer(HEADER_ALG)) {
        Some(Value::Integer(alg)) => {
            SigningAlg::from_cose_alg(*alg).ok_or("unsupported signature algorithm")?
        }
        Some(_) => return Err("protected header names a non-integer algorithm"),
        None => return Err("protected header names no algorithm"),
    };

    let certificates = match headers.get(&Value::Integer(HEADER_X5CHAIN)) {
        // RFC 9360: a lone certificate may appear unwrapped.
        Some(Value::Bytes(one)) => vec![one.clone()],
        Some(Value::Array(chain)) => chain
            .iter()
            .map(|item| match item {
                Value::Bytes(der) => Ok(der.clone()),
                _ => Err("x5chain contains a non-byte-string entry"),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("x5chain is neither a byte string nor an array"),
        None => return Err("protected header carries no certificate chain"),
    };

    if certificates.is_empty() {
        return Err("x5chain is empty");
    }

    Ok(ClaimSignature {
        alg,
        certificates,
        protected,
        signature,
        timestamp: timestamp_header(&unprotected),
    })
}

/// Reads an RFC 3161 timestamp out of the unprotected header bucket.
///
/// The timestamp lives in the *unprotected* bucket because the claim
/// signature cannot cover it: the token is obtained by countersigning that
/// very signature, so it does not exist until after the signing is done.
fn timestamp_header(unprotected: &Value) -> TimestampHeader {
    let Value::Map(headers) = unprotected else {
        return TimestampHeader::Malformed("COSE_Sign1 unprotected header is not a map");
    };

    // `sigTst2` first: a signature carrying both is taken at its stronger
    // word, since that token covers the signature rather than the claim.
    let (value, storage) = match [
        (SIGTST2_LABEL, TimestampStorage::SigTst2),
        (SIGTST_LABEL, TimestampStorage::SigTst),
    ]
    .into_iter()
    .find_map(|(label, storage)| {
        headers
            .get(&Value::Text(label.to_string()))
            .map(|value| (value, storage))
    }) {
        Some(found) => found,
        None => return TimestampHeader::Absent,
    };

    // { "tstTokens": [ { "val": <token bytes> }, … ] }
    let Value::Map(container) = value else {
        return TimestampHeader::Malformed("timestamp header is not a map");
    };

    let Some(Value::Array(tokens)) = container.get(&Value::Text(TST_TOKENS_LABEL.to_string()))
    else {
        return TimestampHeader::Malformed("timestamp header carries no token array");
    };

    // More than one token is permitted; only the first is examined, which
    // is what c2pa-rs does too. A second one could only agree or conflict
    // with the first, and neither is acted on today.
    let Some(Value::Map(token)) = tokens.first() else {
        return TimestampHeader::Malformed("timestamp token list is empty or malformed");
    };

    let Some(Value::Bytes(token)) = token.get(&Value::Text(TST_VALUE_LABEL.to_string())) else {
        return TimestampHeader::Malformed("timestamp token carries no value");
    };

    TimestampHeader::Present {
        token: token.clone(),
        storage,
    }
}

/// Unprotected-header label of a C2PA 1.x timestamp.
const SIGTST_LABEL: &str = "sigTst";

/// Unprotected-header label of a C2PA 2.x timestamp.
const SIGTST2_LABEL: &str = "sigTst2";

/// Key of the token array inside either timestamp header.
const TST_TOKENS_LABEL: &str = "tstTokens";

/// Key of one token's bytes.
const TST_VALUE_LABEL: &str = "val";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use super::*;

    /// Encodes a value the way a signer would, for round-tripping.
    fn encode(value: &Value) -> Vec<u8> {
        c2pa_cbor::to_vec(value).unwrap()
    }

    fn protected_header(alg: i64, chain: Vec<Vec<u8>>) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(Value::Integer(HEADER_ALG), Value::Integer(alg));
        map.insert(
            Value::Integer(HEADER_X5CHAIN),
            Value::Array(chain.into_iter().map(Value::Bytes).collect()),
        );
        encode(&Value::Map(map))
    }

    fn sign1(protected: Vec<u8>, payload: Value, signature: Vec<u8>) -> Vec<u8> {
        encode(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(BTreeMap::new()),
                payload,
                Value::Bytes(signature),
            ])),
        ))
    }

    #[test]
    fn parses_a_well_formed_signature() {
        let protected = protected_header(-7, vec![vec![1, 2, 3], vec![4, 5, 6]]);
        let bytes = sign1(protected.clone(), Value::Null, vec![0xaa; 64]);

        let sig = parse(&bytes).unwrap();
        assert_eq!(sig.alg, SigningAlg::Es256);
        assert_eq!(sig.certificates, [vec![1, 2, 3], vec![4, 5, 6]]);
        assert_eq!(sig.signature, vec![0xaa; 64]);

        // The protected bucket is preserved byte for byte, because it is
        // signed input.
        assert_eq!(sig.protected, protected);
    }

    #[test]
    fn accepts_an_untagged_structure() {
        let protected = protected_header(-37, vec![vec![9]]);
        let untagged = encode(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(BTreeMap::new()),
            Value::Null,
            Value::Bytes(vec![1; 8]),
        ]));

        assert_eq!(parse(&untagged).unwrap().alg, SigningAlg::Ps256);
    }

    #[test]
    fn accepts_a_bare_single_certificate() {
        let mut map = BTreeMap::new();
        map.insert(Value::Integer(HEADER_ALG), Value::Integer(-8));
        map.insert(Value::Integer(HEADER_X5CHAIN), Value::Bytes(vec![7; 4]));
        let bytes = sign1(encode(&Value::Map(map)), Value::Null, vec![2; 64]);

        let sig = parse(&bytes).unwrap();
        assert_eq!(sig.alg, SigningAlg::Ed25519);
        assert_eq!(sig.certificates, [vec![7; 4]]);
    }

    #[test]
    fn rejects_structures_it_cannot_verify() {
        let good = protected_header(-7, vec![vec![1]]);

        // Not CBOR at all.
        assert!(parse(&[0xff, 0xff, 0xff]).is_err());

        // An attached payload would be a second, unverifiable copy of the
        // claim.
        assert_eq!(
            parse(&sign1(good.clone(), Value::Bytes(vec![1]), vec![0; 4])),
            Err("COSE_Sign1 payload is not detached")
        );

        // A `COSE_Sign` (tag 98) is the same shape as a `COSE_Sign1`, but
        // is not one.
        assert_eq!(
            parse(&encode(&Value::Tag(
                98,
                Box::new(Value::Array(vec![
                    Value::Bytes(good.clone()),
                    Value::Map(BTreeMap::new()),
                    Value::Null,
                    Value::Bytes(vec![0; 4]),
                ])),
            ))),
            Err("signature does not carry the COSE_Sign1 tag")
        );

        // Wrong shape.
        assert_eq!(
            parse(&encode(&Value::Array(vec![Value::Null]))),
            Err("COSE_Sign1 does not have exactly four elements")
        );
        assert_eq!(
            parse(&encode(&Value::Integer(3))),
            Err("signature is not a COSE_Sign1 array")
        );

        // A protected bucket that is not a map, or names nothing useful.
        assert_eq!(
            parse(&sign1(encode(&Value::Integer(1)), Value::Null, vec![0; 4])),
            Err("protected header is not a map")
        );

        let mut no_alg = BTreeMap::new();
        no_alg.insert(Value::Integer(HEADER_X5CHAIN), Value::Bytes(vec![1]));
        assert_eq!(
            parse(&sign1(encode(&Value::Map(no_alg)), Value::Null, vec![0; 4])),
            Err("protected header names no algorithm")
        );

        let mut unknown_alg = BTreeMap::new();
        unknown_alg.insert(Value::Integer(HEADER_ALG), Value::Integer(-65_000));
        unknown_alg.insert(Value::Integer(HEADER_X5CHAIN), Value::Bytes(vec![1]));
        assert_eq!(
            parse(&sign1(
                encode(&Value::Map(unknown_alg)),
                Value::Null,
                vec![0; 4]
            )),
            Err("unsupported signature algorithm")
        );

        let mut no_chain = BTreeMap::new();
        no_chain.insert(Value::Integer(HEADER_ALG), Value::Integer(-7));
        assert_eq!(
            parse(&sign1(
                encode(&Value::Map(no_chain)),
                Value::Null,
                vec![0; 4]
            )),
            Err("protected header carries no certificate chain")
        );

        let empty_chain = protected_header(-7, vec![]);
        assert_eq!(
            parse(&sign1(empty_chain, Value::Null, vec![0; 4])),
            Err("x5chain is empty")
        );
    }

    #[test]
    fn rejects_elements_of_the_wrong_cbor_type() {
        let chain = vec![Value::Bytes(vec![1])];

        // Protected bucket that is not a byte string.
        assert_eq!(
            parse(&encode(&Value::Array(vec![
                Value::Integer(1),
                Value::Map(BTreeMap::new()),
                Value::Null,
                Value::Bytes(vec![0; 4]),
            ]))),
            Err("COSE_Sign1 protected header is not a byte string")
        );

        // Signature that is not a byte string — which is also what makes a
        // `COSE_Sign` (an array of signatures there) bounce.
        assert_eq!(
            parse(&encode(&Value::Array(vec![
                Value::Bytes(protected_header(-7, vec![vec![1]])),
                Value::Map(BTreeMap::new()),
                Value::Null,
                Value::Array(vec![]),
            ]))),
            Err("COSE_Sign1 signature is not a byte string")
        );

        // Algorithm that is not an integer.
        let mut text_alg = BTreeMap::new();
        text_alg.insert(Value::Integer(HEADER_ALG), Value::Text("ES256".to_string()));
        text_alg.insert(Value::Integer(HEADER_X5CHAIN), Value::Array(chain.clone()));
        assert_eq!(
            parse(&sign1(
                encode(&Value::Map(text_alg)),
                Value::Null,
                vec![0; 4]
            )),
            Err("protected header names a non-integer algorithm")
        );

        // A chain entry that is not a byte string.
        let mut bad_entry = BTreeMap::new();
        bad_entry.insert(Value::Integer(HEADER_ALG), Value::Integer(-7));
        bad_entry.insert(
            Value::Integer(HEADER_X5CHAIN),
            Value::Array(vec![Value::Integer(7)]),
        );
        assert_eq!(
            parse(&sign1(
                encode(&Value::Map(bad_entry)),
                Value::Null,
                vec![0; 4]
            )),
            Err("x5chain contains a non-byte-string entry")
        );

        // A chain that is neither a byte string nor an array.
        let mut bad_chain = BTreeMap::new();
        bad_chain.insert(Value::Integer(HEADER_ALG), Value::Integer(-7));
        bad_chain.insert(Value::Integer(HEADER_X5CHAIN), Value::Integer(0));
        assert_eq!(
            parse(&sign1(
                encode(&Value::Map(bad_chain)),
                Value::Null,
                vec![0; 4]
            )),
            Err("x5chain is neither a byte string nor an array")
        );

        // A protected bucket that is not itself valid CBOR.
        assert_eq!(
            parse(&sign1(vec![0xff, 0xff], Value::Null, vec![0; 4])),
            Err("protected header is not valid CBOR")
        );
    }

    #[test]
    fn sig_structure_matches_the_rfc_9052_layout() {
        let protected = protected_header(-7, vec![vec![1]]);
        let sig = parse(&sign1(protected.clone(), Value::Null, vec![0; 4])).unwrap();

        let tbs = sig.to_be_signed(b"claim");

        // [ "Signature1", protected, h'', h'claim' ]
        let mut expected = vec![0x84, 0x6a];
        expected.extend_from_slice(b"Signature1");
        // This protected bucket is short, so its length rides in the
        // head's low bits rather than a following byte — which is what
        // "shortest form" requires.
        assert!(protected.len() < 24, "test assumes a one-byte head");
        expected.push(0x40 | protected.len() as u8);
        expected.extend_from_slice(&protected);
        expected.push(0x40);
        expected.extend_from_slice(&[0x45]);
        expected.extend_from_slice(b"claim");

        assert_eq!(tbs, expected);
    }

    /// Builds a `COSE_Sign1` with the given unprotected header bucket.
    fn sign1_with_unprotected(unprotected: Value) -> Vec<u8> {
        encode(&Value::Array(vec![
            Value::Bytes(protected_header(-7, vec![vec![1]])),
            unprotected,
            Value::Null,
            Value::Bytes(vec![0xab; 8]),
        ]))
    }

    /// A `{ "tstTokens": [ { "val": … } ] }` container.
    fn tst_container(token: Vec<u8>) -> Value {
        let mut entry = BTreeMap::new();
        entry.insert(Value::Text("val".to_string()), Value::Bytes(token));

        let mut container = BTreeMap::new();
        container.insert(
            Value::Text("tstTokens".to_string()),
            Value::Array(vec![Value::Map(entry)]),
        );

        Value::Map(container)
    }

    fn unprotected_with(label: &str, value: Value) -> Value {
        let mut map = BTreeMap::new();
        map.insert(Value::Text(label.to_string()), value);
        Value::Map(map)
    }

    #[test]
    fn a_signature_without_a_timestamp_header_reports_absence() {
        let bytes = sign1_with_unprotected(Value::Map(BTreeMap::new()));
        assert_eq!(parse(&bytes).unwrap().timestamp, TimestampHeader::Absent);
    }

    #[test]
    fn both_timestamp_headers_are_recognized() {
        for (label, expected) in [
            ("sigTst", TimestampStorage::SigTst),
            ("sigTst2", TimestampStorage::SigTst2),
        ] {
            let bytes =
                sign1_with_unprotected(unprotected_with(label, tst_container(vec![9, 9, 9])));

            assert_eq!(
                parse(&bytes).unwrap().timestamp,
                TimestampHeader::Present {
                    token: vec![9, 9, 9],
                    storage: expected,
                },
                "{label}"
            );
        }
    }

    #[test]
    fn a_signature_carrying_both_headers_is_read_as_the_stronger_one() {
        // `sigTst2` countersigns the signature rather than the claim, so a
        // signature offering both is taken at its stronger word.
        let mut map = BTreeMap::new();
        map.insert(
            Value::Text("sigTst".to_string()),
            tst_container(vec![1, 1, 1]),
        );
        map.insert(
            Value::Text("sigTst2".to_string()),
            tst_container(vec![2, 2, 2]),
        );

        assert_eq!(
            parse(&sign1_with_unprotected(Value::Map(map)))
                .unwrap()
                .timestamp,
            TimestampHeader::Present {
                token: vec![2, 2, 2],
                storage: TimestampStorage::SigTst2,
            }
        );
    }

    #[test]
    fn a_timestamp_header_of_the_wrong_shape_is_malformed_not_absent() {
        // Each of these is a header that plainly *is* a timestamp attempt,
        // so reporting "no timestamp" would contradict the manifest.
        let mut empty_tokens = BTreeMap::new();
        empty_tokens.insert(Value::Text("tstTokens".to_string()), Value::Array(vec![]));

        let mut token_without_value = BTreeMap::new();
        token_without_value.insert(
            Value::Text("tstTokens".to_string()),
            Value::Array(vec![Value::Map(BTreeMap::new())]),
        );

        let cases: [(Value, &str); 4] = [
            (Value::Integer(7), "not a map"),
            (Value::Map(BTreeMap::new()), "no token array"),
            (Value::Map(empty_tokens), "empty or malformed"),
            (Value::Map(token_without_value), "carries no value"),
        ];

        for (value, expected) in cases {
            let bytes = sign1_with_unprotected(unprotected_with("sigTst", value));

            match parse(&bytes).unwrap().timestamp {
                TimestampHeader::Malformed(reason) => assert!(
                    reason.contains(expected),
                    "expected {expected:?}, got {reason:?}"
                ),
                other => panic!("expected a malformed header, got {other:?}"),
            }
        }

        // And an unprotected bucket that is not a map at all.
        let bytes = sign1_with_unprotected(Value::Integer(0));
        assert!(matches!(
            parse(&bytes).unwrap().timestamp,
            TimestampHeader::Malformed("COSE_Sign1 unprotected header is not a map")
        ));
    }

    #[test]
    fn the_two_headers_countersign_different_things() {
        let bytes = sign1_with_unprotected(unprotected_with("sigTst", tst_container(vec![0])));
        let signature = parse(&bytes).unwrap();

        let over_claim = signature.countersigned(b"the claim", TimestampStorage::SigTst);
        let over_signature = signature.countersigned(b"the claim", TimestampStorage::SigTst2);

        // Both are `CounterSignature` structures over the same protected
        // bucket; only the payload differs — and that difference is the
        // whole reason the second header exists.
        assert_ne!(over_claim, over_signature);

        let mut prefix = vec![0x84, 0x70];
        prefix.extend_from_slice(b"CounterSignature");
        assert!(over_claim.starts_with(&prefix), "{over_claim:02x?}");
        assert!(over_signature.starts_with(&prefix));

        // `sigTst` covers the claim verbatim...
        assert_eq!(
            over_claim,
            sig_structure(CONTEXT_COUNTERSIGNATURE, &signature.protected, b"the claim")
        );

        // ...and `sigTst2` covers the signature wrapped as a CBOR byte
        // string, not the raw signature bytes.
        let mut wrapped = Vec::new();
        byte_string(&mut wrapped, &signature.signature);
        assert_eq!(
            over_signature,
            sig_structure(CONTEXT_COUNTERSIGNATURE, &signature.protected, &wrapped)
        );
        assert_ne!(
            over_signature,
            sig_structure(
                CONTEXT_COUNTERSIGNATURE,
                &signature.protected,
                &signature.signature
            ),
            "the wrapping is part of what is countersigned"
        );
    }

    #[test]
    fn head_uses_shortest_form_at_every_width() {
        let widths: [(u64, &[u8]); 5] = [
            (23, &[0x77]),
            (24, &[0x78, 24]),
            (0x100, &[0x79, 0x01, 0x00]),
            (0x1_0000, &[0x7a, 0x00, 0x01, 0x00, 0x00]),
            (0x1_0000_0000, &[0x7b, 0, 0, 0, 1, 0, 0, 0, 0]),
        ];

        for (argument, expected) in widths {
            let mut out = Vec::new();
            head(&mut out, MAJOR_TEXT, argument);
            assert_eq!(out, expected, "argument {argument}");
        }
    }
}
