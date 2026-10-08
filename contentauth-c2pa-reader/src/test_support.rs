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

//! Builders for synthetic JUMBF manifest stores, shared by unit tests.
//!
//! These construct byte sequences by hand rather than by reusing the
//! reader, so tests exercise the reader against independently-built input.
//! Tests that need assurance against *real-world* bytes use the fixture in
//! `tests/` instead.

#![cfg(test)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use sha2::{Digest, Sha256};

/// The end-entity certificate from the claim signature in
/// `tests/fixtures/manifest_data.c2pa`.
///
/// Held as a standalone file so that certificate decoding can be tested
/// without first going through the COSE layer — and so a bug in that layer
/// shows up as a failing comparison in `tests/read_fixture.rs` rather than
/// as two tests agreeing on the wrong bytes.
pub(crate) const FIXTURE_LEAF_CERT: &[u8] = include_bytes!("../tests/fixtures/signer-leaf.der");

/// The intermediate CA certificate from the same chain.
pub(crate) const FIXTURE_ISSUER_CERT: &[u8] = include_bytes!("../tests/fixtures/signer-issuer.der");

/// Self-signed certificate for the synthetic signer, so unit tests can
/// build manifests whose claim signatures genuinely verify.
pub(crate) const TEST_SIGNER_CERT: &[u8] = include_bytes!("../tests/fixtures/test-signer.der");

/// The matching private key. Generated for this repository and used only
/// to sign test data; it protects nothing.
pub(crate) const TEST_SIGNER_KEY: &[u8] = include_bytes!("../tests/fixtures/test-signer.key.pem");

/// Builds a `COSE_Sign1` claim signature over `claim_cbor` that verifies
/// against [`TEST_SIGNER_CERT`].
///
/// The `Sig_structure` is assembled here rather than by calling into
/// `cose.rs`, so that a test proving a signature verifies is not merely
/// proving the reader agrees with itself. If the two constructions ever
/// disagree, the signature stops verifying and the test says so.
pub(crate) fn claim_signature(claim_cbor: &[u8]) -> Vec<u8> {
    claim_signature_with_unprotected(claim_cbor, Value::Map(BTreeMap::new()))
}

/// As [`claim_signature`], but with a caller-chosen unprotected header
/// bucket — for tests that need to control what a timestamp header there
/// looks like.
///
/// The unprotected bucket carries no weight in the `Sig_structure` (RFC
/// 9052 only signs the protected one), so varying it here never touches
/// the signature itself.
pub(crate) fn claim_signature_with_unprotected(claim_cbor: &[u8], unprotected: Value) -> Vec<u8> {
    detached_signature(claim_cbor, unprotected)
}

/// Builds a detached-payload `COSE_Sign1` over `payload` that verifies
/// against [`TEST_SIGNER_CERT`] — what a claim signature and a CAWG
/// identity assertion's X.509 signature both are.
pub(crate) fn detached_signature(payload: &[u8], unprotected: Value) -> Vec<u8> {
    let protected = {
        let mut map = BTreeMap::new();
        // 1 = alg, -7 = ES256; 33 = x5chain.
        map.insert(Value::Integer(1), Value::Integer(-7));
        map.insert(
            Value::Integer(33),
            Value::Array(vec![Value::Bytes(TEST_SIGNER_CERT.to_vec())]),
        );
        c2pa_cbor::to_vec(&Value::Map(map)).unwrap()
    };

    let mut to_be_signed = Vec::new();
    cbor_head(&mut to_be_signed, 4, 4);
    cbor_head(&mut to_be_signed, 3, 10);
    to_be_signed.extend_from_slice(b"Signature1");
    cbor_bytes(&mut to_be_signed, &protected);
    cbor_bytes(&mut to_be_signed, &[]);
    cbor_bytes(&mut to_be_signed, payload);

    let signer = c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .unwrap();
    let signature = signer.sign(&to_be_signed).unwrap();

    c2pa_cbor::to_vec(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            unprotected,
            Value::Null,
            Value::Bytes(signature),
        ])),
    ))
    .unwrap()
}

/// Writes a CBOR definite-length head, shortest form.
fn cbor_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;

    match argument {
        0..=23 => out.push(major | argument as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, argument as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
    }
}

/// Writes a CBOR byte string.
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Extracts the CBOR payload from a claim box built by [`claim_box`].
///
/// Walks the JUMBF layout by hand — `jumb` header, `jumd` description box,
/// then the `cbor` content box — rather than reusing the reader.
fn claim_cbor(claim_box: &[u8]) -> &[u8] {
    let body = &claim_box[8..];
    let desc_len = u32::from_be_bytes(body[0..4].try_into().unwrap()) as usize;
    let content = &body[desc_len..];
    let content_len = u32::from_be_bytes(content[0..4].try_into().unwrap()) as usize;

    assert_eq!(&content[4..8], b"cbor", "claim box has no CBOR content");
    &content[8..content_len]
}

/// Builds a JUMBF type UUID from its four-character code.
pub(crate) const fn type_uuid(fourcc: [u8; 4]) -> [u8; 16] {
    [
        fourcc[0], fourcc[1], fourcc[2], fourcc[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa,
        0x00, 0x38, 0x9b, 0x71,
    ]
}

/// Builds a JUMBF box: 4-byte length, 4-byte type, payload.
pub(crate) fn boxed(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(box_type);
    out.extend_from_slice(payload);
    out
}

/// Builds a superbox with the given type UUID, label, and children.
pub(crate) fn superbox(uuid: [u8; 16], label: &str, children: &[Vec<u8>]) -> Vec<u8> {
    let mut desc = uuid.to_vec();
    desc.push(0b0000_0011); // requestable + label present
    desc.extend_from_slice(label.as_bytes());
    desc.push(0);

    let mut payload = boxed(b"jumd", &desc);
    for child in children {
        payload.extend_from_slice(child);
    }
    boxed(b"jumb", &payload)
}

/// Builds a claim box carrying the given title and no assertion
/// references.
pub(crate) fn claim_box(title: &str) -> Vec<u8> {
    claim_box_with_assertions(title, vec![])
}

/// Builds a claim box carrying the given title and hashed-URI references.
pub(crate) fn claim_box_with_assertions(title: &str, assertions: Vec<Value>) -> Vec<u8> {
    claim_box_with_alg(title, Some("sha256"), assertions)
}

/// Builds a claim box naming a specific hash algorithm, or none at all.
pub(crate) fn claim_box_with_alg(
    title: &str,
    alg: Option<&str>,
    assertions: Vec<Value>,
) -> Vec<u8> {
    let mut fields = BTreeMap::from([(
        Value::Text("dc:title".to_string()),
        Value::Text(title.to_string()),
    )]);

    if let Some(alg) = alg {
        fields.insert(Value::Text("alg".to_string()), Value::Text(alg.to_string()));
    }

    if !assertions.is_empty() {
        fields.insert(
            Value::Text("assertions".to_string()),
            Value::Array(assertions),
        );
    }

    let cbor = c2pa_cbor::to_vec(&Value::Map(fields)).unwrap();

    superbox(type_uuid(*b"c2cl"), "c2pa.claim", &[boxed(b"cbor", &cbor)])
}

/// Builds a conformant v2 claim box: every field the specification
/// requires (`instanceID`, `signature`, a single-map `claim_generator_info`
/// with a `name`, `created_assertions`), with `created_assertions` and
/// `gathered_assertions` in place of v1's flat `assertions` list.
pub(crate) fn claim_box_v2(
    title: &str,
    created_assertions: Vec<Value>,
    gathered_assertions: Vec<Value>,
) -> Vec<u8> {
    let mut fields = v2_required_fields();
    fields.insert(
        Value::Text("dc:title".to_string()),
        Value::Text(title.to_string()),
    );
    fields.insert(
        Value::Text("created_assertions".to_string()),
        Value::Array(created_assertions),
    );

    if !gathered_assertions.is_empty() {
        fields.insert(
            Value::Text("gathered_assertions".to_string()),
            Value::Array(gathered_assertions),
        );
    }

    claim_box_v2_from_fields(fields)
}

/// The required v2 claim fields except `created_assertions`.
pub(crate) fn v2_required_fields() -> BTreeMap<Value, Value> {
    BTreeMap::from([
        (
            Value::Text("instanceID".to_string()),
            Value::Text("xmp:iid:v2".to_string()),
        ),
        (
            Value::Text("signature".to_string()),
            Value::Text("self#jumbf=c2pa.signature".to_string()),
        ),
        (
            Value::Text("claim_generator_info".to_string()),
            Value::Map(BTreeMap::from([(
                Value::Text("name".to_string()),
                Value::Text("test".to_string()),
            )])),
        ),
    ])
}

/// Wraps arbitrary CBOR map fields in a `c2pa.claim.v2` claim box, for
/// tests that need a claim that departs from the specification.
pub(crate) fn claim_box_v2_from_fields(fields: BTreeMap<Value, Value>) -> Vec<u8> {
    let cbor = c2pa_cbor::to_vec(&Value::Map(fields)).unwrap();

    superbox(
        type_uuid(*b"c2cl"),
        "c2pa.claim.v2",
        &[boxed(b"cbor", &cbor)],
    )
}

/// Builds one hashed-URI reference to an assertion.
///
/// The hash is computed here over the assertion superbox's payload — the
/// bytes after its 8-byte header — which this module knows because it built
/// the box. That derivation is independent of how the reader extracts a
/// payload, so a match is real evidence rather than a tautology.
pub(crate) fn hashed_uri(label: &str, assertion_box: &[u8]) -> Value {
    hashed_uri_with_hash(label, Sha256::digest(&assertion_box[8..]).to_vec())
}

/// Builds a hashed-URI reference with an explicit (possibly wrong) hash.
pub(crate) fn hashed_uri_with_hash(label: &str, hash: Vec<u8>) -> Value {
    Value::Map(BTreeMap::from([
        (
            Value::Text("url".to_string()),
            Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
        ),
        (Value::Text("hash".to_string()), Value::Bytes(hash)),
    ]))
}

/// Builds an assertion superbox with the given label.
pub(crate) fn assertion_box(label: &str) -> Vec<u8> {
    superbox(type_uuid(*b"cbor"), label, &[boxed(b"cbor", &[0xa0])])
}

/// Builds a genuine `c2pa.hash.data` hard binding assertion naming a
/// specific hash algorithm.
pub(crate) fn data_hash_box_with_alg(
    exclusions: &[(u64, u64)],
    hash: Vec<u8>,
    alg: Option<&str>,
) -> Vec<u8> {
    let mut inner = data_hash_fields(exclusions, hash);
    if let Some(alg) = alg {
        inner.insert(Value::Text("alg".to_string()), Value::Text(alg.to_string()));
    }

    let cbor = c2pa_cbor::to_vec(&Value::Map(inner)).unwrap();
    superbox(
        type_uuid(*b"cbor"),
        "c2pa.hash.data",
        &[boxed(b"cbor", &cbor)],
    )
}

/// Builds a genuine `c2pa.hash.data` hard binding assertion.
pub(crate) fn data_hash_box(exclusions: &[(u64, u64)], hash: Vec<u8>) -> Vec<u8> {
    let cbor = c2pa_cbor::to_vec(&Value::Map(data_hash_fields(exclusions, hash))).unwrap();
    superbox(
        type_uuid(*b"cbor"),
        "c2pa.hash.data",
        &[boxed(b"cbor", &cbor)],
    )
}

/// The common fields of a hard binding assertion.
fn data_hash_fields(exclusions: &[(u64, u64)], hash: Vec<u8>) -> BTreeMap<Value, Value> {
    let exclusions: Vec<Value> = exclusions
        .iter()
        .map(|(start, length)| {
            Value::Map(BTreeMap::from([
                (
                    Value::Text("start".to_string()),
                    Value::Integer(*start as i64),
                ),
                (
                    Value::Text("length".to_string()),
                    Value::Integer(*length as i64),
                ),
            ]))
        })
        .collect();

    let mut fields = BTreeMap::from([
        (Value::Text("hash".to_string()), Value::Bytes(hash)),
        (
            Value::Text("name".to_string()),
            Value::Text("jumbf manifest".to_string()),
        ),
    ]);

    if !exclusions.is_empty() {
        fields.insert(
            Value::Text("exclusions".to_string()),
            Value::Array(exclusions),
        );
    }

    fields
}

/// Builds a manifest whose claim references each of its assertions with
/// the correct hash.
pub(crate) fn manifest(label: &str, title: &str, assertions: &[&str]) -> Vec<u8> {
    let boxes: Vec<Vec<u8>> = assertions.iter().map(|a| assertion_box(a)).collect();

    let refs: Vec<Value> = assertions
        .iter()
        .zip(&boxes)
        .map(|(label, bytes)| hashed_uri(label, bytes))
        .collect();

    manifest_with_claim(label, &boxes, claim_box_with_assertions(title, refs))
}

/// Builds a manifest around explicit assertion boxes and a claim box.
pub(crate) fn manifest_with_claim(
    label: &str,
    assertion_boxes: &[Vec<u8>],
    claim: Vec<u8>,
) -> Vec<u8> {
    let signature = claim_signature(claim_cbor(&claim));

    superbox(
        type_uuid(*b"c2ma"),
        label,
        &[
            superbox(type_uuid(*b"c2as"), "c2pa.assertions", assertion_boxes),
            claim,
            superbox(
                type_uuid(*b"c2cs"),
                "c2pa.signature",
                &[boxed(b"cbor", &signature)],
            ),
        ],
    )
}

/// Builds a manifest whose claim signature superbox is present but holds
/// no content box at all.
pub(crate) fn manifest_with_empty_signature_box(label: &str, claim: Vec<u8>) -> Vec<u8> {
    superbox(
        type_uuid(*b"c2ma"),
        label,
        &[
            superbox(type_uuid(*b"c2as"), "c2pa.assertions", &[]),
            claim,
            superbox(type_uuid(*b"c2cs"), "c2pa.signature", &[]),
        ],
    )
}

/// Builds a manifest with no claim signature superbox at all.
pub(crate) fn manifest_without_signature_box(label: &str, claim: Vec<u8>) -> Vec<u8> {
    superbox(
        type_uuid(*b"c2ma"),
        label,
        &[superbox(type_uuid(*b"c2as"), "c2pa.assertions", &[]), claim],
    )
}

/// Builds a manifest whose claim signature does not verify, by signing a
/// different claim than the one the manifest carries.
pub(crate) fn manifest_with_broken_signature(
    label: &str,
    assertion_boxes: &[Vec<u8>],
    claim: Vec<u8>,
) -> Vec<u8> {
    let signature = claim_signature(b"a claim this manifest does not contain");

    superbox(
        type_uuid(*b"c2ma"),
        label,
        &[
            superbox(type_uuid(*b"c2as"), "c2pa.assertions", assertion_boxes),
            claim,
            superbox(
                type_uuid(*b"c2cs"),
                "c2pa.signature",
                &[boxed(b"cbor", &signature)],
            ),
        ],
    )
}

/// Builds a manifest store around the given manifests.
pub(crate) fn manifest_store(manifests: &[Vec<u8>]) -> Vec<u8> {
    superbox(type_uuid(*b"c2pa"), "c2pa", manifests)
}

/// The asset the hard binding of an [`identity_manifest`] covers.
pub(crate) const IDENTITY_ASSET: &[u8] = b"an asset for the identity tests";

/// The hard binding of an [`identity_manifest`]: no exclusions, the whole
/// of [`IDENTITY_ASSET`].
fn identity_hard_binding() -> Vec<u8> {
    data_hash_box(&[], Sha256::digest(IDENTITY_ASSET).to_vec())
}

/// Everything a test may vary about a manifest carrying one CAWG identity
/// assertion, starting from a correct one. See [`identity_manifest`].
pub(crate) struct IdentityParts {
    /// What the identity assertion vouches for: label and hash. Starts as
    /// the host assertion and the hard binding, with their true hashes.
    pub(crate) referenced: Vec<(String, Vec<u8>)>,

    /// The `sig_type`.
    pub(crate) sig_type: String,

    /// The `role`s; none are written when empty.
    pub(crate) roles: Vec<String>,

    /// `pad1`.
    pub(crate) pad1: Vec<u8>,

    /// `pad2`, written only when present.
    pub(crate) pad2: Option<Vec<u8>>,

    /// Bytes to sign instead of the real `signer_payload`, so the
    /// signature does not verify.
    pub(crate) sign_instead: Option<Vec<u8>>,

    /// The `COSE_Sign1` unprotected header.
    pub(crate) unprotected: Value,

    /// Edits the `signer_payload` map *before* it is signed.
    pub(crate) edit_payload: Option<fn(&mut BTreeMap<Value, Value>)>,

    /// Edits the assertion's top-level map *after* signing.
    pub(crate) edit_assertion: Option<fn(&mut BTreeMap<Value, Value>)>,

    /// Replaces the assertion's CBOR wholesale.
    pub(crate) raw_cbor: Option<Vec<u8>>,

    /// Labels of the other assertions in the claim to list, besides the
    /// hard binding and identity assertion; the host assertion
    /// `a.test` is always built.
    pub(crate) omit_from_claim: Vec<String>,

    /// Replaces the signature field with these bytes.
    pub(crate) signature_override: Option<Vec<u8>>,
}

impl Default for IdentityParts {
    fn default() -> Self {
        let a = assertion_box("a.test");
        let hash = identity_hard_binding();

        Self {
            referenced: vec![
                ("a.test".to_string(), Sha256::digest(&a[8..]).to_vec()),
                (
                    "c2pa.hash.data".to_string(),
                    Sha256::digest(&hash[8..]).to_vec(),
                ),
            ],
            sig_type: "cawg.x509.cose".to_string(),
            roles: vec![],
            pad1: vec![],
            pad2: None,
            sign_instead: None,
            unprotected: Value::Map(BTreeMap::new()),
            edit_payload: None,
            edit_assertion: None,
            raw_cbor: None,
            omit_from_claim: vec![],
            signature_override: None,
        }
    }
}

/// Builds a v2 manifest with a host assertion (`a.test`), a hard binding,
/// and one identity assertion (`cawg.identity`), all listed in the claim
/// with true hashes; `adjust` makes the identity assertion wrong in
/// whatever way a test wants.
pub(crate) fn identity_manifest(adjust: impl FnOnce(&mut IdentityParts)) -> Vec<u8> {
    let mut parts = IdentityParts::default();
    adjust(&mut parts);

    let identity = identity_box("cawg.identity", &parts);
    identity_manifest_from(&parts, vec![identity])
}

/// As [`identity_manifest`], with identity assertion boxes of the test's
/// own making (in place of the one `parts` would build).
pub(crate) fn identity_manifest_from(parts: &IdentityParts, identities: Vec<Vec<u8>>) -> Vec<u8> {
    let a = assertion_box("a.test");
    let hash = identity_hard_binding();

    let mut boxes = vec![a, hash];
    boxes.extend(identities);

    let labels = ["a.test", "c2pa.hash.data", "cawg.identity"];
    let refs: Vec<Value> = boxes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let label = labels.get(i).copied().unwrap_or("cawg.identity__1");
            (label, b)
        })
        .filter(|(label, _)| !parts.omit_from_claim.iter().any(|o| o == label))
        .map(|(label, b)| hashed_uri(label, b))
        .collect();

    let claim = claim_box_v2("identity.jpg", refs, vec![]);
    manifest_with_claim("urn:uuid:identity", &boxes, claim)
}

/// Builds the identity assertion box for `parts`.
pub(crate) fn identity_box(label: &str, parts: &IdentityParts) -> Vec<u8> {
    if let Some(raw) = &parts.raw_cbor {
        return superbox(type_uuid(*b"cbor"), label, &[boxed(b"cbor", raw)]);
    }

    let mut payload = BTreeMap::from([
        (
            Value::Text("referenced_assertions".to_string()),
            Value::Array(
                parts
                    .referenced
                    .iter()
                    .map(|(label, hash)| hashed_uri_with_hash(label, hash.clone()))
                    .collect(),
            ),
        ),
        (
            Value::Text("sig_type".to_string()),
            Value::Text(parts.sig_type.clone()),
        ),
    ]);

    if !parts.roles.is_empty() {
        payload.insert(
            Value::Text("role".to_string()),
            Value::Array(parts.roles.iter().cloned().map(Value::Text).collect()),
        );
    }

    if let Some(edit) = parts.edit_payload {
        edit(&mut payload);
    }

    let payload = Value::Map(payload);
    let payload_bytes = c2pa_cbor::to_vec(&payload).unwrap();

    let signature = parts.signature_override.clone().unwrap_or_else(|| {
        detached_signature(
            parts.sign_instead.as_deref().unwrap_or(&payload_bytes),
            parts.unprotected.clone(),
        )
    });

    let mut fields = BTreeMap::from([
        (Value::Text("signer_payload".to_string()), payload),
        (
            Value::Text("signature".to_string()),
            Value::Bytes(signature),
        ),
        (
            Value::Text("pad1".to_string()),
            Value::Bytes(parts.pad1.clone()),
        ),
    ]);

    if let Some(pad2) = &parts.pad2 {
        fields.insert(Value::Text("pad2".to_string()), Value::Bytes(pad2.clone()));
    }

    if let Some(edit) = parts.edit_assertion {
        edit(&mut fields);
    }

    let cbor = c2pa_cbor::to_vec(&Value::Map(fields)).unwrap();
    superbox(type_uuid(*b"cbor"), label, &[boxed(b"cbor", &cbor)])
}
