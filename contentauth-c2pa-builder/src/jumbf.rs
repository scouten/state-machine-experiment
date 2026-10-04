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

//! Assembles a C2PA manifest store's JUMBF structure via
//! [`jumbf::builder`], and patches in the values that are only known after
//! the host has embedded a placeholder and this crate has hashed and
//! signed the result.
//!
//! # The two-pass shape
//!
//! [`ManifestBuilder::build_placeholder`] renders the *entire* manifest
//! store once, with three [`PlaceholderDataBox`]es standing in for the
//! `c2pa.hash.data` assertion's CBOR, the claim's CBOR, and the claim
//! signature's CBOR — each sized from a "dummy" encoding computed with
//! [`crate::data_hash`], [`crate::claim`], and [`crate::cose`], which are
//! all designed so their real encodings (computed once the real values are
//! known) total exactly the same lengths. That means `replace_payload`
//! always succeeds and the buffer never needs to be resized or
//! reassembled — one `Vec<u8>`, patched in place, twice.

use std::io::Cursor;

use contentauth_c2pa_primitives::{ByteRange, HashAlgorithm, SigningAlg};
use jumbf::{
    builder::{DataBoxBuilder, PlaceholderDataBox, SuperBoxBuilder, ToBox},
    BoxType,
};

use crate::{
    builder::AssertionKind,
    claim::{self, ClaimFields},
    cose, data_hash,
    error::Error,
};

/// Builds a JUMBF type UUID from its four-character code.
///
/// C2PA's box type UUIDs are all the four-character code followed by the
/// same 12-byte suffix (matches
/// `contentauth_c2pa_reader::manifest_store`'s copy of the same helper).
const fn type_uuid(fourcc: [u8; 4]) -> [u8; 16] {
    [
        fourcc[0], fourcc[1], fourcc[2], fourcc[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa,
        0x00, 0x38, 0x9b, 0x71,
    ]
}

const MANIFEST_STORE_UUID: [u8; 16] = type_uuid(*b"c2pa");
const MANIFEST_UUID: [u8; 16] = type_uuid(*b"c2ma");
const ASSERTIONS_STORE_UUID: [u8; 16] = type_uuid(*b"c2as");
const ASSERTION_UUID: [u8; 16] = type_uuid(*b"cbor");
const CLAIM_UUID: [u8; 16] = type_uuid(*b"c2cl");
const SIGNATURE_UUID: [u8; 16] = type_uuid(*b"c2cs");

/// Box type of a CBOR content box.
const CBOR_BOX_TYPE: BoxType = BoxType(*b"cbor");

const MANIFEST_STORE_LABEL: &str = "c2pa";
const ASSERTIONS_LABEL: &str = "c2pa.assertions";
const CLAIM_LABEL: &str = "c2pa.claim.v2";
const SIGNATURE_LABEL: &str = "c2pa.signature";

/// A hashed-URI reference to an assertion, as `(url, hash)` — what
/// `claim::encode` takes for each of `created_assertions` and
/// `gathered_assertions`.
type AssertionRef = (String, Vec<u8>);

/// An [`AssertionRef`] paired with the [`AssertionKind`] that says which
/// of the claim's two assertion lists it belongs in.
type KindedAssertionRef = (String, Vec<u8>, AssertionKind);

/// One assertion to be embedded, as supplied by
/// [`BuilderSettings::assertions`](crate::BuilderSettings::assertions).
pub(crate) struct AssertionInput<'a> {
    pub(crate) label: &'a str,
    pub(crate) cbor: &'a [u8],
    pub(crate) kind: AssertionKind,
}

/// Everything [`ManifestBuilder::build_placeholder`] needs, decoupled from
/// [`crate::BuilderSettings`] so this module can be exercised
/// independently of it.
pub(crate) struct ManifestInputs<'a> {
    pub(crate) manifest_label: &'a str,
    pub(crate) title: Option<&'a str>,
    pub(crate) instance_id: &'a str,
    pub(crate) generator_name: &'a str,
    pub(crate) generator_version: &'a str,
    pub(crate) assertions: &'a [AssertionInput<'a>],
    pub(crate) signing_alg: SigningAlg,
    pub(crate) certificates: &'a [Vec<u8>],
    pub(crate) signature_len: usize,
    pub(crate) timestamp_reserve: Option<usize>,
}

/// Assembles a manifest store's JUMBF bytes and holds the state needed to
/// patch in the hard binding, signature, and (if configured) timestamp
/// once each becomes known.
///
/// Does not derive `Debug`: `jumbf::builder::PlaceholderDataBox` does not
/// implement it. [`std::fmt::Debug`] is implemented by hand below,
/// reporting only the buffer's length rather than the placeholders'
/// internal state.
pub(crate) struct ManifestBuilder {
    buffer: Vec<u8>,
    data_hash_placeholder: PlaceholderDataBox,
    claim_placeholder: PlaceholderDataBox,
    signature_placeholder: PlaceholderDataBox,

    assertion_refs: Vec<KindedAssertionRef>,
    hash_alg: HashAlgorithm,
    protected_header: Vec<u8>,
    signature_len: usize,
    timestamp_reserve: Option<usize>,

    title: Option<String>,
    instance_id: String,
    generator_name: String,
    generator_version: String,
}

impl ManifestBuilder {
    /// Builds the placeholder manifest store: every fixed field is final,
    /// every variable one (the hard binding's hash and exclusion, the
    /// signature, the timestamp) is zero-filled at exactly the length its
    /// real value will occupy.
    pub(crate) fn build_placeholder(inputs: &ManifestInputs<'_>) -> Result<Self, Error> {
        let hash_alg = inputs.signing_alg.claim_hash_algorithm();
        let protected_header = cose::protected_header(inputs.signing_alg, inputs.certificates)?;

        // Non-hard-binding assertions: rendered once, each contributing a
        // hashed-URI reference the claim carries unchanged from here on.
        let mut assertions_builder =
            SuperBoxBuilder::new(&ASSERTIONS_STORE_UUID).set_label(ASSERTIONS_LABEL);
        let mut assertion_refs = Vec::with_capacity(inputs.assertions.len());

        for assertion in inputs.assertions {
            let sbox = SuperBoxBuilder::new(&ASSERTION_UUID)
                .set_label(assertion.label)
                .add_child_box(DataBoxBuilder::from_owned(
                    CBOR_BOX_TYPE,
                    assertion.cbor.to_vec(),
                ));

            let mut rendered = Cursor::new(Vec::new());
            sbox.write_jumbf(&mut rendered)?;
            let rendered = rendered.into_inner();

            assertion_refs.push((
                format!("self#jumbf=c2pa.assertions/{}", assertion.label),
                hash_alg.digest(&rendered[8..]),
                assertion.kind,
            ));

            assertions_builder = assertions_builder.add_child_box(sbox);
        }

        // The hard binding: placeholder exclusion and hash, both at their
        // final encoded lengths.
        let dummy_hash = vec![0u8; hash_alg.digest_len()];
        let dummy_data_hash_cbor = data_hash::encode(hash_alg, &dummy_hash, None)?;
        let data_hash_placeholder =
            PlaceholderDataBox::new(CBOR_BOX_TYPE, dummy_data_hash_cbor.len());

        let data_hash_sbox = SuperBoxBuilder::new(&ASSERTION_UUID)
            .set_label(data_hash::LABEL)
            .add_borrowed_child_box(&data_hash_placeholder);

        let assertions_sbox = assertions_builder.add_borrowed_child_box(&data_hash_sbox);

        // The claim: every reference final except the hard binding's own,
        // which is a fixed-length digest either way. The hard binding is
        // always this session's own creation, never gathered.
        let mut dummy_claim_refs = assertion_refs.clone();
        dummy_claim_refs.push((
            format!("self#jumbf=c2pa.assertions/{}", data_hash::LABEL),
            vec![0u8; hash_alg.digest_len()],
            AssertionKind::Created,
        ));
        let (dummy_created, dummy_gathered) = partition_by_kind(&dummy_claim_refs);

        let claim_fields = ClaimFields {
            title: inputs.title,
            instance_id: inputs.instance_id,
            generator_name: inputs.generator_name,
            generator_version: inputs.generator_version,
            alg_name: hash_alg.c2pa_name(),
        };
        let dummy_claim_cbor = claim::encode(&claim_fields, &dummy_created, &dummy_gathered)?;
        let claim_placeholder = PlaceholderDataBox::new(CBOR_BOX_TYPE, dummy_claim_cbor.len());

        let claim_sbox = SuperBoxBuilder::new(&CLAIM_UUID)
            .set_label(CLAIM_LABEL)
            .add_borrowed_child_box(&claim_placeholder);

        // The claim signature: zero-filled at its real, fixed length, with
        // a placeholder timestamp header if one was requested.
        let dummy_unprotected = cose::unprotected_header(None, inputs.timestamp_reserve)?;
        let dummy_signature = vec![0u8; inputs.signature_len];
        let dummy_cose =
            cose::build_cose_sign1(&protected_header, dummy_unprotected, &dummy_signature)?;
        let signature_placeholder = PlaceholderDataBox::new(CBOR_BOX_TYPE, dummy_cose.len());

        let signature_sbox = SuperBoxBuilder::new(&SIGNATURE_UUID)
            .set_label(SIGNATURE_LABEL)
            .add_borrowed_child_box(&signature_placeholder);

        let manifest_sbox = SuperBoxBuilder::new(&MANIFEST_UUID)
            .set_label(inputs.manifest_label)
            .add_borrowed_child_box(&assertions_sbox)
            .add_borrowed_child_box(&claim_sbox)
            .add_borrowed_child_box(&signature_sbox);

        let manifest_store_sbox = SuperBoxBuilder::new(&MANIFEST_STORE_UUID)
            .set_label(MANIFEST_STORE_LABEL)
            .add_borrowed_child_box(&manifest_sbox);

        let mut buffer = Cursor::new(Vec::new());
        manifest_store_sbox.write_jumbf(&mut buffer)?;

        Ok(Self {
            buffer: buffer.into_inner(),
            data_hash_placeholder,
            claim_placeholder,
            signature_placeholder,
            assertion_refs,
            hash_alg,
            protected_header,
            signature_len: inputs.signature_len,
            timestamp_reserve: inputs.timestamp_reserve,
            title: inputs.title.map(str::to_string),
            instance_id: inputs.instance_id.to_string(),
            generator_name: inputs.generator_name.to_string(),
            generator_version: inputs.generator_version.to_string(),
        })
    }

    /// The placeholder manifest store bytes, to hand to the host via
    /// `BuilderRequest::ReservePlaceholder`.
    pub(crate) fn placeholder_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Patches in the real hard binding, given the exclusion ranges the
    /// host reported and the digest this crate computed over the asset
    /// outside them. Returns the bytes the claim signature must cover.
    pub(crate) fn apply_hard_binding(
        &mut self,
        exclusions: &[ByteRange],
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let real_data_hash_cbor = data_hash::encode(self.hash_alg, &hash, Some(exclusions))?;
        check_len(&self.data_hash_placeholder, real_data_hash_cbor.len())?;

        let mut cursor = Cursor::new(std::mem::take(&mut self.buffer));
        self.data_hash_placeholder
            .replace_payload(&mut cursor, &real_data_hash_cbor)?;
        self.buffer = cursor.into_inner();

        // The claim's reference to the hard binding covers the assertion
        // box's own rendered bytes, which just changed.
        let data_hash_sbox = SuperBoxBuilder::new(&ASSERTION_UUID)
            .set_label(data_hash::LABEL)
            .add_child_box(DataBoxBuilder::from_owned(
                CBOR_BOX_TYPE,
                real_data_hash_cbor,
            ));
        let mut rendered = Cursor::new(Vec::new());
        data_hash_sbox.write_jumbf(&mut rendered)?;
        let data_hash_ref_hash = self.hash_alg.digest(&rendered.into_inner()[8..]);

        let mut claim_refs = self.assertion_refs.clone();
        claim_refs.push((
            format!("self#jumbf=c2pa.assertions/{}", data_hash::LABEL),
            data_hash_ref_hash,
            AssertionKind::Created,
        ));
        let (created, gathered) = partition_by_kind(&claim_refs);

        let claim_fields = ClaimFields {
            title: self.title.as_deref(),
            instance_id: &self.instance_id,
            generator_name: &self.generator_name,
            generator_version: &self.generator_version,
            alg_name: self.hash_alg.c2pa_name(),
        };
        let real_claim_cbor = claim::encode(&claim_fields, &created, &gathered)?;
        check_len(&self.claim_placeholder, real_claim_cbor.len())?;
        let to_be_signed = cose::claim_to_be_signed(&self.protected_header, &real_claim_cbor);

        let mut cursor = Cursor::new(std::mem::take(&mut self.buffer));
        self.claim_placeholder
            .replace_payload(&mut cursor, &real_claim_cbor)?;
        self.buffer = cursor.into_inner();

        Ok(to_be_signed)
    }

    /// The bytes an RFC 3161 timestamp must cover, given the real
    /// signature — `None` if this session was not configured to request
    /// one.
    pub(crate) fn countersigned_bytes(&self, signature: &[u8]) -> Option<Vec<u8>> {
        self.timestamp_reserve
            .map(|_| cose::countersigned(&self.protected_header, signature))
    }

    /// Patches in the real signature and, if configured, the real
    /// timestamp token, and returns the final manifest store bytes.
    ///
    /// `timestamp_token` must be `Some` if and only if this session was
    /// configured to request one — the caller (`BuilderSession`) is
    /// responsible for that pairing.
    pub(crate) fn finish(
        mut self,
        signature: &[u8],
        timestamp_token: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if signature.len() != self.signature_len {
            return Err(Error::SignatureLengthMismatch {
                expected: self.signature_len,
                actual: signature.len(),
            });
        }

        let unprotected = cose::unprotected_header(timestamp_token, self.timestamp_reserve)?;
        let real_cose = cose::build_cose_sign1(&self.protected_header, unprotected, signature)?;
        check_len(&self.signature_placeholder, real_cose.len())?;

        let mut cursor = Cursor::new(std::mem::take(&mut self.buffer));
        self.signature_placeholder
            .replace_payload(&mut cursor, &real_cose)?;
        Ok(cursor.into_inner())
    }
}

impl std::fmt::Debug for ManifestBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestBuilder")
            .field("buffer_len", &self.buffer.len())
            .field("hash_alg", &self.hash_alg)
            .field("signature_len", &self.signature_len)
            .field("timestamp_reserve", &self.timestamp_reserve)
            .finish_non_exhaustive()
    }
}

/// Splits assertion references into the claim's `created_assertions` and
/// `gathered_assertions` lists, each in original order.
///
/// The split is static — it depends only on which kind the host declared
/// each assertion to be, never on a value that changes between the
/// placeholder and final passes — so which key a reference lands under
/// never changes either, preserving the two-pass length invariant.
fn partition_by_kind(refs: &[KindedAssertionRef]) -> (Vec<AssertionRef>, Vec<AssertionRef>) {
    let mut created = Vec::new();
    let mut gathered = Vec::new();

    for (url, hash, kind) in refs {
        let target = match kind {
            AssertionKind::Created => &mut created,
            AssertionKind::Gathered => &mut gathered,
        };
        target.push((url.clone(), hash.clone()));
    }

    (created, gathered)
}

/// Verifies a real encoding matches its placeholder's reserved size
/// exactly — the two-pass length invariant this whole module depends on.
fn check_len(placeholder: &PlaceholderDataBox, actual: usize) -> Result<(), Error> {
    let expected = placeholder.payload_size()?;
    if expected != actual {
        return Err(Error::PlaceholderSizeMismatch(
            "a real encoding's length did not match its reserved placeholder size",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use jumbf::parser::SuperBox;

    use super::*;

    fn inputs<'a>(
        assertions: &'a [AssertionInput<'a>],
        certificates: &'a [Vec<u8>],
        timestamp_reserve: Option<usize>,
    ) -> ManifestInputs<'a> {
        ManifestInputs {
            manifest_label: "urn:uuid:test",
            title: Some("A.jpg"),
            instance_id: "xmp:iid:1234",
            generator_name: "test",
            generator_version: "1.0",
            assertions,
            signing_alg: SigningAlg::Es256,
            certificates,
            signature_len: 64,
            timestamp_reserve,
        }
    }

    /// Drives the full placeholder -> hard binding -> signature flow with
    /// no timestamp, and returns the final manifest bytes.
    fn build_and_finish(assertions: &[AssertionInput<'_>]) -> (usize, Vec<u8>) {
        let certificates = vec![vec![9u8; 32]];
        let mut manifest =
            ManifestBuilder::build_placeholder(&inputs(assertions, &certificates, None)).unwrap();

        let placeholder_len = manifest.placeholder_bytes().len();

        let exclusions = [ByteRange {
            start: 1234,
            len: placeholder_len as u64,
        }];
        let hash = vec![0xab; HashAlgorithm::Sha256.digest_len()];
        let to_be_signed = manifest.apply_hard_binding(&exclusions, hash).unwrap();
        assert!(!to_be_signed.is_empty());

        assert!(manifest.countersigned_bytes(&[0u8; 64]).is_none());

        let signature = vec![0x11u8; 64];
        let final_bytes = manifest.finish(&signature, None).unwrap();

        (placeholder_len, final_bytes)
    }

    #[test]
    fn final_bytes_are_the_same_length_as_the_placeholder() {
        let (placeholder_len, final_bytes) = build_and_finish(&[]);
        assert_eq!(placeholder_len, final_bytes.len());
    }

    #[test]
    fn final_bytes_are_a_well_formed_manifest_store() {
        let (_, final_bytes) = build_and_finish(&[]);

        let (store, rest) = SuperBox::from_slice(&final_bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(store.desc.uuid, &MANIFEST_STORE_UUID);
        assert_eq!(store.desc.label, Some(MANIFEST_STORE_LABEL));
    }

    #[test]
    fn non_hard_binding_assertions_are_embedded_and_reflected_in_the_claim() {
        let assertions = [AssertionInput {
            label: "c2pa.actions",
            cbor: &[0xa0], // an empty CBOR map, as a stand-in
            kind: AssertionKind::Created,
        }];

        let (placeholder_len, final_bytes) = build_and_finish(&assertions);
        assert_eq!(placeholder_len, final_bytes.len());

        let (store, _) = SuperBox::from_slice(&final_bytes).unwrap();
        // store -> manifest -> assertions store -> at least two children
        // (the real assertion, plus the hard binding).
        let manifest = match &store.child_boxes[0] {
            jumbf::parser::ChildBox::SuperBox(m) => m,
            jumbf::parser::ChildBox::DataBox(_) => panic!("expected a manifest superbox"),
        };
        let assertions_store = match &manifest.child_boxes[0] {
            jumbf::parser::ChildBox::SuperBox(a) => a,
            jumbf::parser::ChildBox::DataBox(_) => panic!("expected an assertions store"),
        };
        assert_eq!(assertions_store.child_boxes.len(), 2);
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let certificates = vec![vec![9u8; 32]];
        let mut manifest =
            ManifestBuilder::build_placeholder(&inputs(&[], &certificates, None)).unwrap();
        let placeholder_len = manifest.placeholder_bytes().len();

        manifest
            .apply_hard_binding(
                &[ByteRange {
                    start: 0,
                    len: placeholder_len as u64,
                }],
                vec![0u8; HashAlgorithm::Sha256.digest_len()],
            )
            .unwrap();

        assert!(matches!(
            manifest.finish(&[0u8; 63], None),
            Err(Error::SignatureLengthMismatch {
                expected: 64,
                actual: 63
            })
        ));
    }

    #[test]
    fn a_timestamp_is_requested_only_when_configured() {
        let certificates = vec![vec![9u8; 32]];
        let mut manifest =
            ManifestBuilder::build_placeholder(&inputs(&[], &certificates, Some(1000))).unwrap();
        let placeholder_len = manifest.placeholder_bytes().len();

        manifest
            .apply_hard_binding(
                &[ByteRange {
                    start: 0,
                    len: placeholder_len as u64,
                }],
                vec![0u8; HashAlgorithm::Sha256.digest_len()],
            )
            .unwrap();

        let signature = vec![0x22u8; 64];
        assert!(manifest.countersigned_bytes(&signature).is_some());

        let token = vec![0x33u8; 250];
        let final_bytes = manifest.finish(&signature, Some(&token)).unwrap();
        assert_eq!(placeholder_len, final_bytes.len());
    }
}
