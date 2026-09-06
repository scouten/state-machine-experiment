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

//! Interpretation of a C2PA manifest store's JUMBF structure.
//!
//! JUMBF parsing itself comes from the [`jumbf`] crate, whose parser is
//! zero-copy — parsed boxes borrow from the host's bytes. This module walks
//! the box tree it produces, decodes each manifest's claim, and builds the
//! owned summaries that populate a [`ReadReport`].
//!
//! [`ReadReport`]: crate::read::ReadReport

use jumbf::{
    parser::{ChildBox, SuperBox},
    BoxType,
};

use crate::{
    chain::PendingChain,
    claim::{self, Claim, ClaimVersion},
    data_hash::{self, DataHash},
    error::Error,
    validation::{self, status_code, ValidationStatus},
};

/// Maximum superbox nesting depth accepted when parsing a manifest store.
///
/// Manifest store bytes come from the host and are not trusted, so the
/// depth is bounded rather than left to the input: a real store nests only
/// a handful of levels deep (store → manifest → assertion store →
/// assertion), while an adversarial one could otherwise drive unbounded
/// recursion. Boxes deeper than this are left unparsed as opaque data
/// boxes, so an over-nested store reads as structurally incomplete rather
/// than exhausting the stack.
const MAX_BOX_DEPTH: usize = 16;

/// Builds a JUMBF type UUID from its four-character code.
///
/// C2PA's box type UUIDs are all the four-character code followed by the
/// same 12-byte suffix (see the `CAI_*_UUID` constants in c2pa-rs).
pub(crate) const fn type_uuid(fourcc: [u8; 4]) -> [u8; 16] {
    [
        fourcc[0], fourcc[1], fourcc[2], fourcc[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa,
        0x00, 0x38, 0x9b, 0x71,
    ]
}

/// Type UUID of the manifest store superbox.
pub(crate) const MANIFEST_STORE_UUID: [u8; 16] = type_uuid(*b"c2pa");

/// Type UUID of a manifest's assertion store superbox.
pub(crate) const ASSERTIONS_UUID: [u8; 16] = type_uuid(*b"c2as");

/// Type UUID of a manifest's claim superbox.
pub(crate) const CLAIM_UUID: [u8; 16] = type_uuid(*b"c2cl");

/// JUMBF label of a v2 claim box, as opposed to a v1 claim's `c2pa.claim`.
pub(crate) const CLAIM_V2_LABEL: &str = "c2pa.claim.v2";

/// Type UUID of a manifest's claim signature superbox.
pub(crate) const SIGNATURE_UUID: [u8; 16] = type_uuid(*b"c2cs");

/// Box type of a CBOR content box.
pub(crate) const CBOR: BoxType = BoxType(*b"cbor");

/// One manifest read out of a manifest store.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Manifest {
    /// The manifest's JUMBF label, which is its identifier within the
    /// store (typically a `urn:uuid:` string).
    pub label: String,

    /// The manifest's decoded claim.
    pub claim: Claim,

    /// Labels of the assertions physically present in this manifest's
    /// assertion store, in store order.
    ///
    /// Reconciling these against the claim's assertion references (see
    /// [`Claim::assertion_references`]) — and verifying each assertion's
    /// hash — is a validation concern, not a reading one.
    pub assertion_labels: Vec<String>,

    /// True if the manifest carries a claim signature box.
    ///
    /// Whether that signature *verifies* is a validation finding rather
    /// than a property of the manifest, and is reported as a status.
    pub has_signature: bool,

    /// The manifest's hard binding to its asset, if it carries a
    /// well-formed `c2pa.hash.data` assertion.
    ///
    /// `None` covers both "no hard binding present" and "present but
    /// malformed"; the latter also records a validation status.
    pub data_hash: Option<DataHash>,
}

/// The result of reading a manifest store.
#[derive(Debug)]
pub(crate) struct ParsedManifestStore {
    /// Manifests in store order.
    pub(crate) manifests: Vec<Manifest>,

    /// Label of the active manifest, if the store contains any.
    pub(crate) active_manifest: Option<String>,

    /// Validation findings recorded while reading.
    pub(crate) statuses: Vec<ValidationStatus>,

    /// The certificate chains of the claim signatures that verified,
    /// awaiting a time to be evaluated against.
    ///
    /// Correlated back to [`Self::manifests`] by
    /// [`PendingChain::manifest_label`](crate::chain::PendingChain), not by
    /// position: not every manifest's claim signature verifies, so this is
    /// shorter than `manifests` whenever one does not.
    ///
    /// Owned rather than borrowed from `bytes`: the evaluation happens
    /// after the host has been asked for the current time, by which point
    /// the store bytes are long gone.
    pub(crate) chains: Vec<PendingChain>,
}

/// Reads a manifest store from its JUMBF bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<ParsedManifestStore, Error> {
    let (manifest_store, _rest) = SuperBox::from_slice_with_depth_limit(bytes, MAX_BOX_DEPTH)?;

    if manifest_store.desc.uuid != &MANIFEST_STORE_UUID {
        return Err(Error::NotAManifestStore);
    }

    let mut statuses = Vec::new();
    let mut chains = Vec::new();
    let mut manifests = Vec::new();

    for manifest in child_superboxes(&manifest_store) {
        manifests.push(read_manifest(manifest, &mut statuses, &mut chains)?);
    }

    // The C2PA specification defines the active manifest as the last
    // manifest in the store.
    let active_manifest = manifests.last().map(|m| m.label.clone());

    Ok(ParsedManifestStore {
        manifests,
        active_manifest,
        statuses,
        chains,
    })
}

/// Returns a superbox's child superboxes, in order.
fn child_superboxes<'a>(parent: &'a SuperBox<'a>) -> impl Iterator<Item = &'a SuperBox<'a>> {
    parent.child_boxes.iter().filter_map(|child| match child {
        ChildBox::SuperBox(sbox) => Some(sbox),
        ChildBox::DataBox(_) => None,
    })
}

/// Returns the first child superbox carrying the given type UUID.
///
/// JUMBF identifies a box's *type* by UUID; the label is its *identity*
/// within the enclosing box. Structural lookups therefore go by UUID, so a
/// box merely *labelled* `c2pa.claim` is never mistaken for the claim.
fn child_by_uuid<'a>(parent: &'a SuperBox<'a>, uuid: &[u8; 16]) -> Option<&'a SuperBox<'a>> {
    child_superboxes(parent).find(|sbox| sbox.desc.uuid == uuid)
}

/// Returns the payload of a superbox's first data box of the given type.
fn content<'a>(parent: &'a SuperBox<'a>, box_type: BoxType) -> Option<&'a [u8]> {
    parent.child_boxes.iter().find_map(|child| match child {
        ChildBox::DataBox(dbox) if dbox.tbox == box_type => Some(dbox.data),
        _ => None,
    })
}

/// Reads one manifest superbox.
fn read_manifest(
    manifest: &SuperBox<'_>,
    statuses: &mut Vec<ValidationStatus>,
    chains: &mut Vec<PendingChain>,
) -> Result<Manifest, Error> {
    let label = manifest
        .desc
        .label
        .ok_or(Error::MalformedManifest {
            manifest: String::new(),
            reason: "manifest superbox has no label",
        })?
        .to_string();

    let claim_box =
        child_by_uuid(manifest, &CLAIM_UUID).ok_or_else(|| Error::MalformedManifest {
            manifest: label.clone(),
            reason: "manifest has no claim box",
        })?;

    let claim_cbor = content(claim_box, CBOR).ok_or_else(|| Error::MalformedManifest {
        manifest: label.clone(),
        reason: "claim box has no CBOR content",
    })?;

    // The claim box's own label is what the C2PA specification uses to
    // distinguish a v2 claim from a v1 one; anything other than the
    // reserved v2 label (including no label at all) reads as v1, the
    // long-standing default.
    let version = if claim_box.desc.label == Some(CLAIM_V2_LABEL) {
        ClaimVersion::V2
    } else {
        ClaimVersion::V1
    };

    let claim = claim::decode(claim_cbor, version).map_err(|source| Error::MalformedClaim {
        manifest: label.clone(),
        source,
    })?;

    validation::check_assertion_hashes(manifest, &claim, statuses);

    // The claim signature commits to the claim box's CBOR, which is why
    // both are read here rather than carried out to the report: the
    // signature's detached payload is the sibling box's bytes.
    let signature = child_by_uuid(manifest, &SIGNATURE_UUID);
    chains.extend(validation::check_claim_signature(
        &label,
        claim_cbor,
        match signature.map(|sbox| content(sbox, CBOR)) {
            None => validation::SignatureBox::Absent,
            Some(None) => validation::SignatureBox::Empty,
            Some(Some(bytes)) => validation::SignatureBox::Present(bytes),
        },
        statuses,
    ));

    let assertion_labels = child_by_uuid(manifest, &ASSERTIONS_UUID)
        .map(|assertions| {
            child_superboxes(assertions)
                .filter_map(|a| a.desc.label.map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let data_hash = read_data_hash(manifest, statuses);

    Ok(Manifest {
        label,
        claim,
        assertion_labels,
        has_signature: signature.is_some(),
        data_hash,
    })
}

/// Decodes the manifest's hard binding, if it has one.
///
/// A binding that is present but undecodable is a validation finding, not
/// a read failure, so it is recorded and reported as absent.
fn read_data_hash(
    manifest: &SuperBox<'_>,
    statuses: &mut Vec<ValidationStatus>,
) -> Option<DataHash> {
    let assertions = child_by_uuid(manifest, &ASSERTIONS_UUID)?;
    let binding = assertions
        .child_boxes
        .iter()
        .filter_map(|child| match child {
            ChildBox::SuperBox(sbox) if sbox.desc.label == Some(data_hash::LABEL) => Some(sbox),
            _ => None,
        })
        .next()?;

    match content(binding, CBOR).and_then(data_hash::decode) {
        Some(decoded) => Some(decoded),
        None => {
            statuses.push(ValidationStatus::for_url(
                status_code::ASSERTION_DATAHASH_MALFORMED,
                &format!("self#jumbf=c2pa.assertions/{}", data_hash::LABEL),
                "hard binding assertion could not be interpreted",
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use c2pa_cbor::Value;

    use super::*;
    use crate::{
        test_support::{
            assertion_box, boxed, claim_box, claim_box_v2, claim_box_with_alg,
            claim_box_with_assertions, hashed_uri, hashed_uri_with_hash, manifest, manifest_store,
            manifest_with_claim, superbox,
        },
        validation::status_code,
    };

    /// A manifest superbox's type UUID.
    const MANIFEST_UUID: [u8; 16] = type_uuid(*b"c2ma");

    #[test]
    fn reads_a_single_manifest_store() {
        let bytes = manifest_store(&[manifest(
            "urn:uuid:one",
            "A.jpg",
            &["c2pa.actions", "c2pa.hash.data"],
        )]);

        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.manifests.len(), 1);
        assert_eq!(parsed.active_manifest.as_deref(), Some("urn:uuid:one"));

        let m = &parsed.manifests[0];
        assert_eq!(m.label, "urn:uuid:one");
        assert_eq!(m.claim.version, ClaimVersion::V1);
        assert_eq!(m.claim.title.as_deref(), Some("A.jpg"));
        assert_eq!(m.assertion_labels, ["c2pa.actions", "c2pa.hash.data"]);
        assert!(m.has_signature);
    }

    #[test]
    fn active_manifest_is_the_last_one() {
        let bytes = manifest_store(&[
            manifest("urn:uuid:first", "first.jpg", &[]),
            manifest("urn:uuid:second", "second.jpg", &[]),
            manifest("urn:uuid:third", "third.jpg", &[]),
        ]);

        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.manifests.len(), 3);
        assert_eq!(parsed.active_manifest.as_deref(), Some("urn:uuid:third"));
        assert_eq!(
            parsed.manifests[0].claim.title.as_deref(),
            Some("first.jpg")
        );
    }

    #[test]
    fn empty_store_has_no_active_manifest() {
        let parsed = parse(&manifest_store(&[])).unwrap();
        assert!(parsed.manifests.is_empty());
        assert_eq!(parsed.active_manifest, None);
    }

    #[test]
    fn manifest_without_assertion_store_reads_with_no_labels() {
        let bytes = manifest_store(&[superbox(
            MANIFEST_UUID,
            "urn:uuid:bare",
            &[claim_box("bare.jpg")],
        )]);

        let parsed = parse(&bytes).unwrap();
        assert!(parsed.manifests[0].assertion_labels.is_empty());
        assert!(!parsed.manifests[0].has_signature);
    }

    #[test]
    fn boxes_are_matched_by_uuid_not_label() {
        // A box labelled like a claim but carrying the assertion store's
        // type UUID must not be read as the claim.
        let bytes = manifest_store(&[superbox(
            MANIFEST_UUID,
            "urn:uuid:mislabelled",
            &[superbox(ASSERTIONS_UUID, "c2pa.claim", &[])],
        )]);

        assert!(matches!(
            parse(&bytes),
            Err(Error::MalformedManifest {
                reason: "manifest has no claim box",
                ..
            })
        ));
    }

    #[test]
    fn rejects_store_with_wrong_uuid() {
        let bytes = superbox(type_uuid(*b"c2ma"), "c2pa", &[]);
        assert!(matches!(parse(&bytes), Err(Error::NotAManifestStore)));
    }

    #[test]
    fn rejects_manifest_without_claim() {
        let bytes = manifest_store(&[superbox(
            MANIFEST_UUID,
            "urn:uuid:no-claim",
            &[superbox(ASSERTIONS_UUID, "c2pa.assertions", &[])],
        )]);

        assert!(matches!(
            parse(&bytes),
            Err(Error::MalformedManifest {
                reason: "manifest has no claim box",
                ..
            })
        ));
    }

    #[test]
    fn rejects_claim_box_without_cbor() {
        let bytes = manifest_store(&[superbox(
            MANIFEST_UUID,
            "urn:uuid:x",
            &[superbox(CLAIM_UUID, "c2pa.claim", &[])],
        )]);

        assert!(matches!(
            parse(&bytes),
            Err(Error::MalformedManifest {
                reason: "claim box has no CBOR content",
                ..
            })
        ));
    }

    #[test]
    fn rejects_undecodable_claim() {
        let bytes = manifest_store(&[superbox(
            MANIFEST_UUID,
            "urn:uuid:bad-claim",
            &[superbox(
                CLAIM_UUID,
                "c2pa.claim",
                &[boxed(b"cbor", &[0xff, 0xff])],
            )],
        )]);

        assert!(matches!(
            parse(&bytes),
            Err(Error::MalformedClaim { manifest, .. }) if manifest == "urn:uuid:bad-claim"
        ));
    }

    #[test]
    fn stray_data_boxes_are_skipped() {
        let cbor = c2pa_cbor::to_vec(&Value::Map(BTreeMap::from([(
            Value::Text("dc:title".to_string()),
            Value::Text("mixed.jpg".to_string()),
        )])))
        .unwrap();

        // The claim box carries an unrelated JSON data box ahead of its
        // CBOR, and the store carries a loose data box among its
        // manifests. Neither should disturb the walk.
        let claim = superbox(
            CLAIM_UUID,
            "c2pa.claim",
            &[boxed(b"json", b"{}"), boxed(b"cbor", &cbor)],
        );

        let bytes = manifest_store(&[
            superbox(MANIFEST_UUID, "urn:uuid:mixed", &[claim]),
            boxed(b"json", b"{}"),
        ]);

        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.manifests.len(), 1);
        assert_eq!(
            parsed.manifests[0].claim.title.as_deref(),
            Some("mixed.jpg")
        );
    }

    #[test]
    fn deeply_nested_input_is_bounded_rather_than_fatal() {
        // Wrap a claim in far more nesting than MAX_BOX_DEPTH allows.
        // Parsing stops descending instead of recursing without bound, so
        // the manifest reads as structurally incomplete rather than
        // exhausting the stack.
        let mut nested = claim_box("deep.jpg");
        for _ in 0..(MAX_BOX_DEPTH + 8) {
            nested = superbox(MANIFEST_UUID, "nested", &[nested]);
        }

        let bytes = manifest_store(&[superbox(MANIFEST_UUID, "urn:uuid:deep", &[nested])]);

        assert!(matches!(
            parse(&bytes),
            Err(Error::MalformedManifest {
                reason: "manifest has no claim box",
                ..
            })
        ));
    }

    /// Reads a store built from one manifest and returns its statuses as
    /// (code, url) pairs.
    fn statuses_of(manifest_bytes: Vec<u8>) -> Vec<(String, Option<String>)> {
        let parsed = parse(&manifest_store(&[manifest_bytes])).unwrap();
        parsed
            .statuses
            .into_iter()
            .map(|s| (s.code, s.url))
            .collect()
    }

    #[test]
    fn correct_assertion_hashes_are_reported_as_matches() {
        let parsed = parse(&manifest_store(&[manifest(
            "urn:uuid:ok",
            "ok.jpg",
            &["c2pa.actions"],
        )]))
        .unwrap();

        // One per assertion reference, plus the claim signature.
        assert_eq!(parsed.statuses.len(), 2);
        assert_eq!(
            parsed.statuses[0].code,
            status_code::ASSERTION_HASHEDURI_MATCH
        );
        assert_eq!(
            parsed.statuses[1].code,
            status_code::CLAIM_SIGNATURE_VALIDATED
        );
        assert!(
            parsed.statuses.iter().all(|s| !s.is_failure()),
            "an intact manifest records no failures"
        );
    }

    #[test]
    fn a_wrong_assertion_hash_is_a_mismatch_and_invalidates_the_store() {
        let assertion = assertion_box("c2pa.actions");
        let claim = claim_box_with_assertions(
            "bad.jpg",
            vec![hashed_uri_with_hash("c2pa.actions", vec![0u8; 32])],
        );

        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:bad", &[assertion], claim)]);
        let parsed = parse(&bytes).unwrap();

        assert_eq!(
            parsed.statuses[0].code,
            status_code::ASSERTION_HASHEDURI_MISMATCH
        );
        assert!(parsed.statuses[0].is_failure());
    }

    #[test]
    fn a_v2_claims_created_and_gathered_assertions_are_both_hash_checked() {
        let created = assertion_box("c2pa.actions");
        let gathered = assertion_box("c2pa.ingredient");

        let claim = claim_box_v2(
            "v2.jpg",
            vec![hashed_uri("c2pa.actions", &created)],
            vec![hashed_uri("c2pa.ingredient", &gathered)],
        );

        let bytes = manifest_store(&[manifest_with_claim(
            "urn:uuid:v2",
            &[created, gathered],
            claim,
        )]);

        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.manifests[0].claim.version, ClaimVersion::V2);
        assert_eq!(parsed.manifests[0].claim.created_assertions.len(), 1);
        assert_eq!(parsed.manifests[0].claim.gathered_assertions.len(), 1);
        assert!(parsed.manifests[0].claim.assertions.is_empty());

        assert_eq!(
            parsed
                .statuses
                .iter()
                .filter(|s| s.code == status_code::ASSERTION_HASHEDURI_MATCH)
                .count(),
            2,
            "both the created and gathered assertion references should be hash-checked"
        );
        assert!(parsed.statuses.iter().all(|s| !s.is_failure()));
    }

    #[test]
    fn a_reference_to_an_absent_assertion_is_reported_missing() {
        // The claim references an assertion the store does not contain.
        let claim = claim_box_with_assertions(
            "gone.jpg",
            vec![hashed_uri_with_hash("c2pa.actions", vec![0u8; 32])],
        );

        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:gone", &[], claim)]);
        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.statuses[0].code, status_code::HASHED_URI_MISSING);

        // Nothing was checked and found wrong, so this is not a failure.
        assert!(!parsed.statuses[0].is_failure());
    }

    #[test]
    fn an_unsupported_algorithm_is_reported_rather_than_substituted() {
        let assertion = assertion_box("c2pa.actions");
        let claim = claim_box_with_alg(
            "sha1.jpg",
            Some("sha1"),
            vec![hashed_uri("c2pa.actions", &assertion)],
        );

        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:sha1", &[assertion], claim)]);
        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.statuses[0].code, status_code::ALGORITHM_UNSUPPORTED);
        assert!(!parsed.statuses[0].is_failure());
    }

    #[test]
    fn a_claim_naming_no_algorithm_defaults_to_sha256() {
        let assertion = assertion_box("c2pa.actions");
        let claim = claim_box_with_alg(
            "default.jpg",
            None,
            vec![hashed_uri("c2pa.actions", &assertion)],
        );

        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:default", &[assertion], claim)]);

        assert_eq!(
            parse(&bytes).unwrap().statuses[0].code,
            status_code::ASSERTION_HASHEDURI_MATCH
        );
    }

    #[test]
    fn statuses_carry_the_uri_they_pertain_to() {
        let codes = statuses_of(manifest("urn:uuid:u", "u.jpg", &["c2pa.actions"]));
        assert_eq!(
            codes,
            [
                (
                    status_code::ASSERTION_HASHEDURI_MATCH.to_string(),
                    Some("self#jumbf=c2pa.assertions/c2pa.actions".to_string())
                ),
                (
                    status_code::CLAIM_SIGNATURE_VALIDATED.to_string(),
                    Some("self#jumbf=/c2pa/urn:uuid:u/c2pa.signature".to_string())
                )
            ]
        );
    }

    #[test]
    fn a_store_with_no_manifests_records_nothing() {
        let parsed = parse(&manifest_store(&[])).unwrap();
        assert!(parsed.manifests.is_empty());
        assert!(parsed.statuses.is_empty());
    }

    #[test]
    fn rejects_malformed_jumbf() {
        assert!(matches!(
            parse(&[0, 0, 0]),
            Err(Error::MalformedManifestStore(_))
        ));
    }
}
