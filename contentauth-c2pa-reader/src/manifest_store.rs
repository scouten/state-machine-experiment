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
    identity::{self, IdentityAssertion},
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

    /// Assertion payloads, in assertion-store order.
    ///
    /// Assertions using an unsupported encoding or malformed data remain visible
    /// in [`Self::assertion_labels`] but have no decoded value here.
    pub assertions: Vec<Assertion>,

    /// Embedded binary assertion payloads, in assertion-store order.
    ///
    /// These bytes are decoded content, not a separate trust verdict. Consult
    /// the report's validation statuses before relying on their provenance.
    pub resources: Vec<EmbeddedResource>,

    /// True if the manifest carries a claim signature box.
    ///
    /// Whether that signature *verifies* is a validation finding rather
    /// than a property of the manifest, and is reported as a status.
    pub has_signature: bool,

    /// Signer metadata for a cryptographically verified claim signature.
    ///
    /// This is not a trust verdict. A reported timestamp may be authentic but
    /// untrusted, and does not replace the host clock for validation.
    pub signature_info: Option<SignatureInfo>,

    /// The manifest's hard binding to its asset, if it carries a
    /// well-formed `c2pa.hash.data` assertion.
    ///
    /// `None` covers both "no hard binding present" and "present but
    /// malformed"; the latter also records a validation status.
    pub data_hash: Option<DataHash>,

    /// The CAWG identity assertions this manifest carries, in store
    /// order. An assertion whose CBOR could not be read at all is absent
    /// here and reported as a status instead.
    ///
    /// Each says what a named actor *claims*; whether the claim holds is
    /// in the report's statuses, which name an assertion by
    /// [`IdentityAssertion::url`].
    pub identity_assertions: Vec<IdentityAssertion>,
}

/// One assertion in the assertion store.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Assertion {
    /// Assertion label within the manifest.
    pub label: String,

    /// True when the claim lists this assertion as created.
    pub created: bool,

    /// Decoded CBOR payload.
    pub data: Option<c2pa_cbor::Value>,

    /// Decoded JSON payload, kept separate from CBOR to preserve JSON numbers
    /// and avoid interpreting JSON as a supported CBOR assertion.
    pub json_data: Option<serde_json::Value>,
}

impl Assertion {
    /// The ingredient assertion version, retaining unsupported numeric versions.
    ///
    /// Positional `__N` suffixes are ignored only when `N` contains digits.
    pub fn ingredient_version(&self) -> Option<&str> {
        let base = match self.label.rsplit_once("__") {
            Some((base, instance))
                if !instance.is_empty() && instance.bytes().all(|b| b.is_ascii_digit()) =>
            {
                base
            }
            _ => &self.label,
        };
        match base {
            "c2pa.ingredient" => Some("1"),
            _ => base.strip_prefix("c2pa.ingredient.v").filter(|version| {
                !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit())
            }),
        }
    }
}

/// A binary resource stored in an embedded-file assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EmbeddedResource {
    /// Assertion label within its manifest.
    pub label: String,
    /// Media type from the embedded-file description.
    pub format: String,
    /// Exact embedded-file data, excluding JUMBF framing.
    pub bytes: Vec<u8>,
}

/// Metadata decoded from a verified COSE signature and its signing certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SignatureInfo {
    /// Algorithm from the COSE protected header.
    pub alg: crate::SigningAlg,
    /// Organization in the signing certificate's subject.
    ///
    /// Compatibility reports call this `issuer`; it is not the issuer DN.
    pub organization: Option<String>,
    /// Common name in the signing certificate's subject.
    pub common_name: Option<String>,
    /// Certificate serial number as unsigned big-endian bytes.
    pub serial_number: Vec<u8>,
    /// RFC 3339 time from an authenticated, matching timestamp, if present.
    ///
    /// This does not imply that the timestamp authority is trusted.
    pub time: Option<String>,
}

const EMBEDDED_FILE_UUID: [u8; 16] = [
    0x40, 0xcb, 0x0c, 0x32, 0xbb, 0x8a, 0x48, 0x9d, 0xa7, 0x0b, 0x2a, 0xd6, 0xf4, 0x7f, 0x43, 0x69,
];

fn read_resources(store: &SuperBox<'_>, manifest: &str) -> Result<Vec<EmbeddedResource>, Error> {
    child_superboxes(store)
        .filter(|assertion| assertion.desc.uuid == &EMBEDDED_FILE_UUID)
        .map(|assertion| {
            let malformed = || Error::MalformedManifest {
                manifest: manifest.to_string(),
                reason: "malformed embedded-file assertion",
            };
            let label = assertion.desc.label.ok_or_else(malformed)?;
            let mut descriptions = assertion
                .child_boxes
                .iter()
                .filter_map(|child| match child {
                    ChildBox::DataBox(data) if data.tbox == BoxType(*b"bfdb") => Some(data.data),
                    _ => None,
                });
            let description = descriptions.next().ok_or_else(malformed)?;
            if descriptions.next().is_some() {
                return Err(malformed());
            }
            let (&flags, fields) = description.split_first().ok_or_else(malformed)?;
            let end = fields
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(malformed)?;
            let format = std::str::from_utf8(&fields[..end]).map_err(|_| malformed())?;
            let remaining = &fields[end + 1..];
            let valid_filename = flags == 1
                && remaining.last() == Some(&0)
                && !remaining[..remaining.len().saturating_sub(1)].contains(&0)
                && std::str::from_utf8(&remaining[..remaining.len().saturating_sub(1)]).is_ok();
            if format.is_empty() || !(flags == 0 && remaining.is_empty() || valid_filename) {
                return Err(malformed());
            }
            let mut payloads = assertion
                .child_boxes
                .iter()
                .filter_map(|child| match child {
                    ChildBox::DataBox(data) if data.tbox == BoxType(*b"bidb") => Some(data.data),
                    _ => None,
                });
            let bytes = payloads.next().ok_or_else(malformed)?;
            if payloads.next().is_some() {
                return Err(malformed());
            }
            Ok(EmbeddedResource {
                label: label.to_string(),
                format: format.to_string(),
                bytes: bytes.to_vec(),
            })
        })
        .collect()
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

    /// The same for each identity assertion whose X.509 signature
    /// verified, to be judged against the identity trust anchors.
    ///
    /// Kept apart from [`Self::chains`]: a claim signer's chain shapes the
    /// store's [`ValidationState`](crate::ValidationState), an identity
    /// signer's never does.
    pub(crate) identity_chains: Vec<PendingChain>,
}

/// Reads a manifest store from its JUMBF bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<ParsedManifestStore, Error> {
    let (manifest_store, _rest) = SuperBox::from_slice_with_depth_limit(bytes, MAX_BOX_DEPTH)?;

    if manifest_store.desc.uuid != &MANIFEST_STORE_UUID {
        return Err(Error::NotAManifestStore);
    }

    let mut statuses = Vec::new();
    let mut chains = Vec::new();
    let mut identity_chains = Vec::new();
    let mut manifests = Vec::new();

    for manifest in child_superboxes(&manifest_store) {
        manifests.push(read_manifest(
            manifest,
            &mut statuses,
            &mut chains,
            &mut identity_chains,
        )?);
    }

    // The C2PA specification defines the active manifest as the last
    // manifest in the store.
    let active_manifest = manifests.last().map(|m| m.label.clone());

    Ok(ParsedManifestStore {
        manifests,
        active_manifest,
        statuses,
        chains,
        identity_chains,
    })
}

/// Returns a superbox's child superboxes, in order.
pub(crate) fn child_superboxes<'a>(
    parent: &'a SuperBox<'a>,
) -> impl Iterator<Item = &'a SuperBox<'a>> {
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
pub(crate) fn content<'a>(parent: &'a SuperBox<'a>, box_type: BoxType) -> Option<&'a [u8]> {
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
    identity_chains: &mut Vec<PendingChain>,
) -> Result<Manifest, Error> {
    let status_start = statuses.len();
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

    validation::check_claim_fields(&label, &claim, statuses);
    validation::check_assertion_hashes(manifest, &claim, statuses);

    // The claim signature commits to the claim box's CBOR, which is why
    // both are read here rather than carried out to the report: the
    // signature's detached payload is the sibling box's bytes.
    let signature = child_by_uuid(manifest, &SIGNATURE_UUID);
    let verified = validation::check_claim_signature(
        &label,
        claim_cbor,
        match signature.map(|sbox| content(sbox, CBOR)) {
            None => validation::SignatureBox::Absent,
            Some(None) => validation::SignatureBox::Empty,
            Some(Some(bytes)) => validation::SignatureBox::Present(bytes),
        },
        statuses,
    );
    let signature_info = verified.as_ref().map(|chain| chain.signature_info.clone());
    chains.extend(verified);

    let assertion_boxes = child_by_uuid(manifest, &ASSERTIONS_UUID);
    let assertion_labels = assertion_boxes
        .map(|assertions| {
            child_superboxes(assertions)
                .filter_map(|a| a.desc.label.map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let assertions: Vec<Assertion> = assertion_boxes
        .map(|store| {
            child_superboxes(store)
                .filter_map(|assertion| {
                    let label = assertion.desc.label?.to_string();
                    let created = claim.created_assertions.iter().any(|reference| {
                        reference.url.rsplit(['/', '=']).next() == Some(label.as_str())
                    });
                    let data = content(assertion, CBOR)
                        .and_then(|bytes| c2pa_cbor::from_slice(bytes).ok());
                    let json_data = content(assertion, BoxType(*b"json"))
                        .and_then(|bytes| serde_json::from_slice(bytes).ok());
                    Some(Assertion {
                        label,
                        created,
                        data,
                        json_data,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    for assertion in &assertions {
        if !matches!(assertion.ingredient_version(), Some("1" | "2" | "3")) {
            continue;
        }
        if let Some(fields) = assertion.data.as_ref().and_then(c2pa_cbor::Value::as_map) {
            let field = |name: &str| {
                fields
                    .get(&c2pa_cbor::Value::Text(name.into()))
                    .filter(|value| **value != c2pa_cbor::Value::Null)
            };
            if matches!(
                field("relationship").and_then(c2pa_cbor::Value::as_str),
                Some("parentOf" | "componentOf")
            ) && field("activeManifest").is_none()
                && field("c2pa_manifest").is_none()
            {
                let title = field("dc:title")
                    .and_then(c2pa_cbor::Value::as_str)
                    .unwrap_or("no title");
                statuses.push(ValidationStatus::for_url(
                    crate::validation::status_code::INGREDIENT_PROVENANCE_UNKNOWN,
                    &format!(
                        "self#jumbf=/c2pa/{label}/c2pa.assertions/{}",
                        assertion.label
                    ),
                    format!("{title}: ingredient does not have provenance"),
                ));
            }
        }
    }

    let data_hash = read_data_hash(manifest, statuses);
    let resources = assertion_boxes
        .map(|store| read_resources(store, &label))
        .transpose()?
        .unwrap_or_default();

    // After the claim and its assertion hashes: an identity assertion is
    // checked against what the claim lists, so the claim has to be read.
    let identity_assertions = identity::check_manifest(
        &label,
        child_by_uuid(manifest, &ASSERTIONS_UUID),
        &claim,
        statuses,
        identity_chains,
    )
    .assertions;

    for status in &mut statuses[status_start..] {
        if let Some(path) = status
            .url
            .as_deref()
            .and_then(|url| url.strip_prefix("self#jumbf=c2pa.assertions/"))
        {
            status.url = Some(format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{path}"));
        }
    }

    Ok(Manifest {
        label,
        claim,
        assertion_labels,
        assertions,
        resources,
        has_signature: signature.is_some(),
        signature_info,
        data_hash,
        identity_assertions,
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
            assertion_box, boxed, claim_box, claim_box_v2, claim_box_v2_from_fields,
            claim_box_with_alg, claim_box_with_assertions, hashed_uri, hashed_uri_with_hash,
            manifest, manifest_store, manifest_with_claim, superbox, v2_required_fields,
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
    fn ingredient_labels_require_version_and_instance_boundaries() {
        for (label, version) in [
            ("c2pa.ingredient", Some("1")),
            ("c2pa.ingredient__2", Some("1")),
            ("c2pa.ingredient.v2", Some("2")),
            ("c2pa.ingredient.v3__1", Some("3")),
            ("c2pa.ingredient.v4", Some("4")),
            ("c2pa.ingredient.extra", None),
            ("c2pa.ingredient.v3__x", None),
            ("c2pa.ingredient.v3__", None),
            ("c2pa.ingredient.v", None),
            ("example.c2pa.ingredient", None),
        ] {
            let assertion = Assertion {
                label: label.into(),
                created: false,
                data: None,
                json_data: None,
            };
            assert_eq!(assertion.ingredient_version(), version, "{label}");
        }
    }

    #[test]
    fn json_assertions_preserve_types_and_do_not_become_cbor_assertions() {
        let payload = serde_json::json!({
            "mixed": [null, true, -1, 1.25, "text", {"nested": []}],
            "large": u64::MAX,
        });
        let assertion = superbox(
            type_uuid(*b"json"),
            "example.json",
            &[boxed(b"json", &serde_json::to_vec(&payload).unwrap())],
        );
        let claim =
            claim_box_with_assertions("json.jpg", vec![hashed_uri("example.json", &assertion)]);
        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:json", &[assertion], claim)]);
        let parsed = parse(&bytes).unwrap();
        let assertion = &parsed.manifests[0].assertions[0];
        assert_eq!(assertion.json_data.as_ref(), Some(&payload));
        assert!(assertion.data.is_none());
        assert!(parsed
            .statuses
            .iter()
            .any(|status| status.code == status_code::ASSERTION_HASHEDURI_MATCH));

        let mut tampered = bytes;
        let offset = tampered
            .windows(b"nested".len())
            .position(|bytes| bytes == b"nested")
            .unwrap();
        tampered[offset] = b'N';
        let parsed = parse(&tampered).unwrap();
        assert!(parsed.manifests[0].assertions[0].json_data.is_some());
        assert!(parsed
            .statuses
            .iter()
            .any(|status| status.code == status_code::ASSERTION_HASHEDURI_MISMATCH));
    }

    #[test]
    fn malformed_json_assertions_keep_their_labels_without_a_payload() {
        let assertion = superbox(
            type_uuid(*b"json"),
            "example.invalid-json",
            &[boxed(b"json", b"{")],
        );
        let bytes = manifest_store(&[manifest_with_claim(
            "urn:uuid:json",
            &[assertion],
            claim_box("json.jpg"),
        )]);
        let parsed = parse(&bytes).unwrap();
        let assertion = &parsed.manifests[0].assertions[0];
        assert_eq!(assertion.label, "example.invalid-json");
        assert!(assertion.json_data.is_none());
        assert!(assertion.data.is_none());
    }

    #[test]
    fn unknown_ingredient_provenance_is_informational_and_owned_by_its_manifest() {
        use c2pa_cbor::Value;
        let make_manifest = |label: &str| {
            let assertions: Vec<_> = ["parentOf", "componentOf", "inputTo"]
                .iter()
                .enumerate()
                .map(|(index, relationship)| {
                    let fields = std::collections::BTreeMap::from([(
                        Value::Text("relationship".into()),
                        Value::Text((*relationship).into()),
                    )]);
                    superbox(
                        type_uuid(*b"cbor"),
                        &format!("c2pa.ingredient.v3__{index}"),
                        &[boxed(
                            b"cbor",
                            &c2pa_cbor::to_vec(&Value::Map(fields)).unwrap(),
                        )],
                    )
                })
                .collect();
            superbox(
                MANIFEST_UUID,
                label,
                &[
                    claim_box("output.jpg"),
                    superbox(ASSERTIONS_UUID, "c2pa.assertions", &assertions),
                ],
            )
        };
        let bytes = manifest_store(&[make_manifest("first"), make_manifest("active")]);
        let parsed = parse(&bytes).unwrap();
        let statuses: Vec<_> = parsed
            .statuses
            .iter()
            .filter(|status| status.code == status_code::INGREDIENT_PROVENANCE_UNKNOWN)
            .collect();
        assert_eq!(statuses.len(), 4);
        for (index, status) in statuses.iter().enumerate() {
            let owner = if index < 2 { "first" } else { "active" };
            assert_eq!(
                status.url.as_deref(),
                Some(
                    format!(
                        "self#jumbf=/c2pa/{owner}/c2pa.assertions/c2pa.ingredient.v3__{}",
                        index % 2
                    )
                    .as_str()
                )
            );
            assert!(!status.is_failure());
            assert!(!status.is_unchecked());
        }
    }

    #[test]
    fn embedded_resources_preserve_exact_payload_and_media_type() {
        for description in [
            b"\0image/jpeg\0".as_slice(),
            b"\x01image/jpeg\0thumbnail.jpg\0",
        ] {
            let bytes = manifest_store(&[superbox(
                MANIFEST_UUID,
                "urn:uuid:resource",
                &[
                    claim_box("resource.jpg"),
                    superbox(
                        ASSERTIONS_UUID,
                        "c2pa.assertions",
                        &[superbox(
                            EMBEDDED_FILE_UUID,
                            "c2pa.thumbnail.claim",
                            &[boxed(b"bfdb", description), boxed(b"bidb", &[0, 255, 1, 2])],
                        )],
                    ),
                ],
            )]);
            let parsed = parse(&bytes).unwrap();
            let resource = &parsed.manifests[0].resources[0];
            assert_eq!(resource.label, "c2pa.thumbnail.claim");
            assert_eq!(resource.format, "image/jpeg");
            assert_eq!(resource.bytes, [0, 255, 1, 2]);
        }
    }

    #[test]
    fn malformed_embedded_resources_fail_explicitly() {
        for children in [
            vec![boxed(b"bidb", &[1])],
            vec![boxed(b"bfdb", b"\0image/jpeg\0")],
            vec![boxed(b"bfdb", b"\0image/jpeg"), boxed(b"bidb", &[1])],
            vec![boxed(b"bfdb", b"\x02image/jpeg\0"), boxed(b"bidb", &[1])],
            vec![
                boxed(b"bfdb", b"\x01image/jpeg\0file"),
                boxed(b"bidb", &[1]),
            ],
            vec![boxed(b"bfdb", b"\0\xff\0"), boxed(b"bidb", &[1])],
            vec![
                boxed(b"bfdb", b"\0image/jpeg\0"),
                boxed(b"bidb", &[1]),
                boxed(b"bidb", &[2]),
            ],
            vec![
                boxed(b"bfdb", b"\0image/jpeg\0"),
                boxed(b"bfdb", b"\0image/jpeg\0"),
                boxed(b"bidb", &[1]),
            ],
        ] {
            let bytes = manifest_store(&[superbox(
                MANIFEST_UUID,
                "urn:uuid:bad",
                &[
                    claim_box("bad.jpg"),
                    superbox(
                        ASSERTIONS_UUID,
                        "c2pa.assertions",
                        &[superbox(
                            EMBEDDED_FILE_UUID,
                            "c2pa.thumbnail.claim",
                            &children,
                        )],
                    ),
                ],
            )]);
            assert!(matches!(
                parse(&bytes),
                Err(Error::MalformedManifest {
                    reason: "malformed embedded-file assertion",
                    ..
                })
            ));
        }
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

    /// Parses a store holding one v2 manifest labelled `urn:uuid:v2`
    /// whose claim has `fields`, returning the statuses.
    fn statuses_for_v2_claim(
        fields: std::collections::BTreeMap<c2pa_cbor::Value, c2pa_cbor::Value>,
    ) -> Vec<crate::validation::ValidationStatus> {
        let claim = claim_box_v2_from_fields(fields);
        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:v2", &[], claim)]);
        parse(&bytes).unwrap().statuses
    }

    fn created_only() -> std::collections::BTreeMap<c2pa_cbor::Value, c2pa_cbor::Value> {
        let mut fields = v2_required_fields();
        fields.insert(
            c2pa_cbor::Value::Text("created_assertions".to_string()),
            c2pa_cbor::Value::Array(vec![]),
        );
        fields
    }

    #[test]
    fn a_conformant_v2_claim_raises_no_claim_malformed() {
        let statuses = statuses_for_v2_claim(created_only());
        assert!(statuses
            .iter()
            .all(|s| s.code != status_code::CLAIM_MALFORMED));
    }

    #[test]
    fn a_v2_claim_missing_required_fields_is_malformed() {
        let mut fields = created_only();
        fields.remove(&c2pa_cbor::Value::Text("instanceID".to_string()));
        fields.remove(&c2pa_cbor::Value::Text("created_assertions".to_string()));

        let statuses = statuses_for_v2_claim(fields);
        let malformed: Vec<_> = statuses
            .iter()
            .filter(|s| s.code == status_code::CLAIM_MALFORMED)
            .collect();

        assert_eq!(malformed.len(), 1);
        assert!(malformed[0].is_failure());
        assert_eq!(
            malformed[0].url.as_deref(),
            Some("self#jumbf=/c2pa/urn:uuid:v2/c2pa.claim.v2")
        );
        let why = malformed[0].explanation.as_deref().unwrap();
        assert!(why.contains("instanceID") && why.contains("created_assertions"));
    }

    #[test]
    fn a_v1_claim_is_not_held_to_the_v2_field_requirements() {
        let bytes = manifest_store(&[manifest_with_claim(
            "urn:uuid:v1",
            &[],
            claim_box("bare.jpg"),
        )]);

        let statuses = parse(&bytes).unwrap().statuses;
        assert!(statuses
            .iter()
            .all(|s| s.code != status_code::CLAIM_MALFORMED));
    }

    #[test]
    fn redacting_an_assertion_in_ones_own_manifest_is_rejected() {
        for uri in [
            // Relative: resolves inside the claim's own manifest.
            "self#jumbf=c2pa.assertions/c2pa.thumbnail",
            // Absolute, naming this manifest.
            "self#jumbf=/c2pa/urn:uuid:v2/c2pa.assertions/c2pa.thumbnail",
        ] {
            let mut fields = created_only();
            fields.insert(
                c2pa_cbor::Value::Text("redacted_assertions".to_string()),
                c2pa_cbor::Value::Array(vec![c2pa_cbor::Value::Text(uri.to_string())]),
            );

            let statuses = statuses_for_v2_claim(fields);
            let self_redacted: Vec<_> = statuses
                .iter()
                .filter(|s| s.code == status_code::ASSERTION_SELF_REDACTED)
                .collect();

            assert_eq!(self_redacted.len(), 1, "{uri}");
            assert!(self_redacted[0].is_failure());
            assert_eq!(
                self_redacted[0].url.as_deref(),
                Some("self#jumbf=/c2pa/urn:uuid:v2/c2pa.assertions/c2pa.thumbnail")
            );
        }
    }

    #[test]
    fn decoded_assertions_preserve_payload_and_created_relationship() {
        let payload = Value::Map(BTreeMap::from([(
            Value::Text("actions".to_string()),
            Value::Array(vec![Value::Map(BTreeMap::from([(
                Value::Text("action".to_string()),
                Value::Text("c2pa.created".to_string()),
            )]))]),
        )]));
        let encoded = c2pa_cbor::to_vec(&payload).unwrap();
        let assertion = superbox(
            type_uuid(*b"cbor"),
            "c2pa.actions.v2",
            &[boxed(b"cbor", &encoded)],
        );
        let claim = claim_box_v2(
            "created.jpg",
            vec![hashed_uri("c2pa.actions.v2", &assertion)],
            vec![],
        );
        let bytes = manifest_store(&[manifest_with_claim("urn:uuid:created", &[assertion], claim)]);

        let parsed = parse(&bytes).unwrap();
        let reported = &parsed.manifests[0].assertions[0];
        assert_eq!(reported.label, "c2pa.actions.v2");
        assert!(reported.created);
        assert_eq!(reported.data.as_ref(), Some(&payload));
    }

    #[test]
    fn redacting_an_ingredients_assertion_is_allowed() {
        let mut fields = created_only();
        fields.insert(
            c2pa_cbor::Value::Text("redacted_assertions".to_string()),
            c2pa_cbor::Value::Array(vec![c2pa_cbor::Value::Text(
                "self#jumbf=/c2pa/urn:uuid:ingredient/c2pa.assertions/c2pa.thumbnail".to_string(),
            )]),
        );

        let statuses = statuses_for_v2_claim(fields);
        assert!(statuses
            .iter()
            .all(|s| s.code != status_code::ASSERTION_SELF_REDACTED));
    }

    /// Parses a v2 manifest whose generator `icon` references `icon_url`
    /// with `hash`, alongside a real `c2pa.icon` assertion.
    fn statuses_for_icon(icon_url: &str, hash: Vec<u8>) -> Vec<ValidationStatus> {
        use c2pa_cbor::Value;

        let icon = assertion_box("c2pa.icon");
        let mut fields = v2_required_fields();
        fields.insert(
            Value::Text("created_assertions".to_string()),
            Value::Array(vec![hashed_uri("c2pa.icon", &icon)]),
        );
        fields.insert(
            Value::Text("claim_generator_info".to_string()),
            Value::Map(std::collections::BTreeMap::from([
                (
                    Value::Text("name".to_string()),
                    Value::Text("t".to_string()),
                ),
                (
                    Value::Text("icon".to_string()),
                    Value::Map(std::collections::BTreeMap::from([
                        (
                            Value::Text("url".to_string()),
                            Value::Text(icon_url.to_string()),
                        ),
                        (Value::Text("hash".to_string()), Value::Bytes(hash)),
                    ])),
                ),
            ])),
        );

        let bytes = manifest_store(&[manifest_with_claim(
            "urn:uuid:v2",
            &[icon],
            claim_box_v2_from_fields(fields),
        )]);
        parse(&bytes).unwrap().statuses
    }

    #[test]
    fn a_generator_icons_hash_is_checked_like_an_assertions() {
        let icon = assertion_box("c2pa.icon");
        let good = <sha2::Sha256 as sha2::Digest>::digest(&icon[8..]).to_vec();

        let matched = statuses_for_icon("self#jumbf=c2pa.assertions/c2pa.icon", good);
        assert_eq!(
            matched
                .iter()
                .filter(|s| s.code == status_code::ASSERTION_HASHEDURI_MATCH)
                .count(),
            1,
            "an identical claim and icon reference is checked once"
        );

        let wrong = statuses_for_icon("self#jumbf=c2pa.assertions/c2pa.icon", vec![0; 32]);
        assert!(wrong
            .iter()
            .any(|s| s.code == status_code::ASSERTION_HASHEDURI_MATCH));
        assert!(wrong
            .iter()
            .any(|s| s.code == status_code::ASSERTION_HASHEDURI_MISMATCH && s.is_failure()));
    }

    #[test]
    fn a_data_box_icon_is_not_reported_missing() {
        let statuses = statuses_for_icon("self#jumbf=c2pa.databoxes/c2pa.icon", vec![0; 32]);
        assert!(statuses
            .iter()
            .all(|s| s.code != status_code::HASHED_URI_MISSING));
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
                    Some("self#jumbf=/c2pa/urn:uuid:u/c2pa.assertions/c2pa.actions".to_string())
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
    fn local_assertion_statuses_keep_their_own_manifest_in_a_multiple_manifest_store() {
        let parsed = parse(&manifest_store(&[
            manifest("urn:uuid:first", "first.jpg", &["c2pa.actions"]),
            manifest("urn:uuid:second", "second.jpg", &["c2pa.actions"]),
        ]))
        .unwrap();
        let urls: Vec<_> = parsed
            .statuses
            .iter()
            .filter(|status| status.code == status_code::ASSERTION_HASHEDURI_MATCH)
            .filter_map(|status| status.url.as_deref())
            .collect();
        assert_eq!(
            urls,
            [
                "self#jumbf=/c2pa/urn:uuid:first/c2pa.assertions/c2pa.actions",
                "self#jumbf=/c2pa/urn:uuid:second/c2pa.assertions/c2pa.actions",
            ]
        );
    }

    #[test]
    fn rejects_malformed_jumbf() {
        assert!(matches!(
            parse(&[0, 0, 0]),
            Err(Error::MalformedManifestStore(_))
        ));
    }
}
