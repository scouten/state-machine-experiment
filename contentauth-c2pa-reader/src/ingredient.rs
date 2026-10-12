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

//! Ingredient assertions: reading them, and checking what they say about
//! the rest of the store.
//!
//! An ingredient assertion (`c2pa.ingredient`, `.v2` or `.v3`, with `__N`
//! suffixes when a manifest has several) records an asset that went into
//! this one: its `relationship`, and — if it carried a manifest — hashed
//! URIs to that manifest's box and claim signature box, which the claim
//! generator copied into this store. This module covers the parts of the
//! specification's *Validate the ingredients* that need nothing beyond the
//! store itself:
//!
//! * the assertion is well formed (`assertion.ingredient.malformed`);
//! * at most one `parentOf` per manifest (`manifest.multipleParents`);
//! * the manifest and claim signature an assertion points at are in the
//!   store and hash as recorded (`ingredient.manifest.*`,
//!   `ingredient.claimSignature.*`), the latter alone where an assertion
//!   in that manifest was redacted, since redaction changes its box;
//! * in a v2 claim, a `c2pa.opened` names exactly one `parentOf`
//!   ingredient of the same manifest and a `c2pa.placed` one or more
//!   `componentOf` (`assertion.action.ingredientMismatch`); older claims
//!   are not held to this, as in c2pa-rs outside strict mode;
//! * an ingredient with no manifest is noted
//!   (`ingredient.unknownProvenance`), unless it is an `inputTo`.
//!
//! # Not yet done
//!
//! Validating the ingredient's *own* ingredients recursively, comparing
//! `validationResults` (and `ingredientDeltas`) with a fresh validation,
//! and checking that a redacted assertion was really zeroed
//! (`assertion.notRedacted`).

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::HashAlgorithm;
use jumbf::parser::{DataBox, SuperBox};

use crate::{
    claim::{hashed_uri_array, Claim, ClaimVersion, HashedUri},
    manifest_store::{child_superboxes, content, CBOR, SIGNATURE_UUID},
    validation::{assertion_path, assertion_payload, status_code, ValidationStatus},
};

/// Label prefix shared by every version of the ingredient assertion.
const INGREDIENT_PREFIX: &str = "c2pa.ingredient";

/// Label prefix shared by both versions of the actions assertion.
const ACTIONS_PREFIX: &str = "c2pa.actions";

/// The hash algorithm assumed when neither a reference nor its claim names
/// one.
const DEFAULT_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;

/// How an ingredient relates to the asset that lists it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Relationship {
    /// The asset is a derived asset or rendition of the ingredient.
    ParentOf,

    /// The asset is composed of several parts, this being one.
    ComponentOf,

    /// The ingredient was an input to a computational process that led to
    /// the asset.
    InputTo,
}

/// One ingredient assertion, as decoded.
///
/// Whether what it says holds is in the report's statuses, which name the
/// assertion by URI.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Ingredient {
    /// The assertion's label within its manifest, for example
    /// `c2pa.ingredient.v3` or `c2pa.ingredient.v3__1`.
    pub label: String,

    /// The `relationship` field, or `None` if it is absent or not one of
    /// the three the specification defines (which is also reported as
    /// `assertion.ingredient.malformed`).
    pub relationship: Option<Relationship>,

    /// `dc:title`.
    pub title: Option<String>,

    /// `dc:format`.
    pub format: Option<String>,

    /// `instanceID`.
    pub instance_id: Option<String>,

    /// The reference to the ingredient's active manifest: `activeManifest`
    /// in a v3 assertion, `c2pa_manifest` in an older one. `None` for an
    /// ingredient with no manifest.
    pub active_manifest: Option<HashedUri>,

    /// `claimSignature`: the reference to that manifest's claim signature
    /// box. Only a v3 assertion has one.
    pub claim_signature: Option<HashedUri>,

    /// `digitalSourceType`: only for an ingredient with no manifest.
    pub digital_source_type: Option<String>,

    /// True if the assertion carries `validationResults` (v3) or
    /// `validationStatus` (v1, v2). Their content is not decoded yet.
    pub has_validation_results: bool,
}

impl Ingredient {
    /// The ingredient assertion's absolute URI, as a status names it.
    fn url(&self, manifest_label: &str) -> String {
        assertion_url(manifest_label, &self.label)
    }
}

/// The absolute JUMBF URI of an assertion.
fn assertion_url(manifest_label: &str, assertion_label: &str) -> String {
    format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{assertion_label}")
}

/// The absolute JUMBF URI of a manifest.
fn manifest_url(manifest_label: &str) -> String {
    format!("self#jumbf=/c2pa/{manifest_label}")
}

/// Reads a manifest's ingredient assertions, recording the findings about
/// each assertion on its own.
pub(crate) fn read(
    manifest_label: &str,
    assertions: Option<&SuperBox<'_>>,
    statuses: &mut Vec<ValidationStatus>,
) -> Vec<Ingredient> {
    let Some(assertions) = assertions else {
        return Vec::new();
    };

    let mut ingredients = Vec::new();
    for assertion in child_superboxes(assertions) {
        let Some(label) = assertion
            .desc
            .label
            .filter(|l| l.starts_with(INGREDIENT_PREFIX))
        else {
            continue;
        };
        let url = assertion_url(manifest_label, label);

        let Some(ingredient) = content(assertion, CBOR).and_then(|cbor| decode(label, cbor)) else {
            statuses.push(ValidationStatus::for_url(
                status_code::ASSERTION_INGREDIENT_MALFORMED,
                &url,
                "ingredient assertion could not be interpreted",
            ));
            continue;
        };

        if let Some(problem) = problem_with(&ingredient) {
            statuses.push(ValidationStatus::for_url(
                status_code::ASSERTION_INGREDIENT_MALFORMED,
                &url,
                problem,
            ));
        }
        ingredients.push(ingredient);
    }
    ingredients
}

/// What is wrong with an ingredient assertion on its own, if anything.
fn problem_with(ingredient: &Ingredient) -> Option<&'static str> {
    let is_v3 = ingredient.label.starts_with("c2pa.ingredient.v3");

    if ingredient.relationship.is_none() {
        Some("`relationship` is missing or is not parentOf, componentOf or inputTo")
    } else if ingredient.active_manifest.is_some() && ingredient.digital_source_type.is_some() {
        Some("`activeManifest` and `digitalSourceType` may not both be present")
    } else if is_v3 && ingredient.active_manifest.is_some() && !ingredient.has_validation_results {
        Some("an ingredient with an `activeManifest` must carry `validationResults`")
    } else {
        None
    }
}

/// Decodes one ingredient assertion's CBOR. `None` if it is not a map.
fn decode(label: &str, cbor: &[u8]) -> Option<Ingredient> {
    let value: Value = c2pa_cbor::from_slice(cbor).ok()?;
    let map = value.as_map()?;

    let get = |key: &str| {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    };
    let text = |key: &str| get(key).and_then(|v| v.as_str()).map(str::to_string);
    let reference = |key: &str| {
        get(key)
            .and_then(|v| hashed_uri_array(&Value::Array(vec![v.clone()]), "ingredient").ok())
            .and_then(|mut refs| refs.pop())
    };

    Some(Ingredient {
        label: label.to_string(),
        relationship: match get("relationship").and_then(|v| v.as_str()) {
            Some("parentOf") => Some(Relationship::ParentOf),
            Some("componentOf") => Some(Relationship::ComponentOf),
            Some("inputTo") => Some(Relationship::InputTo),
            _ => None,
        },
        title: text("dc:title"),
        format: text("dc:format"),
        instance_id: text("instanceID"),
        active_manifest: reference("activeManifest").or_else(|| reference("c2pa_manifest")),
        claim_signature: reference("claimSignature"),
        digital_source_type: text("digitalSourceType"),
        has_validation_results: get("validationResults").is_some()
            || get("validationStatus").is_some(),
    })
}

/// The checks on one manifest's ingredients that need only that manifest:
/// how many parents, which have no provenance, and whether its actions
/// refer to its ingredients correctly.
pub(crate) fn check_manifest(
    manifest: &SuperBox<'_>,
    manifest_label: &str,
    ingredients: &[Ingredient],
    assertions: Option<&SuperBox<'_>>,
    claim: &Claim,
    statuses: &mut Vec<ValidationStatus>,
) {
    let parents = ingredients
        .iter()
        .filter(|i| i.relationship == Some(Relationship::ParentOf))
        .count();
    if parents > 1 {
        statuses.push(ValidationStatus::for_url(
            status_code::MANIFEST_MULTIPLE_PARENTS,
            &manifest_url(manifest_label),
            "the manifest has more than one parentOf ingredient",
        ));
    }

    for ingredient in ingredients {
        if ingredient.active_manifest.is_none()
            && ingredient.relationship.is_some()
            && ingredient.relationship != Some(Relationship::InputTo)
        {
            statuses.push(ValidationStatus::for_url(
                status_code::INGREDIENT_UNKNOWN_PROVENANCE,
                &ingredient.url(manifest_label),
                "the ingredient has no C2PA manifest",
            ));
        }
    }

    if claim.version == ClaimVersion::V2 {
        if let Some(assertions) = assertions {
            check_actions(
                manifest,
                manifest_label,
                ingredients,
                assertions,
                claim,
                statuses,
            );
        }
    }
}

/// Checks that each `c2pa.opened` and `c2pa.placed` action refers to
/// ingredient assertions of the right relationship in this manifest.
fn check_actions(
    manifest: &SuperBox<'_>,
    manifest_label: &str,
    ingredients: &[Ingredient],
    assertions: &SuperBox<'_>,
    claim: &Claim,
    statuses: &mut Vec<ValidationStatus>,
) {
    for assertion in child_superboxes(assertions) {
        let Some(label) = assertion
            .desc
            .label
            .filter(|l| l.starts_with(ACTIONS_PREFIX))
        else {
            continue;
        };
        let url = assertion_url(manifest_label, label);
        let Some(value) =
            content(assertion, CBOR).and_then(|cbor| c2pa_cbor::from_slice::<Value>(cbor).ok())
        else {
            continue;
        };
        let Some(actions) = value
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("actions")))
            .and_then(|(_, v)| v.as_array())
        else {
            continue;
        };

        for action in actions {
            let Some(map) = action.as_map() else { continue };
            let field = |m: &std::collections::BTreeMap<Value, Value>, key: &str| {
                m.iter()
                    .find(|(k, _)| k.as_str() == Some(key))
                    .map(|(_, v)| v.clone())
            };
            let expected = match field(map, "action").as_ref().and_then(|v| v.as_str()) {
                Some("c2pa.opened") => Relationship::ParentOf,
                Some("c2pa.placed") => Relationship::ComponentOf,
                _ => continue,
            };

            // v2 actions name `ingredients` (an array); v1 actions
            // `ingredient` (one reference).
            let parameters = field(map, "parameters");
            let references = parameters
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|p| {
                    field(p, "ingredients")
                        .and_then(|v| hashed_uri_array(&v, "ingredients").ok())
                        .or_else(|| {
                            field(p, "ingredient").and_then(|v| {
                                hashed_uri_array(&Value::Array(vec![v]), "ingredient").ok()
                            })
                        })
                })
                .unwrap_or_default();

            let wrong_count = match expected {
                Relationship::ParentOf => references.len() != 1,
                _ => references.is_empty(),
            };
            let fails = |reason: &str| {
                ValidationStatus::for_url(
                    status_code::ASSERTION_ACTION_INGREDIENT_MISMATCH,
                    &url,
                    reason.to_string(),
                )
            };
            if wrong_count {
                statuses.push(fails(
                    "the action does not reference the number of ingredients it requires",
                ));
                continue;
            }

            for reference in &references {
                let target = assertion_path(&reference.url)
                    .and_then(|path| path.strip_prefix("c2pa.assertions/"))
                    .and_then(|label| ingredients.iter().find(|i| i.label == label));
                let Some(target) = target else {
                    statuses.push(fails(
                        "the action references no ingredient of this manifest",
                    ));
                    continue;
                };
                if target.relationship != Some(expected) {
                    statuses.push(fails(
                        "the action references an ingredient with the wrong relationship",
                    ));
                    continue;
                }

                // The reference must also hash as recorded.
                let algorithm = algorithm(reference.alg.as_deref(), claim.alg.as_deref());
                let matches = algorithm
                    .zip(assertion_payload(manifest, &reference.url))
                    .is_some_and(|(alg, payload)| alg.digest(payload) == reference.hash);
                if !matches {
                    statuses.push(ValidationStatus::for_url(
                        status_code::ASSERTION_HASHEDURI_MISMATCH,
                        &reference.url,
                        "the ingredient assertion does not hash to the value the action recorded",
                    ));
                }
            }
        }
    }
}

/// One manifest of a store, for the store-wide checks.
pub(crate) struct StoreEntry<'a, 'b> {
    pub(crate) label: &'a str,
    pub(crate) sbox: &'a SuperBox<'b>,
    pub(crate) claim: &'a Claim,
    pub(crate) ingredients: &'a [Ingredient],
}

/// Checks every `activeManifest` and `claimSignature` reference against
/// the manifests actually in the store.
pub(crate) fn check_store(entries: &[StoreEntry<'_, '_>], statuses: &mut Vec<ValidationStatus>) {
    // Redacting an assertion changes its manifest's box, so a manifest
    // with redactions against it is checked by its claim signature alone.
    let redacted: Vec<&str> = entries
        .iter()
        .flat_map(|e| e.claim.redacted_assertions.iter().map(String::as_str))
        .collect();

    for entry in entries {
        for ingredient in entry.ingredients {
            let url = ingredient.url(entry.label);
            let algorithm_for = |reference: &HashedUri| {
                algorithm(reference.alg.as_deref(), entry.claim.alg.as_deref())
            };

            if let Some(reference) = &ingredient.active_manifest {
                let target = target_label(&reference.url)
                    .and_then(|label| entries.iter().find(|e| e.label == label));
                let was_redacted = target_label(&reference.url)
                    .is_some_and(|label| redacted.iter().any(|r| mentions_manifest(r, label)));

                match (target, algorithm_for(reference)) {
                    (None, _) => statuses.push(ValidationStatus::for_url(
                        status_code::INGREDIENT_MANIFEST_MISSING,
                        &url,
                        "the ingredient's manifest is not in the store",
                    )),
                    (Some(_), _) if was_redacted => {}
                    (Some(target), Some(alg)) => {
                        statuses.push(compare(
                            payload(target.sbox).map(|p| alg.digest(p)),
                            &reference.hash,
                            &url,
                            status_code::INGREDIENT_MANIFEST_VALIDATED,
                            status_code::INGREDIENT_MANIFEST_MISMATCH,
                            "the ingredient's manifest",
                        ));
                    }
                    (Some(_), None) => {}
                }
            }

            if let Some(reference) = &ingredient.claim_signature {
                let target = target_label(&reference.url)
                    .and_then(|label| entries.iter().find(|e| e.label == label));
                let signature = target.and_then(|t| {
                    child_superboxes(t.sbox).find(|b| b.desc.uuid == &SIGNATURE_UUID)
                });

                match (signature, algorithm_for(reference)) {
                    (None, _) => statuses.push(ValidationStatus::for_url(
                        status_code::INGREDIENT_CLAIM_SIGNATURE_MISSING,
                        &url,
                        "the ingredient's claim signature is not in the store",
                    )),
                    (Some(signature), Some(alg)) => {
                        statuses.push(compare(
                            payload(signature).map(|p| alg.digest(p)),
                            &reference.hash,
                            &url,
                            status_code::INGREDIENT_CLAIM_SIGNATURE_VALIDATED,
                            status_code::INGREDIENT_CLAIM_SIGNATURE_MISMATCH,
                            "the ingredient's claim signature",
                        ));
                    }
                    (Some(_), None) => {}
                }
            }
        }
    }
}

/// A status saying whether `actual` is the `recorded` hash.
fn compare(
    actual: Option<Vec<u8>>,
    recorded: &[u8],
    url: &str,
    matched: &str,
    mismatched: &str,
    what: &str,
) -> ValidationStatus {
    if actual.as_deref() == Some(recorded) {
        ValidationStatus::for_url(matched, url, format!("{what} hashed as recorded"))
    } else {
        ValidationStatus::for_url(
            mismatched,
            url,
            format!("{what} does not hash to the value recorded"),
        )
    }
}

/// The hash algorithm for a reference: its own, else its claim's, else the
/// specification's default. `None` if one is named that cannot be computed.
fn algorithm(reference: Option<&str>, claim: Option<&str>) -> Option<HashAlgorithm> {
    match reference.or(claim) {
        None => Some(DEFAULT_ALGORITHM),
        Some(name) => HashAlgorithm::from_c2pa_name(name),
    }
}

/// A superbox's payload: what a hashed URI to it covers.
fn payload<'a>(sbox: &SuperBox<'a>) -> Option<&'a [u8]> {
    let (boxx, _rest) = DataBox::from_slice(sbox.original).ok()?;
    Some(boxx.data)
}

/// The label of the manifest a reference names: the segment after `/c2pa/`.
fn target_label(url: &str) -> Option<&str> {
    let path = url.rsplit_once('=').map_or(url, |(_, path)| path);
    path.trim_start_matches('/')
        .strip_prefix("c2pa/")?
        .split('/')
        .next()
        .filter(|label| !label.is_empty())
}

/// True if a redacted assertion's URI is inside manifest `label`.
fn mentions_manifest(uri: &str, label: &str) -> bool {
    target_label(uri) == Some(label)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn cbor(entries: &[(&str, Value)]) -> Vec<u8> {
        c2pa_cbor::to_vec(&Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::Text((*k).to_string()), v.clone()))
                .collect(),
        ))
        .unwrap()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    #[test]
    fn decodes_a_v3_ingredient() {
        let bytes = cbor(&[
            ("relationship", text("parentOf")),
            ("dc:title", text("source.jpg")),
            ("instanceID", text("xmp:iid:1")),
            ("digitalSourceType", text("http://example/dst")),
        ]);

        let ingredient = decode("c2pa.ingredient.v3", &bytes).unwrap();

        assert_eq!(ingredient.relationship, Some(Relationship::ParentOf));
        assert_eq!(ingredient.title.as_deref(), Some("source.jpg"));
        assert_eq!(ingredient.instance_id.as_deref(), Some("xmp:iid:1"));
        assert_eq!(
            ingredient.digital_source_type.as_deref(),
            Some("http://example/dst")
        );
        assert!(ingredient.active_manifest.is_none());
        assert!(problem_with(&ingredient).is_none());
    }

    #[test]
    fn a_missing_or_unknown_relationship_is_malformed() {
        for entries in [
            vec![("dc:title", text("x"))],
            vec![("relationship", text("siblingOf"))],
        ] {
            let ingredient = decode("c2pa.ingredient.v3", &cbor(&entries)).unwrap();
            assert_eq!(ingredient.relationship, None);
            assert!(problem_with(&ingredient).is_some());
        }
    }

    #[test]
    fn a_manifest_and_a_source_type_together_are_malformed() {
        let reference = Value::Map(
            [
                (text("url"), text("self#jumbf=/c2pa/urn:uuid:a")),
                (text("hash"), Value::Bytes(vec![0; 32])),
            ]
            .into_iter()
            .collect(),
        );
        let bytes = cbor(&[
            ("relationship", text("parentOf")),
            ("activeManifest", reference),
            ("digitalSourceType", text("x")),
            ("validationResults", Value::Map(Default::default())),
        ]);

        let ingredient = decode("c2pa.ingredient.v3", &bytes).unwrap();
        assert!(problem_with(&ingredient)
            .unwrap()
            .contains("digitalSourceType"));
    }

    #[test]
    fn a_v3_manifest_reference_needs_validation_results_but_a_v1_does_not() {
        let reference = Value::Map(
            [
                (text("url"), text("self#jumbf=/c2pa/urn:uuid:a")),
                (text("hash"), Value::Bytes(vec![0; 32])),
            ]
            .into_iter()
            .collect(),
        );
        let v3 = cbor(&[
            ("relationship", text("parentOf")),
            ("activeManifest", reference.clone()),
        ]);
        assert!(problem_with(&decode("c2pa.ingredient.v3", &v3).unwrap()).is_some());

        let v1 = cbor(&[
            ("relationship", text("parentOf")),
            ("c2pa_manifest", reference),
        ]);
        let v1 = decode("c2pa.ingredient", &v1).unwrap();
        assert!(v1.active_manifest.is_some());
        assert!(problem_with(&v1).is_none());
    }

    // --- checks against a whole store -----------------------------------

    use sha2::{Digest, Sha256};

    use crate::{
        manifest_store::{self, type_uuid, ParsedManifestStore},
        test_support::{
            boxed, claim_box_v2_from_fields, hashed_uri, manifest_store as store_bytes,
            manifest_with_claim, superbox, v2_required_fields,
        },
    };

    fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
    }

    fn reference(url: &str, hash: Vec<u8>) -> Value {
        map(vec![("url", text(url)), ("hash", Value::Bytes(hash))])
    }

    fn assertion(label: &str, value: &Value) -> Vec<u8> {
        let cbor = c2pa_cbor::to_vec(value).unwrap();
        superbox(type_uuid(*b"cbor"), label, &[boxed(b"cbor", &cbor)])
    }

    /// A v2 manifest with these assertions (all created) and redactions.
    fn manifest(label: &str, assertions: Vec<(&str, Value)>, redacted: &[&str]) -> Vec<u8> {
        manifest_of_boxes(
            label,
            assertions
                .iter()
                .map(|(l, v)| (*l, assertion(l, v)))
                .collect(),
            redacted,
        )
    }

    /// As [`manifest`], from assertion boxes already built — so a box can
    /// hold bytes that are not CBOR at all.
    fn manifest_of_boxes(
        label: &str,
        labelled_boxes: Vec<(&str, Vec<u8>)>,
        redacted: &[&str],
    ) -> Vec<u8> {
        let boxes: Vec<_> = labelled_boxes.iter().map(|(_, b)| b.clone()).collect();
        let refs = labelled_boxes
            .iter()
            .map(|(l, b)| hashed_uri(l, b))
            .collect();

        let mut fields = v2_required_fields();
        fields.insert(text("created_assertions"), Value::Array(refs));
        if !redacted.is_empty() {
            fields.insert(
                text("redacted_assertions"),
                Value::Array(redacted.iter().map(|r| text(r)).collect()),
            );
        }
        manifest_with_claim(label, &boxes, claim_box_v2_from_fields(fields))
    }

    /// The payload hash of a manifest box, and of its claim signature box.
    fn hashes(manifest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (sbox, _) = SuperBox::from_slice(manifest).unwrap();
        let signature = child_superboxes(&sbox)
            .find(|b| b.desc.uuid == &SIGNATURE_UUID)
            .unwrap();
        (
            Sha256::digest(&manifest[8..]).to_vec(),
            Sha256::digest(&signature.original[8..]).to_vec(),
        )
    }

    fn ingredient_assertion(relationship: &str, target: Option<(&str, Vec<u8>, Vec<u8>)>) -> Value {
        let mut entries = vec![("relationship", text(relationship))];
        if let Some((label, manifest_hash, signature_hash)) = target {
            entries.push((
                "activeManifest",
                reference(&format!("self#jumbf=/c2pa/{label}"), manifest_hash),
            ));
            entries.push((
                "claimSignature",
                reference(
                    &format!("self#jumbf=/c2pa/{label}/c2pa.signature"),
                    signature_hash,
                ),
            ));
            entries.push(("validationResults", map(vec![])));
        }
        map(entries)
    }

    fn parse(manifests: &[Vec<u8>]) -> ParsedManifestStore {
        manifest_store::parse(&store_bytes(manifests)).unwrap()
    }

    fn codes(parsed: &ParsedManifestStore) -> Vec<&str> {
        parsed.statuses.iter().map(|s| s.code.as_str()).collect()
    }

    fn failures(parsed: &ParsedManifestStore) -> Vec<&str> {
        parsed
            .statuses
            .iter()
            .filter(|s| s.is_failure())
            .map(|s| s.code.as_str())
            .collect()
    }

    /// A store of an ingredient manifest `A` and a manifest `B` over it,
    /// with `B`'s ingredient assertion built by `ingredient`.
    fn store_over_a(
        ingredient: impl FnOnce(Vec<u8>, Vec<u8>) -> Value,
        redacted: &[&str],
    ) -> ParsedManifestStore {
        let a = manifest("A", vec![], &[]);
        let (manifest_hash, signature_hash) = hashes(&a);
        let b = manifest(
            "B",
            vec![(
                "c2pa.ingredient.v3",
                ingredient(manifest_hash, signature_hash),
            )],
            redacted,
        );
        parse(&[a, b])
    }

    #[test]
    fn an_ingredients_manifest_and_claim_signature_are_checked_by_hash() {
        let parsed = store_over_a(
            |m, s| ingredient_assertion("parentOf", Some(("A", m, s))),
            &[],
        );

        let codes = codes(&parsed);
        assert!(codes.contains(&status_code::INGREDIENT_MANIFEST_VALIDATED));
        assert!(codes.contains(&status_code::INGREDIENT_CLAIM_SIGNATURE_VALIDATED));
        assert!(failures(&parsed).is_empty(), "{:?}", parsed.statuses);

        let b = &parsed.manifests[1];
        assert_eq!(b.ingredients.len(), 1);
        assert_eq!(b.ingredients[0].relationship, Some(Relationship::ParentOf));
    }

    #[test]
    fn a_wrong_manifest_hash_or_signature_hash_is_a_failure() {
        let parsed = store_over_a(
            |_, s| ingredient_assertion("parentOf", Some(("A", vec![0; 32], s))),
            &[],
        );
        assert_eq!(
            failures(&parsed),
            [status_code::INGREDIENT_MANIFEST_MISMATCH]
        );

        let parsed = store_over_a(
            |m, _| ingredient_assertion("parentOf", Some(("A", m, vec![0; 32]))),
            &[],
        );
        assert_eq!(
            failures(&parsed),
            [status_code::INGREDIENT_CLAIM_SIGNATURE_MISMATCH]
        );
    }

    #[test]
    fn a_manifest_the_store_does_not_hold_is_missing() {
        let b = manifest(
            "B",
            vec![(
                "c2pa.ingredient.v3",
                ingredient_assertion("parentOf", Some(("nowhere", vec![0; 32], vec![0; 32]))),
            )],
            &[],
        );
        let parsed = parse(&[b]);

        assert_eq!(
            failures(&parsed),
            [
                status_code::INGREDIENT_MANIFEST_MISSING,
                status_code::INGREDIENT_CLAIM_SIGNATURE_MISSING
            ]
        );
    }

    #[test]
    fn redaction_against_a_manifest_leaves_only_its_signature_to_check() {
        // The manifest hash no longer matches — redaction changed the
        // box — and that is expected; the signature still must.
        let parsed = store_over_a(
            |_, s| ingredient_assertion("parentOf", Some(("A", vec![0; 32], s))),
            &["self#jumbf=/c2pa/A/c2pa.assertions/c2pa.thumbnail.claim.jpeg"],
        );

        let codes = codes(&parsed);
        assert!(failures(&parsed).is_empty(), "{:?}", parsed.statuses);
        assert!(!codes.contains(&status_code::INGREDIENT_MANIFEST_VALIDATED));
        assert!(codes.contains(&status_code::INGREDIENT_CLAIM_SIGNATURE_VALIDATED));
    }

    #[test]
    fn two_parents_are_a_failure_and_a_missing_manifest_is_only_noted() {
        let b = manifest(
            "B",
            vec![
                ("c2pa.ingredient.v3", ingredient_assertion("parentOf", None)),
                (
                    "c2pa.ingredient.v3__1",
                    ingredient_assertion("parentOf", None),
                ),
                (
                    "c2pa.ingredient.v3__2",
                    ingredient_assertion("componentOf", None),
                ),
                (
                    "c2pa.ingredient.v3__3",
                    ingredient_assertion("inputTo", None),
                ),
            ],
            &[],
        );
        let parsed = parse(&[b]);

        assert_eq!(failures(&parsed), [status_code::MANIFEST_MULTIPLE_PARENTS]);
        // Three have no provenance; the input is exempt.
        assert_eq!(
            codes(&parsed)
                .iter()
                .filter(|c| **c == status_code::INGREDIENT_UNKNOWN_PROVENANCE)
                .count(),
            3
        );
    }

    fn action(name: &str, ingredient_label: &str, hash: Vec<u8>) -> Value {
        map(vec![
            ("action", text(name)),
            (
                "parameters",
                map(vec![(
                    "ingredients",
                    Value::Array(vec![reference(
                        &format!("self#jumbf=c2pa.assertions/{ingredient_label}"),
                        hash,
                    )]),
                )]),
            ),
        ])
    }

    /// A manifest with one ingredient assertion and an actions assertion
    /// built from it.
    fn manifest_with_action(relationship: &str, action_name: &str) -> ParsedManifestStore {
        let ingredient = ingredient_assertion(relationship, None);
        let hash = Sha256::digest(&assertion("c2pa.ingredient.v3", &ingredient)[8..]).to_vec();
        let actions = map(vec![(
            "actions",
            Value::Array(vec![action(action_name, "c2pa.ingredient.v3", hash)]),
        )]);
        parse(&[manifest(
            "B",
            vec![
                ("c2pa.actions.v2", actions),
                ("c2pa.ingredient.v3", ingredient),
            ],
            &[],
        )])
    }

    #[test]
    fn an_action_must_name_an_ingredient_of_the_relationship_it_requires() {
        for (relationship, action_name) in
            [("parentOf", "c2pa.opened"), ("componentOf", "c2pa.placed")]
        {
            let parsed = manifest_with_action(relationship, action_name);
            assert!(
                !codes(&parsed).contains(&status_code::ASSERTION_ACTION_INGREDIENT_MISMATCH),
                "{relationship} / {action_name}: {:?}",
                parsed.statuses
            );
        }

        for (relationship, action_name) in
            [("componentOf", "c2pa.opened"), ("parentOf", "c2pa.placed")]
        {
            let parsed = manifest_with_action(relationship, action_name);
            assert!(
                codes(&parsed).contains(&status_code::ASSERTION_ACTION_INGREDIENT_MISMATCH),
                "{relationship} / {action_name}"
            );
        }
    }

    #[test]
    fn an_action_with_no_ingredient_reference_is_a_mismatch() {
        let actions = map(vec![(
            "actions",
            Value::Array(vec![map(vec![("action", text("c2pa.opened"))])]),
        )]);
        let parsed = parse(&[manifest("B", vec![("c2pa.actions.v2", actions)], &[])]);

        assert_eq!(
            failures(&parsed),
            [status_code::ASSERTION_ACTION_INGREDIENT_MISMATCH]
        );
    }

    #[test]
    fn an_action_whose_reference_hash_is_wrong_is_a_failure() {
        let ingredient = ingredient_assertion("parentOf", None);
        let actions = map(vec![(
            "actions",
            Value::Array(vec![action(
                "c2pa.opened",
                "c2pa.ingredient.v3",
                vec![0; 32],
            )]),
        )]);
        let parsed = parse(&[manifest(
            "B",
            vec![
                ("c2pa.actions.v2", actions),
                ("c2pa.ingredient.v3", ingredient),
            ],
            &[],
        )]);

        assert_eq!(
            failures(&parsed),
            [status_code::ASSERTION_HASHEDURI_MISMATCH]
        );
    }

    #[test]
    fn a_v1_claim_is_not_held_to_the_action_rules() {
        // `claim_box_with_assertions` writes a v1 claim.
        let actions = map(vec![(
            "actions",
            Value::Array(vec![map(vec![("action", text("c2pa.opened"))])]),
        )]);
        let boxes = [assertion("c2pa.actions", &actions)];
        let claim = crate::test_support::claim_box_with_assertions(
            "v1.jpg",
            vec![hashed_uri("c2pa.actions", &boxes[0])],
        );
        let parsed = parse(&[manifest_with_claim("B", &boxes, claim)]);

        assert!(failures(&parsed).is_empty(), "{:?}", parsed.statuses);
    }

    #[test]
    fn an_ingredient_assertion_that_cannot_be_read_or_is_incomplete_is_malformed() {
        let not_a_map = assertion("c2pa.ingredient.v3", &Value::Array(vec![]));
        let no_relationship =
            assertion("c2pa.ingredient.v3__1", &map(vec![("dc:title", text("x"))]));
        let parsed = parse(&[manifest_of_boxes(
            "B",
            vec![
                ("c2pa.ingredient.v3", not_a_map),
                ("c2pa.ingredient.v3__1", no_relationship),
            ],
            &[],
        )]);

        assert_eq!(
            failures(&parsed),
            [
                status_code::ASSERTION_INGREDIENT_MALFORMED,
                status_code::ASSERTION_INGREDIENT_MALFORMED
            ]
        );
        // The unreadable one is left out; the incomplete one is kept.
        let labels: Vec<_> = parsed.manifests[0]
            .ingredients
            .iter()
            .map(|i| i.label.as_str())
            .collect();
        assert_eq!(labels, ["c2pa.ingredient.v3__1"]);
    }

    #[test]
    fn an_actions_assertion_that_is_not_cbor_is_left_to_the_hash_checks() {
        let garbage = superbox(
            type_uuid(*b"cbor"),
            "c2pa.actions.v2",
            &[boxed(b"cbor", &[0xff, 0xff])],
        );
        let parsed = parse(&[manifest_of_boxes(
            "B",
            vec![("c2pa.actions.v2", garbage)],
            &[],
        )]);

        // Nothing here to say about ingredients.
        assert!(failures(&parsed).is_empty(), "{:?}", parsed.statuses);
    }

    #[test]
    fn a_v2_action_may_name_its_ingredient_with_the_singular_field() {
        let ingredient = ingredient_assertion("parentOf", None);
        let hash = Sha256::digest(&assertion("c2pa.ingredient.v3", &ingredient)[8..]).to_vec();
        let opened = map(vec![
            ("action", text("c2pa.opened")),
            (
                "parameters",
                map(vec![(
                    "ingredient",
                    reference("self#jumbf=c2pa.assertions/c2pa.ingredient.v3", hash),
                )]),
            ),
        ]);
        let parsed = parse(&[manifest(
            "B",
            vec![
                (
                    "c2pa.actions.v2",
                    map(vec![("actions", Value::Array(vec![opened]))]),
                ),
                ("c2pa.ingredient.v3", ingredient),
            ],
            &[],
        )]);

        assert!(failures(&parsed).is_empty(), "{:?}", parsed.statuses);
    }

    #[test]
    fn an_action_naming_an_ingredient_the_manifest_does_not_have_is_a_mismatch() {
        let placed = action("c2pa.placed", "c2pa.ingredient.v3__9", vec![0; 32]);
        let parsed = parse(&[manifest(
            "B",
            vec![
                (
                    "c2pa.actions.v2",
                    map(vec![("actions", Value::Array(vec![placed]))]),
                ),
                (
                    "c2pa.ingredient.v3",
                    ingredient_assertion("componentOf", None),
                ),
            ],
            &[],
        )]);

        assert_eq!(
            failures(&parsed),
            [status_code::ASSERTION_ACTION_INGREDIENT_MISMATCH]
        );
    }

    #[test]
    fn a_reference_in_an_algorithm_this_crate_cannot_compute_is_not_judged() {
        let a = manifest("A", vec![], &[]);
        let unsupported = |label: &str| {
            map(vec![
                ("url", text(label)),
                ("hash", Value::Bytes(vec![0; 32])),
                ("alg", text("sha999")),
            ])
        };
        let ingredient = map(vec![
            ("relationship", text("parentOf")),
            ("activeManifest", unsupported("self#jumbf=/c2pa/A")),
            (
                "claimSignature",
                unsupported("self#jumbf=/c2pa/A/c2pa.signature"),
            ),
            ("validationResults", map(vec![])),
        ]);
        let b = manifest("B", vec![("c2pa.ingredient.v3", ingredient)], &[]);

        let parsed = parse(&[a, b]);

        // Neither validated nor failed: the check simply was not made.
        let codes = codes(&parsed);
        assert!(failures(&parsed).is_empty(), "{:?}", parsed.statuses);
        assert!(!codes.contains(&status_code::INGREDIENT_MANIFEST_VALIDATED));
        assert!(!codes.contains(&status_code::INGREDIENT_CLAIM_SIGNATURE_VALIDATED));
    }

    #[test]
    fn target_label_is_the_segment_after_c2pa() {
        assert_eq!(
            target_label("self#jumbf=/c2pa/urn:uuid:abc"),
            Some("urn:uuid:abc")
        );
        assert_eq!(
            target_label("self#jumbf=/c2pa/urn:uuid:abc/c2pa.signature"),
            Some("urn:uuid:abc")
        );
        assert_eq!(target_label("self#jumbf=c2pa.assertions/x"), None);
    }
}
