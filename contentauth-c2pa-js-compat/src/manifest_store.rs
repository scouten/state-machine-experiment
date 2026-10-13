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

//! The objects [`crate::Reader::manifest_store`] and
//! [`crate::Reader::active_manifest`] return, and the JSON
//! [`crate::Reader::json`] produces.
//!
//! c2pa-wasm returns these as plain JavaScript objects — c2pa-rs's
//! `Reader` and `Manifest` serialized through `serde_wasm_bindgen` — whose
//! shape `@contentauth/c2pa-types` describes as `ManifestStore` and
//! `Manifest`. This projection reports decoded CBOR assertion payloads
//! and created relationships, alongside the validation summary. Ingredient
//! manifests, signature metadata, thumbnails, resolved resources, and
//! complete validation-result buckets remain unimplemented.
//!
//! Every type here owns its data and implements [`serde::Serialize`], so
//! a binding can hand it straight to `serde_wasm_bindgen` (as the `web`
//! feature's `WasmReader` does) or `serde_json` (as [`crate::Reader::json`]
//! does).

use std::collections::BTreeMap;

use contentauth_c2pa_reader::{ClaimVersion, ReadReport};
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize, Serializer,
};

/// The asset's manifest store: what c2pa-wasm's `manifestStore()` returns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestStore {
    /// Label of the active manifest — the last one in the store — if the
    /// store contains any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_manifest: Option<String>,

    /// Every manifest in the store, keyed by label.
    pub manifests: BTreeMap<String, Manifest>,

    /// Overall validation outcome.
    pub validation_state: ValidationState,

    /// Individual validation status codes recorded while reading, in the
    /// vocabulary of the C2PA specification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub validation_status: Vec<ValidationStatus>,

    /// Validation results grouped by the active manifest and outcome.
    pub validation_results: ValidationResults,
}

/// Serializes a [`ClaimVersion`] as the number c2pa-js reports
/// (`claim_version: 2`).
fn serialize_claim_version<S: serde::Serializer>(
    version: &ClaimVersion,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u8(version.number())
}

/// One entry of a manifest's `claim_generator_info`.
///
/// `icon` is not reported: it is a hashed reference to an embedded-data
/// assertion this reader does not resolve.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClaimGeneratorInfo {
    /// Name of the generating product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Version of the generating product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The C2PA specification version the generator followed (v2 only).
    #[serde(rename = "specVersion", skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
}

/// One manifest: what c2pa-wasm's `activeManifest()` returns, and the
/// values of [`ManifestStore::manifests`].
///
/// Carries the fields [`contentauth_c2pa_reader`] can populate today; see
/// the module docs for what `@contentauth/c2pa-types`' `Manifest` has that
/// this does not yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Manifest {
    /// The manifest's label, as referenced in the store.
    pub label: String,

    /// A user-agent-formatted string identifying the software that
    /// produced the claim, if the claim carries the legacy free-form
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator: Option<String>,

    /// Structured descriptions of the software that produced the claim:
    /// a v1 claim's `claim_generator_info` array, or a v2 claim's single
    /// `generator-info-map` as a one-entry list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// The version of the claim this manifest carries: `1` for a
    /// `c2pa.claim`, `2` for a `c2pa.claim.v2`.
    #[serde(serialize_with = "serialize_claim_version")]
    pub claim_version: ClaimVersion,

    /// A user-displayable title for the asset, if the claim carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// The asset's MIME type, if the claim carries one — a v1 claim
    /// only; the v2 claim has no `dc:format` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// The asset's instance identifier, or an empty string if the claim
    /// carries none — c2pa-rs's own `Manifest` has no way to say "absent"
    /// here either.
    pub instance_id: String,

    /// Assertions physically present in the manifest's assertion store,
    /// in store order.
    pub assertions: Vec<ManifestAssertion>,
}

/// One assertion in the manifest store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestAssertion {
    /// Assertion label.
    pub label: String,

    /// True when the claim created this assertion.
    #[serde(skip_serializing_if = "is_false")]
    pub created: bool,

    /// Decoded assertion payload, when its CBOR could be read.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_cbor_value"
    )]
    pub data: Option<c2pa_cbor::Value>,
}

fn serialize_cbor_value<S: Serializer>(
    value: &Option<c2pa_cbor::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => JsonCbor(value).serialize(serializer),
        None => serializer.serialize_none(),
    }
}

struct JsonCbor<'a>(&'a c2pa_cbor::Value);

impl Serialize for JsonCbor<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use c2pa_cbor::Value;

        match self.0 {
            Value::Null => serializer.serialize_none(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Integer(value) => serializer.serialize_i64(*value),
            Value::Float(value) => serializer.serialize_f64(*value),
            Value::Bytes(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Value::Text(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&JsonCbor(value))?;
                }
                sequence.end()
            }
            Value::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    let Value::Text(key) = key else {
                        return Err(serde::ser::Error::custom(
                            "assertion CBOR map key is not text",
                        ));
                    };
                    map.serialize_entry(key, &JsonCbor(value))?;
                }
                map.end()
            }
            Value::Tag(_, value) => JsonCbor(value).serialize(serializer),
        }
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

/// Overall validation outcome for a manifest store, as c2pa-rs's
/// `ValidationState` names it.
///
/// [`contentauth_c2pa_reader::ValidationState`] has a fourth variant,
/// `Incomplete`, for a check that never ran rather than one that failed;
/// c2pa-rs (and so c2pa-js) has no such notion, so it folds into
/// [`Self::Invalid`] here — the conservative reading, and the same one
/// `contentauth-c2pa-rs-compat` makes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ValidationState {
    /// The manifest store failed validation, or nothing was validated, or
    /// the trust evaluation never ran at all.
    Invalid,

    /// Well-formed and every cryptographic check that ran passed, but the
    /// signer is not among the configured trust anchors.
    Valid,

    /// Valid, and the signer's credential chains to a configured trust
    /// anchor.
    Trusted,
}

impl From<Option<contentauth_c2pa_reader::ValidationState>> for ValidationState {
    fn from(state: Option<contentauth_c2pa_reader::ValidationState>) -> Self {
        use contentauth_c2pa_reader::ValidationState as Inner;

        match state {
            Some(Inner::Trusted) => Self::Trusted,
            Some(Inner::Valid) => Self::Valid,
            // `Invalid`, `Incomplete`, and any future non-exhaustive
            // variant added upstream all fold in here.
            Some(_) | None => Self::Invalid,
        }
    }
}

/// One validation status observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationStatus {
    /// The status code, e.g. `assertion.dataHash.match`.
    pub code: String,

    /// JUMBF URI of the manifest store element this status pertains to,
    /// if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// A human-readable explanation of the check performed, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// On a trusted status, the URI of the trust list that matched, when
    /// the list was configured with a `trust_uri`.
    ///
    /// Never serialized: c2pa-rs 0.91 keeps this on its `ValidationStatus`
    /// behind an accessor and marks it `#[serde(skip)]`, so the JSON
    /// reported here stays identical to c2pa-rs's.
    #[serde(skip)]
    pub trust_list_uri: Option<String>,
}

/// Validation statuses grouped as c2pa-rs reports them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationResults {
    /// Results for the active manifest.
    #[serde(rename = "activeManifest")]
    pub active_manifest: ValidationResultBuckets,

    /// C2PA specification version used by this report.
    #[serde(rename = "specVersion")]
    pub spec_version: &'static str,
}

/// Statuses grouped by result category.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ValidationResultBuckets {
    /// Checks that passed.
    pub success: Vec<ValidationStatus>,

    /// Checks that did not establish success or failure.
    pub informational: Vec<ValidationStatus>,

    /// Checks that failed.
    pub failure: Vec<ValidationStatus>,
}

impl ManifestStore {
    /// Reports `report` in c2pa-rs's manifest-store shape.
    ///
    /// Public so that a sibling compatibility layer over another c2pa-rs
    /// surface (`contentauth-c2pa-node-compat`) can reuse the one
    /// reporting of the engine's result rather than copy it.
    pub fn from_report(report: &ReadReport) -> Self {
        let statuses: Vec<_> = report
            .statuses
            .iter()
            .map(|status| ValidationStatus {
                code: status.code.clone(),
                url: status.url.clone(),
                explanation: status.explanation.clone(),
                trust_list_uri: status.trust_list_uri.clone(),
            })
            .collect();

        Self {
            active_manifest: report.active_manifest.clone(),
            manifests: report
                .manifests
                .iter()
                .map(|manifest| (manifest.label.clone(), Manifest::from_inner(manifest)))
                .collect(),
            validation_state: report.validation_state.into(),
            validation_status: statuses.clone(),
            validation_results: validation_results(report, statuses),
        }
    }
}

fn validation_results(report: &ReadReport, statuses: Vec<ValidationStatus>) -> ValidationResults {
    let active_label = report.active_manifest.as_deref().unwrap_or_default();
    let mut active_manifest = ValidationResultBuckets::default();

    for (inner, status) in report.statuses.iter().zip(statuses) {
        let pertains_to_active = inner.url.as_ref().is_none_or(|url| {
            url.contains(&format!("/c2pa/{active_label}/"))
                // Claim-local assertion URIs omit the manifest label.
                || report.active_manifest.is_some()
                    && url.starts_with("self#jumbf=c2pa.assertions/")
        });
        if !pertains_to_active {
            continue;
        }

        if is_failure_bucket(inner) {
            active_manifest.failure.push(status);
        } else if is_informational_bucket(inner) {
            active_manifest.informational.push(status);
        } else {
            active_manifest.success.push(status);
        }
    }

    ValidationResults {
        active_manifest,
        spec_version: "2.4.0",
    }
}

fn is_failure_bucket(status: &contentauth_c2pa_reader::ValidationStatus) -> bool {
    status.is_failure() || status.code == "signingCredential.untrusted"
}

fn is_informational_bucket(status: &contentauth_c2pa_reader::ValidationStatus) -> bool {
    use contentauth_c2pa_reader::validation::status_code;

    status.is_unchecked()
        || matches!(
            status.code.as_str(),
            status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED
                | status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE
                | status_code::SIGNING_CREDENTIAL_OCSP_UNKNOWN
                | status_code::TIMESTAMP_UNTRUSTED
                | status_code::TIMESTAMP_MISMATCH
                | status_code::TIMESTAMP_MALFORMED
                | status_code::TIMESTAMP_OUTSIDE_VALIDITY
                | status_code::CAWG_IDENTITY_SIG_TYPE_UNSUPPORTED
        )
}

impl Manifest {
    /// Reports one of `report`'s manifests; see [`ManifestStore::from_report`].
    pub fn from_inner(manifest: &contentauth_c2pa_reader::Manifest) -> Self {
        Self {
            label: manifest.label.clone(),
            claim_generator: manifest.claim.claim_generator.clone(),
            claim_generator_info: manifest
                .claim
                .claim_generator_info
                .iter()
                .map(|info| ClaimGeneratorInfo {
                    name: info.name.clone(),
                    version: info.version.clone(),
                    spec_version: info.spec_version.clone(),
                })
                .collect(),
            claim_version: manifest.claim.version,
            title: manifest.claim.title.clone(),
            format: manifest.claim.format.clone(),
            instance_id: manifest.claim.instance_id.clone().unwrap_or_default(),
            assertions: manifest
                .assertions
                .iter()
                .map(|assertion| ManifestAssertion {
                    label: assertion.label.clone(),
                    created: assertion.created,
                    data: assertion.data.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use contentauth_c2pa_reader::ValidationState as Inner;

    use super::*;

    #[test]
    fn trusted_and_valid_map_straight_across() {
        assert_eq!(
            ValidationState::from(Some(Inner::Trusted)),
            ValidationState::Trusted
        );
        assert_eq!(
            ValidationState::from(Some(Inner::Valid)),
            ValidationState::Valid
        );
    }

    #[test]
    fn invalid_incomplete_and_no_outcome_at_all_fold_into_invalid() {
        assert_eq!(
            ValidationState::from(Some(Inner::Invalid)),
            ValidationState::Invalid
        );
        assert_eq!(
            ValidationState::from(Some(Inner::Incomplete)),
            ValidationState::Invalid
        );
        assert_eq!(ValidationState::from(None), ValidationState::Invalid);
    }

    /// The optional fields are omitted rather than serialized as `null`,
    /// matching c2pa-rs's own `skip_serializing_if` treatment of them.
    #[test]
    fn an_empty_store_serializes_to_the_minimal_shape() {
        let store = ManifestStore {
            active_manifest: None,
            manifests: BTreeMap::new(),
            validation_state: ValidationState::Invalid,
            validation_status: vec![],
            validation_results: ValidationResults {
                active_manifest: ValidationResultBuckets::default(),
                spec_version: "2.4.0",
            },
        };

        let json = serde_json::to_value(store).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            json,
            serde_json::json!({
                "manifests": {},
                "validation_state": "Invalid",
                "validation_results": {
                    "activeManifest": {
                        "success": [],
                        "informational": [],
                        "failure": [],
                    },
                    "specVersion": "2.4.0",
                },
            })
        );
    }

    #[test]
    fn a_manifest_omits_the_optional_fields_it_does_not_have() {
        let manifest = Manifest {
            label: "urn:uuid:x".to_string(),
            claim_generator: None,
            claim_generator_info: vec![],
            claim_version: ClaimVersion::V1,
            title: None,
            format: Some("image/jpeg".to_string()),
            instance_id: String::new(),
            assertions: vec![ManifestAssertion {
                label: "c2pa.hash.data".to_string(),
                created: false,
                data: None,
            }],
        };

        let json = serde_json::to_value(manifest).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            json,
            serde_json::json!({
                "label": "urn:uuid:x",
                "claim_version": 1,
                "format": "image/jpeg",
                "instance_id": "",
                "assertions": [{ "label": "c2pa.hash.data" }],
            })
        );
    }

    #[test]
    fn assertion_cbor_bytes_serialize_as_json_arrays() {
        let assertion = ManifestAssertion {
            label: "cawg.identity".to_string(),
            created: false,
            data: Some(c2pa_cbor::Value::Bytes(vec![1, 2, 255])),
        };

        let json = serde_json::to_value(assertion).unwrap_or(serde_json::Value::Null);
        assert_eq!(json["data"], serde_json::json!([1, 2, 255]));
    }

    #[test]
    fn assertion_cbor_with_non_text_map_keys_fails_serialization() {
        let assertion = ManifestAssertion {
            label: "custom.assertion".to_string(),
            created: false,
            data: Some(c2pa_cbor::Value::Map(BTreeMap::from([(
                c2pa_cbor::Value::Integer(1),
                c2pa_cbor::Value::Null,
            )]))),
        };

        assert!(serde_json::to_value(assertion).is_err());
    }
}
