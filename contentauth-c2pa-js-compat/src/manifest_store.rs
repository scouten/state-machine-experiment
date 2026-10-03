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
//! `Manifest`. That schema also carries ingredients, decoded assertion
//! values, thumbnails, and resource references, none of which
//! [`contentauth_c2pa_reader`] decodes yet. What is reproduced here is the
//! top-level contract callers lean on — a `manifests` object keyed by
//! label, an `active_manifest` label, a `validation_state`, and a
//! `validation_status` array in the C2PA status-code vocabulary —
//! populated with what this workspace's reader knows how to report today,
//! and in the same shape `contentauth-c2pa-rs-compat`'s `Reader::json`
//! produces, so the two compatibility layers agree with each other.
//!
//! Every type here owns its data and implements [`serde::Serialize`], so
//! a binding can hand it straight to `serde_wasm_bindgen` (as the `web`
//! feature's `WasmReader` does) or `serde_json` (as [`crate::Reader::json`]
//! does).

use std::collections::BTreeMap;

use contentauth_c2pa_reader::ReadReport;
use serde::Serialize;

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

    /// A user-displayable title for the asset, if the claim carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// The asset's MIME type, if the claim carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// The asset's instance identifier, or an empty string if the claim
    /// carries none — c2pa-rs's own `Manifest` has no way to say "absent"
    /// here either.
    pub instance_id: String,

    /// Labels of the assertions physically present in the manifest's
    /// assertion store, in store order.
    pub assertions: Vec<String>,
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

impl ManifestStore {
    /// Reports `report` in c2pa-rs's manifest-store shape.
    ///
    /// Public so that a sibling compatibility layer over another c2pa-rs
    /// surface (`contentauth-c2pa-node-compat`) can reuse the one
    /// reporting of the engine's result rather than copy it.
    pub fn from_report(report: &ReadReport) -> Self {
        Self {
            active_manifest: report.active_manifest.clone(),
            manifests: report
                .manifests
                .iter()
                .map(|manifest| (manifest.label.clone(), Manifest::from_inner(manifest)))
                .collect(),
            validation_state: report.validation_state.into(),
            validation_status: report
                .statuses
                .iter()
                .map(|status| ValidationStatus {
                    code: status.code.clone(),
                    url: status.url.clone(),
                    explanation: status.explanation.clone(),
                    trust_list_uri: status.trust_list_uri.clone(),
                })
                .collect(),
        }
    }
}

impl Manifest {
    /// Reports one of `report`'s manifests; see [`ManifestStore::from_report`].
    pub fn from_inner(manifest: &contentauth_c2pa_reader::Manifest) -> Self {
        Self {
            label: manifest.label.clone(),
            claim_generator: manifest.claim.claim_generator.clone(),
            title: manifest.claim.title.clone(),
            format: manifest.claim.format.clone(),
            instance_id: manifest.claim.instance_id.clone().unwrap_or_default(),
            assertions: manifest.assertion_labels.clone(),
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
        };

        let json = serde_json::to_value(store).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            json,
            serde_json::json!({
                "manifests": {},
                "validation_state": "Invalid",
            })
        );
    }

    #[test]
    fn a_manifest_omits_the_optional_fields_it_does_not_have() {
        let manifest = Manifest {
            label: "urn:uuid:x".to_string(),
            claim_generator: None,
            title: None,
            format: Some("image/jpeg".to_string()),
            instance_id: String::new(),
            assertions: vec!["c2pa.hash.data".to_string()],
        };

        let json = serde_json::to_value(manifest).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            json,
            serde_json::json!({
                "label": "urn:uuid:x",
                "format": "image/jpeg",
                "instance_id": "",
                "assertions": ["c2pa.hash.data"],
            })
        );
    }
}
