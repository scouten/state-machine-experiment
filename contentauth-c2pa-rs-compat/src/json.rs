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

//! The JSON shape [`crate::Reader::json`] and
//! [`crate::Reader::json_checked`] produce.
//!
//! This deliberately does not attempt to reproduce c2pa-rs's manifest-store
//! JSON schema byte for byte — that schema also carries ingredients,
//! decoded assertion values, resource references and more, none of which
//! [`contentauth_c2pa_reader`] decodes yet. What is reproduced is the
//! *contract* `Reader::json`'s callers actually lean on: a pretty-printed
//! JSON object keyed by manifest label, an `active_manifest` label, and a
//! `validation_status` array in the C2PA status-code vocabulary — the same
//! top-level shape, populated with what this workspace's reader knows how
//! to report today.

use std::collections::BTreeMap;

use contentauth_c2pa_reader::{ClaimVersion, ReadReport};
use serde::Serialize;

use crate::validation::ValidationState;

#[derive(Serialize)]
struct ManifestStoreJson<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    active_manifest: Option<&'a str>,
    manifests: BTreeMap<&'a str, ManifestJson<'a>>,
    validation_state: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    validation_status: Vec<ValidationStatusJson<'a>>,
}

#[derive(Serialize)]
struct ManifestJson<'a> {
    label: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    claim_generator_info: Vec<GeneratorInfoJson<'a>>,
    claim_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'a str>,
    instance_id: &'a str,
    assertions: &'a [String],
}

/// One `claim_generator_info` entry. `specVersion` keeps its
/// specification spelling; `icon` is not reported (a hashed reference to
/// an embedded-data assertion this reader does not resolve).
#[derive(Serialize)]
struct GeneratorInfoJson<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(rename = "specVersion", skip_serializing_if = "Option::is_none")]
    spec_version: Option<&'a str>,
}

#[derive(Serialize)]
struct ValidationStatusJson<'a> {
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<&'a str>,
}

fn state_name(state: ValidationState) -> &'static str {
    match state {
        ValidationState::Trusted => "Trusted",
        ValidationState::Valid => "Valid",
        ValidationState::Invalid => "Invalid",
    }
}

/// Builds the JSON value [`crate::Reader::json`]/[`crate::Reader::json_checked`]
/// serialize.
pub(crate) fn value(report: &ReadReport) -> Result<serde_json::Value, serde_json::Error> {
    let manifests = report
        .manifests
        .iter()
        .map(|manifest| {
            (
                manifest.label.as_str(),
                ManifestJson {
                    label: &manifest.label,
                    claim_generator: manifest.claim.claim_generator.as_deref(),
                    claim_generator_info: manifest
                        .claim
                        .claim_generator_info
                        .iter()
                        .map(|info| GeneratorInfoJson {
                            name: info.name.as_deref(),
                            version: info.version.as_deref(),
                            spec_version: info.spec_version.as_deref(),
                        })
                        .collect(),
                    claim_version: match manifest.claim.version {
                        ClaimVersion::V1 => 1,
                        _ => 2,
                    },
                    title: manifest.claim.title.as_deref(),
                    format: manifest.claim.format.as_deref(),
                    instance_id: manifest.claim.instance_id.as_deref().unwrap_or_default(),
                    assertions: &manifest.assertion_labels,
                },
            )
        })
        .collect();

    let store = ManifestStoreJson {
        active_manifest: report.active_manifest.as_deref(),
        manifests,
        validation_state: state_name(ValidationState::from(report.validation_state)),
        validation_status: report
            .statuses
            .iter()
            .map(|status| ValidationStatusJson {
                code: &status.code,
                url: status.url.as_deref(),
                explanation: status.explanation.as_deref(),
            })
            .collect(),
    };

    serde_json::to_value(store)
}
