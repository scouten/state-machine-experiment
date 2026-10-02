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

use contentauth_c2pa_builder::{Assertion, BuilderSettings, GeneratorInfo};
use contentauth_c2pa_primitives::SigningAlg;
use serde::Deserialize;

use crate::error::Error;

/// The baseline case's manifest definition (see the crate docs).
pub const BASELINE_DEFINITION: &str = r#"{
  "title": "baseline.jpg",
  "instance_id": "xmp:iid:00000000-0000-4000-8000-000000000001",
  "label": "urn:uuid:00000000-0000-4000-8000-000000000002",
  "claim_generator_info": [
    { "name": "c2pa-sign-baseline", "version": "0.1" }
  ],
  "assertions": [
    {
      "label": "c2pa.actions.v2",
      "data": {
        "actions": [
          {
            "action": "c2pa.created",
            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
          }
        ]
      }
    }
  ]
}"#;

/// A manifest definition: the subset of c2pa-rs's `ManifestDefinition`
/// JSON the builder engine can act on today, plus `instance_id` and
/// `label`, which c2pa-rs would generate and this workspace's engine
/// requires its host to supply.
///
/// A field outside this subset is an error rather than silently ignored,
/// so a definition written for c2pa-rs that this experiment cannot honor
/// fails loudly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    /// Human-readable title of the asset.
    #[serde(default)]
    pub title: Option<String>,

    /// Identifier for this instance of the asset.
    pub instance_id: String,

    /// The manifest's label within its store, typically `urn:uuid:…`.
    pub label: String,

    /// Exactly one entry.
    pub claim_generator_info: Vec<ClaimGenerator>,

    /// Assertions beyond the hard binding the engine adds itself.
    #[serde(default)]
    pub assertions: Vec<AssertionDefinition>,
}

/// A `claim_generator_info` entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimGenerator {
    /// The generating software's name.
    pub name: String,

    /// Its version.
    pub version: String,
}

/// One assertion: a label and its JSON `data`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssertionDefinition {
    /// The assertion's label, for example `c2pa.actions.v2`.
    pub label: String,

    /// The assertion's content, encoded to CBOR when settings are built.
    pub data: serde_json::Value,

    /// Whether this claim's generator created the assertion (the default)
    /// rather than gathered it.
    #[serde(default = "created_by_default")]
    pub created: bool,
}

fn created_by_default() -> bool {
    true
}

impl Definition {
    /// Parses a definition from JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|err| Error::BadDefinition(err.to_string()))
    }

    /// Builds the engine's settings for `format` (a MIME type), signed
    /// with `alg` and the DER certificate chain `certificates` (signer
    /// first) — the two things a signer, rather than a definition, decides.
    ///
    /// RSASSA-PSS algorithms need `BuilderSettings::rsa_signature_len`
    /// too; set it on the result.
    pub fn into_settings(
        self,
        format: &str,
        alg: SigningAlg,
        certificates: Vec<Vec<u8>>,
    ) -> Result<BuilderSettings, Error> {
        let [generator] = <[ClaimGenerator; 1]>::try_from(self.claim_generator_info)
            .map_err(|_| Error::ClaimGenerator)?;

        let mut settings = BuilderSettings::new(
            format,
            self.instance_id,
            self.label,
            GeneratorInfo::new(generator.name, generator.version),
            alg,
            certificates,
        );
        settings.title = self.title;

        for assertion in self.assertions {
            let cbor = c2pa_cbor::to_vec(&assertion.data).map_err(|err| Error::Assertion {
                label: assertion.label.clone(),
                message: err.to_string(),
            })?;
            settings.assertions.push(if assertion.created {
                Assertion::new(assertion.label, cbor)
            } else {
                Assertion::gathered(assertion.label, cbor)
            });
        }

        Ok(settings)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use contentauth_c2pa_builder::AssertionKind;

    use super::*;

    fn settings(json: &str) -> Result<BuilderSettings, Error> {
        Definition::from_json(json)?.into_settings("image/jpeg", SigningAlg::Es256, vec![vec![1]])
    }

    #[test]
    fn the_baseline_definition_becomes_one_created_actions_assertion() {
        let settings = settings(BASELINE_DEFINITION).unwrap();

        assert_eq!(settings.format, "image/jpeg");
        assert_eq!(settings.title.as_deref(), Some("baseline.jpg"));
        assert_eq!(settings.claim_generator_info.name, "c2pa-sign-baseline");
        assert_eq!(settings.signing_alg, SigningAlg::Es256);
        assert_eq!(settings.certificates, [vec![1]]);
        assert!(settings.timestamp.is_none());

        assert_eq!(settings.assertions.len(), 1);
        let assertion = &settings.assertions[0];
        assert_eq!(assertion.label, "c2pa.actions.v2");
        assert_eq!(assertion.kind, AssertionKind::Created);

        // Round-trips as the same JSON it was encoded from.
        let decoded: serde_json::Value = c2pa_cbor::from_slice(&assertion.cbor).unwrap();
        assert_eq!(
            decoded["actions"][0]["action"],
            serde_json::json!("c2pa.created")
        );
    }

    #[test]
    fn created_false_marks_an_assertion_gathered() {
        let json = BASELINE_DEFINITION.replace(
            "\"label\": \"c2pa.actions.v2\",",
            "\"label\": \"c2pa.actions.v2\", \"created\": false,",
        );
        let settings = settings(&json).unwrap();
        assert_eq!(settings.assertions[0].kind, AssertionKind::Gathered);
    }

    #[test]
    fn a_field_outside_the_supported_subset_is_an_error_not_ignored() {
        let json = BASELINE_DEFINITION.replace("\"title\"", "\"ingredients\": [], \"title\"");
        assert!(matches!(settings(&json), Err(Error::BadDefinition(_))));
    }

    #[test]
    fn instance_id_and_label_are_required() {
        let json = r#"{ "claim_generator_info": [{ "name": "a", "version": "1" }] }"#;
        assert!(matches!(settings(json), Err(Error::BadDefinition(_))));
    }

    #[test]
    fn exactly_one_claim_generator_is_required() {
        for generators in [
            "[]",
            r#"[{"name":"a","version":"1"},{"name":"b","version":"2"}]"#,
        ] {
            let json =
                format!(r#"{{"instance_id":"i","label":"l","claim_generator_info":{generators}}}"#);
            assert_eq!(settings(&json).unwrap_err(), Error::ClaimGenerator);
        }
    }

    #[test]
    fn malformed_json_is_a_bad_definition() {
        assert!(matches!(settings("{"), Err(Error::BadDefinition(_))));
    }
}
