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

use contentauth_c2pa_builder::{
    Assertion, BuilderSettings, GeneratorInfo, IngredientSettings, Relationship, TimestampSettings,
};
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

    /// The asset's ingredients, in c2pa-rs's `Ingredient` JSON shape.
    ///
    /// **Temporary limit:** only ingredients with no manifest of their own
    /// can be described so far, so a field that belongs to one with a
    /// manifest or a thumbnail is an error like any other outside the
    /// supported subset. An action names an ingredient by its `label`
    /// under `parameters.ingredientIds`, as in c2pa-rs.
    #[serde(default)]
    pub ingredients: Vec<IngredientDefinition>,

    /// The URL of an RFC 3161 time-stamp authority (c2pa-rs
    /// spells the field `ta_url`). Present means the claim signature is countersigned with
    /// a timestamp: [`Definition::into_settings`] then sets
    /// `BuilderSettings::timestamp`, and the host must answer the
    /// resulting timestamp request by POSTing to this URL (the engine
    /// never touches the network). Absent (the baseline case) means no
    /// timestamp. Must be an `http://` or `https://` URL.
    #[serde(default)]
    pub tsa_url: Option<String>,
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

/// One ingredient, spelled as c2pa-rs's `Ingredient` JSON spells it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IngredientDefinition {
    /// `parentOf`, `componentOf` (the default, as in c2pa-rs) or
    /// `inputTo`.
    #[serde(default = "component_of")]
    pub relationship: RelationshipDefinition,

    /// A name for linking an action to this ingredient; never written to
    /// the manifest.
    #[serde(default)]
    pub label: Option<String>,

    /// The ingredient's human-readable name.
    #[serde(default)]
    pub title: Option<String>,

    /// The ingredient's media type.
    #[serde(default)]
    pub format: Option<String>,

    /// The ingredient's identifier. Like the manifest's own, the engine
    /// has no RNG to make one up, so it is only written if given.
    #[serde(default)]
    pub instance_id: Option<String>,

    /// What the ingredient is, or is used for.
    #[serde(default)]
    pub description: Option<String>,

    /// A page of information about the ingredient (c2pa-rs's spelling).
    #[serde(default, rename = "informational_URI")]
    pub informational_uri: Option<String>,

    /// One of the digital source types the specification allows.
    #[serde(default)]
    pub digital_source_type: Option<String>,

    /// Whether the ingredient assertion is a created assertion rather
    /// than a gathered one. Ignored for a parent.
    #[serde(default)]
    pub is_created: bool,
}

fn component_of() -> RelationshipDefinition {
    RelationshipDefinition::ComponentOf
}

/// An ingredient's `relationship`, as c2pa-rs's JSON spells it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum RelationshipDefinition {
    /// `parentOf`.
    #[serde(rename = "parentOf")]
    ParentOf,

    /// `componentOf`.
    #[serde(rename = "componentOf")]
    ComponentOf,

    /// `inputTo`.
    #[serde(rename = "inputTo")]
    InputTo,
}

impl From<IngredientDefinition> for IngredientSettings {
    fn from(definition: IngredientDefinition) -> Self {
        let mut ingredient = IngredientSettings::new(match definition.relationship {
            RelationshipDefinition::ParentOf => Relationship::ParentOf,
            RelationshipDefinition::ComponentOf => Relationship::ComponentOf,
            RelationshipDefinition::InputTo => Relationship::InputTo,
        });
        ingredient.label = definition.label;
        ingredient.title = definition.title;
        ingredient.format = definition.format;
        ingredient.instance_id = definition.instance_id;
        ingredient.description = definition.description;
        ingredient.informational_uri = definition.informational_uri;
        ingredient.digital_source_type = definition.digital_source_type;
        ingredient.created = definition.is_created;
        ingredient
    }
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
        let definition: Self =
            serde_json::from_str(json).map_err(|err| Error::BadDefinition(err.to_string()))?;

        if let Some(url) = &definition.tsa_url {
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                return Err(Error::BadDefinition(format!(
                    "tsa_url must be an http or https URL, not {url:?}"
                )));
            }
        }
        Ok(definition)
    }

    /// Builds the engine's settings, signed with `alg` and the DER
    /// certificate chain `certificates` (signer first) — the two things a
    /// signer, rather than a definition, decides.
    ///
    /// RSASSA-PSS algorithms need `BuilderSettings::rsa_signature_len`
    /// too; set it on the result.
    pub fn into_settings(
        self,
        alg: SigningAlg,
        certificates: Vec<Vec<u8>>,
    ) -> Result<BuilderSettings, Error> {
        let [generator] = <[ClaimGenerator; 1]>::try_from(self.claim_generator_info)
            .map_err(|_| Error::ClaimGenerator)?;

        let mut settings = BuilderSettings::new(
            self.instance_id,
            self.label,
            GeneratorInfo::new(generator.name, generator.version),
            alg,
            certificates,
        );
        settings.title = self.title;
        if self.tsa_url.is_some() {
            settings.timestamp = Some(TimestampSettings::default());
        }

        settings.ingredients = self.ingredients.into_iter().map(Into::into).collect();

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
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use contentauth_c2pa_builder::AssertionKind;

    use super::*;

    fn settings(json: &str) -> Result<BuilderSettings, Error> {
        Definition::from_json(json)?.into_settings(SigningAlg::Es256, vec![vec![1]])
    }

    #[test]
    fn the_baseline_definition_becomes_one_created_actions_assertion() {
        let settings = settings(BASELINE_DEFINITION).unwrap();

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
    fn tsa_url_requests_a_timestamp() {
        let json = BASELINE_DEFINITION.replace(
            "\"title\"",
            "\"tsa_url\": \"http://timestamp.example/tsa\", \"title\"",
        );
        let definition = Definition::from_json(&json).unwrap();
        assert_eq!(
            definition.tsa_url.as_deref(),
            Some("http://timestamp.example/tsa")
        );

        let settings = definition
            .into_settings(SigningAlg::Es256, vec![vec![1]])
            .unwrap();
        assert_eq!(
            settings.timestamp.map(|t| t.reserve_size),
            Some(TimestampSettings::default().reserve_size)
        );
    }

    #[test]
    fn tsa_url_must_be_http_or_https() {
        for url in ["file:///etc/passwd", "ftp://x/", "timestamp.example"] {
            let json = BASELINE_DEFINITION
                .replace("\"title\"", &format!("\"tsa_url\": \"{url}\", \"title\""));
            assert!(
                matches!(Definition::from_json(&json), Err(Error::BadDefinition(_))),
                "{url}"
            );
        }
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
        let json = BASELINE_DEFINITION.replace("\"title\"", "\"thumbnail\": {}, \"title\"");
        assert!(matches!(settings(&json), Err(Error::BadDefinition(_))));

        // Likewise inside an ingredient: a thumbnail needs resources this
        // definition cannot carry yet.
        let json = BASELINE_DEFINITION.replace(
            "\"title\"",
            "\"ingredients\": [{ \"thumbnail\": {} }], \"title\"",
        );
        assert!(matches!(settings(&json), Err(Error::BadDefinition(_))));
    }

    #[test]
    fn ingredients_become_engine_ingredients_in_c2pa_rs_shape() {
        let json = BASELINE_DEFINITION.replace(
            "\"title\"",
            r#""ingredients": [
                { "relationship": "parentOf", "title": "source.jpg",
                  "format": "image/jpeg", "instance_id": "xmp:iid:s",
                  "label": "src", "informational_URI": "https://example.com/s" },
                { "title": "logo.png", "is_created": true },
                { "relationship": "inputTo", "title": "model" }
              ], "title""#,
        );

        let settings = settings(&json).unwrap();

        let [parent, logo, input] = settings.ingredients.as_slice() else {
            panic!("expected three ingredients");
        };
        assert_eq!(parent.relationship, Relationship::ParentOf);
        assert_eq!(parent.label.as_deref(), Some("src"));
        assert_eq!(parent.title.as_deref(), Some("source.jpg"));
        assert_eq!(parent.format.as_deref(), Some("image/jpeg"));
        assert_eq!(parent.instance_id.as_deref(), Some("xmp:iid:s"));
        assert_eq!(
            parent.informational_uri.as_deref(),
            Some("https://example.com/s")
        );
        // c2pa-rs's default relationship.
        assert_eq!(logo.relationship, Relationship::ComponentOf);
        assert!(logo.created);
        assert_eq!(input.relationship, Relationship::InputTo);
    }

    #[test]
    fn a_misspelled_relationship_is_an_error() {
        let json = BASELINE_DEFINITION.replace(
            "\"title\"",
            r#""ingredients": [{ "relationship": "siblingOf" }], "title""#,
        );
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
