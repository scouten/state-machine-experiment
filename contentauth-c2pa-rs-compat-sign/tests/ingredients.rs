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

//! Ingredients through the blocking, c2pa-rs-shaped `Builder`: a manifest
//! definition that lists a parent and a component, signed into a JPEG and
//! read back through the sibling read-side compat layer.
//!
//! Ingredients with no manifest of their own, described in the definition,
//! are all this covers so far; `Builder::add_ingredient_from_stream`
//! waits for the session that reads an ingredient's own asset.

#![allow(clippy::unwrap_used)]

use std::{io::Cursor, path::PathBuf};

use contentauth_c2pa_rs_compat::{Context, ReadSettings, Reader, ValidationState};
use contentauth_c2pa_rs_compat_sign::{Builder, HostError, Signer, SigningAlg};
use contentauth_c2pa_sign_baseline::fixtures::*;

struct TestSigner;

impl Signer for TestSigner {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![TEST_SIGNER_CERT.to_vec()]
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY_PEM,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .and_then(|signer| signer.sign(data))
        .map_err(|err| HostError::new(err.to_string()))
    }
}

/// A definition in c2pa-rs's JSON shape: open `source.jpg` and place a
/// logo, the opening action naming its ingredient by label and the
/// placement left for the builder to add.
const EDIT_DEFINITION: &str = r#"{
  "title": "edited.jpg",
  "instance_id": "xmp:iid:00000000-0000-4000-8000-000000000001",
  "label": "urn:uuid:00000000-0000-4000-8000-000000000002",
  "claim_generator_info": [{ "name": "c2pa-sign-baseline", "version": "0.1" }],
  "ingredients": [
    { "relationship": "parentOf", "label": "source", "title": "source.jpg",
      "format": "image/jpeg", "instance_id": "xmp:iid:source" },
    { "relationship": "componentOf", "title": "logo.png", "format": "image/png",
      "digital_source_type": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation" }
  ],
  "assertions": [
    { "label": "c2pa.actions.v2",
      "data": { "actions": [
        { "action": "c2pa.opened", "parameters": { "ingredientIds": ["source"] } },
        { "action": "c2pa.cropped" }
      ] } }
  ]
}"#;

fn read(bytes: Vec<u8>, name: &str) -> Reader {
    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), name].iter().collect();
    std::fs::write(&path, bytes).unwrap();
    Reader::from_context(Context::new().with_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    }))
    .with_file(&path)
    .unwrap()
}

#[test]
fn a_definition_with_a_parent_and_a_component_signs_and_reads_back_trusted() {
    let mut dest = Cursor::new(Vec::new());
    Builder::from_json(EDIT_DEFINITION)
        .unwrap()
        .sign(
            &TestSigner,
            "image/jpeg",
            Cursor::new(SOURCE_JPEG),
            &mut dest,
        )
        .unwrap();

    let reader = read(dest.into_inner(), "ingredients-out.jpg");

    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    // Everything recorded is a pass or a note; nothing says the ingredients
    // or the actions that name them are wrong.
    let statuses = reader.validation_status().unwrap();
    let codes: Vec<&str> = statuses.iter().map(|s| s.code()).collect();
    for bad in [
        "mismatch",
        "Mismatch",
        "malformed",
        "missing",
        "multipleParents",
    ] {
        assert!(codes.iter().all(|c| !c.contains(bad)), "{codes:?}");
    }
    assert_eq!(
        codes
            .iter()
            .filter(|c| **c == "ingredient.unknownProvenance")
            .count(),
        2
    );

    let json: serde_json::Value = serde_json::from_str(&reader.json()).unwrap();
    let labels: Vec<&str> = json["manifests"][reader.active_label().unwrap()]["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|label| label.as_str().unwrap())
        .collect();
    assert!(labels.contains(&"c2pa.ingredient.v3"), "{labels:?}");
    assert!(labels.contains(&"c2pa.ingredient.v3__1"), "{labels:?}");
    assert!(labels.contains(&"c2pa.actions.v2"), "{labels:?}");
}

#[test]
fn an_action_naming_an_ingredient_that_is_not_listed_is_an_error() {
    let definition = EDIT_DEFINITION.replace(r#""label": "source", "#, "");
    let mut dest = Cursor::new(Vec::new());
    let result = Builder::from_json(&definition).unwrap().sign(
        &TestSigner,
        "image/jpeg",
        Cursor::new(SOURCE_JPEG),
        &mut dest,
    );
    assert!(result.is_err());
}
