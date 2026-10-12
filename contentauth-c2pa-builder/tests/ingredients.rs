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

//! Ingredients written by [`BuilderSession`] and read back by
//! `contentauth_c2pa_reader::ReadSession`: the same round trip as
//! `identity.rs`, here showing that the two independently written halves
//! agree on ingredient assertions and on the actions that name them.
//!
//! Only ingredients with no manifest of their own so far — see
//! `contentauth_c2pa_builder::IngredientSettings`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_builder::{
    Assertion, BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep,
    ByteRange, Error, GeneratorInfo, IngredientSettings, Relationship, SigningAlg,
};
use contentauth_c2pa_reader::{
    ingredient::Relationship as ReadRelationship, ReadHostReply, ReadReport, ReadRequest,
    ReadSession, ReadSettings, ReadStep, ValidationState,
};
use contentauth_state_machine::Session;

const TEST_SIGNER_CERT: &[u8] = include_bytes!("fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] = include_bytes!("fixtures/test-signer.key.pem");

/// Builds into an in-memory asset, then reads the result back.
fn build_and_read(settings: BuilderSettings) -> Result<ReadReport, Error> {
    let mut asset: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let mut range = None;

    let mut session = BuilderSession::new(settings);
    loop {
        if session.advance()? == BuilderStep::Complete {
            session.finish()?;
            break;
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                    asset.splice(100..100, placeholder.iter().copied());
                    range = Some((100usize, placeholder.len()));
                    BuilderHostReply::PlaceholderReserved(vec![ByteRange {
                        start: 100,
                        len: placeholder.len() as u64,
                    }])
                }
                BuilderRequest::AssetLength { .. } => {
                    BuilderHostReply::AssetLength(asset.len() as u64)
                }
                BuilderRequest::AssetBytes { range, .. } => {
                    let start = range.start as usize;
                    BuilderHostReply::AssetBytes(asset[start..start + range.len as usize].to_vec())
                }
                BuilderRequest::Sign { data, .. } => {
                    let signer = c2pa_raw_crypto::signer_from_private_key(
                        TEST_SIGNER_KEY,
                        c2pa_raw_crypto::SigningAlg::Es256,
                    )
                    .unwrap();
                    BuilderHostReply::Signature(signer.sign(data).unwrap())
                }
                BuilderRequest::CommitManifest { manifest, .. } => {
                    let (start, len) = range.unwrap();
                    asset[start..start + len].copy_from_slice(manifest);
                    BuilderHostReply::ManifestCommitted
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply)?;
        }
    }

    let (start, len) = range.unwrap();
    let mut session = ReadSession::new(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    });
    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            return Ok(session.finish().unwrap());
        }
        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => {
                    ReadHostReply::ManifestStore(Some(asset[start..start + len].to_vec()))
                }
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(1_800_000_000),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => ReadHostReply::AssetBytes(
                    asset[range.start as usize..(range.start + range.len) as usize].to_vec(),
                ),
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

fn settings() -> BuilderSettings {
    BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    )
}

fn action_names(report: &ReadReport) -> Vec<String> {
    // The reader does not decode assertion values yet, so look at what the
    // claim lists instead.
    report
        .active()
        .unwrap()
        .assertion_labels
        .iter()
        .filter(|l| l.starts_with("c2pa.actions"))
        .cloned()
        .collect()
}

#[test]
fn a_parent_and_a_component_read_back_trusted_with_no_failures() {
    let mut parent = IngredientSettings::new(Relationship::ParentOf);
    parent.title = Some("source.jpg".into());
    parent.format = Some("image/jpeg".into());
    parent.instance_id = Some("xmp:iid:source".into());

    let mut logo = IngredientSettings::new(Relationship::ComponentOf);
    logo.title = Some("logo.png".into());
    logo.digital_source_type =
        Some("http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation".into());

    let mut settings = settings();
    settings.ingredients = vec![parent, logo];

    let report = build_and_read(settings).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(
        report.statuses.iter().all(|s| !s.is_failure()),
        "{:?}",
        report.statuses
    );

    let active = report.active().unwrap();
    let [parent, logo] = active.ingredients.as_slice() else {
        panic!("expected two ingredients: {:?}", active.ingredients);
    };
    assert_eq!(parent.label, "c2pa.ingredient.v3");
    assert_eq!(parent.relationship, Some(ReadRelationship::ParentOf));
    assert_eq!(parent.title.as_deref(), Some("source.jpg"));
    assert_eq!(parent.format.as_deref(), Some("image/jpeg"));
    assert_eq!(parent.instance_id.as_deref(), Some("xmp:iid:source"));
    assert_eq!(logo.label, "c2pa.ingredient.v3__1");
    assert_eq!(logo.relationship, Some(ReadRelationship::ComponentOf));
    assert!(logo.digital_source_type.is_some());

    // The parent is a created assertion, the component a gathered one.
    assert!(active
        .claim
        .created_assertions
        .iter()
        .any(|r| r.url.ends_with("/c2pa.ingredient.v3")));
    assert!(active
        .claim
        .gathered_assertions
        .iter()
        .any(|r| r.url.ends_with("/c2pa.ingredient.v3__1")));

    // Neither has a manifest, which is noted but is not a failure.
    assert_eq!(
        report
            .statuses
            .iter()
            .filter(|s| s.code == "ingredient.unknownProvenance")
            .count(),
        2
    );

    // And the actions the builder added agree with the reader's own check
    // of them (`assertion.action.ingredientMismatch` would be a failure).
    assert_eq!(action_names(&report), ["c2pa.actions.v2"]);
}

#[test]
fn actions_naming_ingredients_by_id_are_resolved_and_checked_by_the_reader() {
    use std::collections::BTreeMap;

    use c2pa_cbor::Value;

    let text = |s: &str| Value::Text(s.to_string());
    let actions = Value::Map(BTreeMap::from([(
        text("actions"),
        Value::Array(vec![
            Value::Map(BTreeMap::from([
                (text("action"), text("c2pa.opened")),
                (
                    text("parameters"),
                    Value::Map(BTreeMap::from([(
                        text("ingredientIds"),
                        Value::Array(vec![text("original")]),
                    )])),
                ),
            ])),
            Value::Map(BTreeMap::from([(text("action"), text("c2pa.cropped"))])),
        ]),
    )]));

    let mut original = IngredientSettings::new(Relationship::ParentOf);
    original.label = Some("original".into());

    let mut settings = settings();
    settings.assertions = vec![Assertion::new(
        "c2pa.actions.v2",
        c2pa_cbor::to_vec(&actions).unwrap(),
    )];
    settings.ingredients = vec![original];

    let report = build_and_read(settings).unwrap();

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(
        report.statuses.iter().all(|s| !s.is_failure()),
        "{:?}",
        report.statuses
    );
}

#[test]
fn a_component_the_hosts_actions_forgot_is_placed_automatically_unless_told_not_to() {
    let mut settings_on = settings();
    settings_on.ingredients = vec![IngredientSettings::new(Relationship::ComponentOf)];
    let report = build_and_read(settings_on).unwrap();
    assert_eq!(action_names(&report), ["c2pa.actions.v2"]);

    let mut settings_off = settings();
    settings_off.auto_ingredient_actions = false;
    settings_off.ingredients = vec![IngredientSettings::new(Relationship::ComponentOf)];
    let report = build_and_read(settings_off).unwrap();
    assert!(action_names(&report).is_empty());
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn two_parents_are_refused_before_anything_is_embedded() {
    let mut settings = settings();
    settings.ingredients = vec![
        IngredientSettings::new(Relationship::ParentOf),
        IngredientSettings::new(Relationship::ParentOf),
    ];
    assert!(matches!(
        build_and_read(settings),
        Err(Error::MultipleParents)
    ));
}
