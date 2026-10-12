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

//! Ingredients: `c2pa.ingredient.v3` assertions, and the `c2pa.actions.v2`
//! entries that tie them to the manifest.
//!
//! Everything here is pure data transformation, so it needs no host
//! requests: [`resolve`] turns [`BuilderSettings`] into the final list of
//! assertions, *before* the manifest is laid out. An ingredient assertion's
//! hashed URI depends only on that assertion's own bytes — never on the
//! hard binding — so it is final at placeholder time, and the actions
//! assertion that references it can be too.
//!
//! # Linking actions to ingredients
//!
//! A host cannot encode `parameters.ingredients` itself: it holds the
//! *hash* of an ingredient assertion, which only this crate computes.
//! Following c2pa-rs's `Builder` JSON, an action may therefore name
//! ingredients by [`IngredientSettings::label`] under
//! `parameters.ingredientIds`; [`resolve`] replaces that temporary
//! parameter with real `parameters.ingredients` hashed URIs.
//!
//! # What the specification requires, and where it is done
//!
//! * A `parentOf` ingredient is opened by a `c2pa.opened` action that is
//!   the first action of the first `created` actions assertion; each
//!   `componentOf` ingredient is placed by a `c2pa.placed` action
//!   (*Ingredient → Relationship*). With
//!   [`BuilderSettings::auto_ingredient_actions`] (on by default, as in
//!   c2pa-rs) this module adds whichever is missing.
//! * A manifest has at most one `parentOf` ingredient
//!   (`manifest.multipleParents`).
//! * A parent's ingredient assertion is a *created* assertion; any other
//!   is *gathered* unless [`IngredientSettings::created`] says otherwise.
//!
//! # Scope
//!
//! Only ingredients with no manifest of their own are supported so far: no
//! `activeManifest`, `claimSignature` or `validationResults`, and no
//! thumbnail or data. See the walkthrough's *Ingredients* page for the
//! plan.

use std::collections::{BTreeMap, HashSet};

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::HashAlgorithm;

use crate::{
    builder::{Assertion, AssertionKind, BuilderSettings},
    error::Error,
    jumbf::{assertion_digest, assertion_uri},
};

/// Label of a v3 ingredient assertion.
const INGREDIENT_LABEL: &str = "c2pa.ingredient.v3";

/// Label of the v2 actions assertion, the only version whose ingredient
/// references this module writes.
const ACTIONS_LABEL: &str = "c2pa.actions.v2";

/// How an ingredient relates to the asset being built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Relationship {
    /// The asset is a derived asset or rendition of this ingredient. A
    /// manifest has at most one.
    ParentOf,

    /// The asset is composed of several parts, this being one.
    ComponentOf,

    /// The ingredient was an input to a computational process (an AI/ML
    /// model, say) that led to the asset.
    InputTo,
}

impl Relationship {
    /// The value of the assertion's `relationship` field.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ParentOf => "parentOf",
            Self::ComponentOf => "componentOf",
            Self::InputTo => "inputTo",
        }
    }
}

/// One ingredient of the asset being built.
///
/// **Temporary limit:** only an ingredient with no manifest of its own can
/// be described so far (see this module's docs).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IngredientSettings {
    /// How the ingredient relates to the asset.
    pub relationship: Relationship,

    /// A name for linking an action to this ingredient, via
    /// `parameters.ingredientIds` — never written to the manifest. Unique
    /// among the manifest's ingredients if present.
    pub label: Option<String>,

    /// The ingredient's human-readable name (`dc:title`).
    pub title: Option<String>,

    /// The ingredient's media type (`dc:format`).
    pub format: Option<String>,

    /// Identifies the ingredient (`instanceID`), typically its
    /// `xmpMM:InstanceID`. This crate has no randomness source, so it does
    /// not make one up; the host supplies it or does without.
    pub instance_id: Option<String>,

    /// What the ingredient is, or is used for (`description`).
    pub description: Option<String>,

    /// A page of information about the ingredient (`informationalURI`).
    pub informational_uri: Option<String>,

    /// The ingredient's `digitalSourceType`, one of those the actions
    /// specification allows. An ingredient with no manifest is the only
    /// kind that may carry one, which is the only kind this crate
    /// supports today.
    pub digital_source_type: Option<String>,

    /// Whether the ingredient assertion is a *created* assertion rather
    /// than a *gathered* one. Ignored for a [`Relationship::ParentOf`]
    /// ingredient, which is always created.
    pub created: bool,
}

impl IngredientSettings {
    /// An ingredient with the given relationship and nothing else set.
    pub fn new(relationship: Relationship) -> Self {
        Self {
            relationship,
            label: None,
            title: None,
            format: None,
            instance_id: None,
            description: None,
            informational_uri: None,
            digital_source_type: None,
            created: false,
        }
    }

    fn kind(&self) -> AssertionKind {
        if self.created || self.relationship == Relationship::ParentOf {
            AssertionKind::Created
        } else {
            AssertionKind::Gathered
        }
    }

    /// The assertion's CBOR content: a `c2pa.ingredient.v3` map.
    fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut map = BTreeMap::new();
        map.insert(text("relationship"), text(self.relationship.as_str()));
        for (key, value) in [
            ("dc:title", &self.title),
            ("dc:format", &self.format),
            ("instanceID", &self.instance_id),
            ("description", &self.description),
            ("informationalURI", &self.informational_uri),
            ("digitalSourceType", &self.digital_source_type),
        ] {
            if let Some(value) = value {
                map.insert(text(key), text(value));
            }
        }
        Ok(c2pa_cbor::to_vec(&Value::Map(map))?)
    }
}

/// The assertion label of the `index`th ingredient: the specification's
/// usual numbering for repeated assertions.
pub(crate) fn label_for(index: usize) -> String {
    match index {
        0 => INGREDIENT_LABEL.to_string(),
        n => format!("{INGREDIENT_LABEL}__{n}"),
    }
}

/// A hashed URI to one of the manifest's own assertions.
struct Reference {
    url: String,
    hash: Vec<u8>,
}

impl Reference {
    fn to_value(&self) -> Value {
        Value::Map(BTreeMap::from([
            (text("url"), text(&self.url)),
            (text("hash"), Value::Bytes(self.hash.clone())),
        ]))
    }
}

/// The assertions a manifest built from `settings` carries, beyond the
/// hard binding and identity assertions: the host's own, with actions'
/// `ingredientIds` resolved, followed by one ingredient assertion per
/// ingredient and any actions assertion this module had to add.
pub(crate) fn resolve(
    settings: &BuilderSettings,
    hash_alg: HashAlgorithm,
) -> Result<Vec<Assertion>, Error> {
    let ingredients = &settings.ingredients;
    let mut assertions = settings.assertions.clone();

    let mut ids = HashSet::new();
    for ingredient in ingredients {
        if let Some(label) = &ingredient.label {
            if !ids.insert(label.as_str()) {
                return Err(Error::DuplicateIngredientLabel(label.clone()));
            }
        }
    }
    if ingredients
        .iter()
        .filter(|i| i.relationship == Relationship::ParentOf)
        .count()
        > 1
    {
        return Err(Error::MultipleParents);
    }

    // Each ingredient's assertion, and the reference actions use to name it.
    let mut references = Vec::with_capacity(ingredients.len());
    let mut ingredient_assertions = Vec::with_capacity(ingredients.len());
    for (index, ingredient) in ingredients.iter().enumerate() {
        let label = label_for(index);
        let cbor = ingredient.to_cbor()?;
        references.push(Reference {
            url: assertion_uri(&label),
            hash: assertion_digest(hash_alg, &label, &cbor)?,
        });
        ingredient_assertions.push(Assertion {
            label,
            cbor,
            kind: ingredient.kind(),
        });
    }

    // Resolve `ingredientIds` in every v2 actions assertion the host gave.
    let by_id: Vec<(&str, &Reference)> = ingredients
        .iter()
        .zip(&references)
        .filter_map(|(i, r)| i.label.as_deref().map(|id| (id, r)))
        .collect();
    let mut decoded: Vec<Option<Value>> = Vec::with_capacity(assertions.len());
    for assertion in &mut assertions {
        if assertion.label != ACTIONS_LABEL {
            decoded.push(None);
            continue;
        }
        let mut value: Value = c2pa_cbor::from_slice(&assertion.cbor)?;
        resolve_ingredient_ids(&mut value, &by_id)?;
        decoded.push(Some(value));
    }

    if settings.auto_ingredient_actions && !ingredients.is_empty() {
        // The first created actions assertion carries the inception action.
        let designated = assertions
            .iter()
            .zip(&decoded)
            .position(|(a, v)| v.is_some() && a.kind == AssertionKind::Created);

        let existing = designated.and_then(|i| decoded[i].take());
        let mut synthesized = existing.is_none();
        let mut actions = existing.unwrap_or_else(|| Value::Map(BTreeMap::new()));

        let placed = placed_urls(&actions, decoded.iter().flatten());
        let new_actions = missing_actions(ingredients, &references, &actions, &placed);
        if new_actions.is_empty() {
            // Nothing to add: an assertion we made up is not worth writing.
            synthesized = false;
        } else {
            add_actions(&mut actions, new_actions)?;
        }

        match (designated, synthesized) {
            (Some(i), _) => decoded[i] = Some(actions),
            (None, true) => {
                // No created actions assertion existed: add one, under the
                // first label not already taken.
                let taken: HashSet<&str> = assertions.iter().map(|a| a.label.as_str()).collect();
                let label = (0..)
                    .map(|n| match n {
                        0 => ACTIONS_LABEL.to_string(),
                        n => format!("{ACTIONS_LABEL}__{n}"),
                    })
                    .find(|label| !taken.contains(label.as_str()))
                    .unwrap_or_else(|| ACTIONS_LABEL.to_string());
                assertions.push(Assertion {
                    label,
                    cbor: c2pa_cbor::to_vec(&actions)?,
                    kind: AssertionKind::Created,
                });
                decoded.push(None);
            }
            (None, false) => {}
        }
    }

    // Re-encode only the actions assertions this module rewrote.
    for (assertion, value) in assertions.iter_mut().zip(&decoded) {
        if let Some(value) = value {
            assertion.cbor = c2pa_cbor::to_vec(value)?;
        }
    }

    assertions.extend(ingredient_assertions);
    Ok(assertions)
}

/// The actions the manifest's ingredients still need: a `c2pa.opened` for
/// a parent not yet opened by a leading inception action, and a
/// `c2pa.placed` for each component not yet placed.
fn missing_actions(
    ingredients: &[IngredientSettings],
    references: &[Reference],
    designated: &Value,
    placed: &HashSet<String>,
) -> Vec<Value> {
    let mut new_actions = Vec::new();

    let has_inception = action_list(designated).is_some_and(|list| {
        list.iter()
            .any(|a| matches!(action_name(a), Some("c2pa.created" | "c2pa.opened")))
    });

    for (ingredient, reference) in ingredients.iter().zip(references) {
        match ingredient.relationship {
            Relationship::ParentOf if !has_inception => {
                new_actions.insert(0, action("c2pa.opened", reference));
            }
            Relationship::ComponentOf if !placed.contains(&reference.url) => {
                new_actions.push(action("c2pa.placed", reference));
            }
            _ => {}
        }
    }
    new_actions
}

/// Adds `new_actions` to an actions assertion: an opening action goes
/// first, as the specification requires of the inception action, and the
/// rest follow the existing ones.
fn add_actions(assertion: &mut Value, new_actions: Vec<Value>) -> Result<(), Error> {
    let Value::Map(map) = assertion else {
        return Err(Error::InvalidActions("the assertion is not a map"));
    };
    let list = match map.entry(text("actions")) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => entry.insert(Value::Array(vec![])),
    };
    let Value::Array(list) = list else {
        return Err(Error::InvalidActions("`actions` is not an array"));
    };

    let (opening, rest): (Vec<_>, Vec<_>) = new_actions
        .into_iter()
        .partition(|a| action_name(a) == Some("c2pa.opened"));
    list.splice(0..0, opening);
    list.extend(rest);
    Ok(())
}

/// The URLs every `c2pa.placed` action in `assertions` (and `first`)
/// already references.
fn placed_urls<'a>(first: &'a Value, rest: impl Iterator<Item = &'a Value>) -> HashSet<String> {
    let mut urls = HashSet::new();
    for assertion in std::iter::once(first).chain(rest) {
        for action in action_list(assertion).unwrap_or(&[]) {
            if action_name(action) != Some("c2pa.placed") {
                continue;
            }
            let referenced = match action {
                Value::Map(m) => m.get(&text("parameters")),
                _ => None,
            };
            let Some(Value::Map(parameters)) = referenced else {
                continue;
            };
            if let Some(Value::Array(refs)) = parameters.get(&text("ingredients")) {
                for reference in refs {
                    if let Value::Map(m) = reference {
                        if let Some(Value::Text(url)) = m.get(&text("url")) {
                            urls.insert(url.clone());
                        }
                    }
                }
            }
        }
    }
    urls
}

/// Replaces each action's `parameters.ingredientIds` with
/// `parameters.ingredients`.
fn resolve_ingredient_ids(
    assertion: &mut Value,
    by_id: &[(&str, &Reference)],
) -> Result<(), Error> {
    let Value::Map(map) = assertion else {
        return Err(Error::InvalidActions("the assertion is not a map"));
    };
    let Some(Value::Array(list)) = map.get_mut(&text("actions")) else {
        return Ok(());
    };

    for action in list {
        let Value::Map(action) = action else { continue };
        let Some(Value::Map(parameters)) = action.get_mut(&text("parameters")) else {
            continue;
        };
        let Some(ids) = parameters.remove(&text("ingredientIds")) else {
            continue;
        };
        let Value::Array(ids) = ids else {
            return Err(Error::InvalidActions("`ingredientIds` is not an array"));
        };

        let mut resolved = match parameters.remove(&text("ingredients")) {
            Some(Value::Array(existing)) => existing,
            _ => Vec::new(),
        };
        for id in ids {
            let Value::Text(id) = id else {
                return Err(Error::InvalidActions("an ingredient id is not text"));
            };
            let (_, reference) = by_id
                .iter()
                .find(|(known, _)| *known == id)
                .ok_or_else(|| Error::UnknownIngredientId(id.clone()))?;
            resolved.push(reference.to_value());
        }
        parameters.insert(text("ingredients"), Value::Array(resolved));
    }
    Ok(())
}

/// A new action naming one ingredient.
fn action(name: &str, reference: &Reference) -> Value {
    Value::Map(BTreeMap::from([
        (text("action"), text(name)),
        (
            text("parameters"),
            Value::Map(BTreeMap::from([(
                text("ingredients"),
                Value::Array(vec![reference.to_value()]),
            )])),
        ),
    ]))
}

fn action_list(assertion: &Value) -> Option<&[Value]> {
    let Value::Map(map) = assertion else {
        return None;
    };
    match map.get(&text("actions")) {
        Some(Value::Array(list)) => Some(list),
        _ => None,
    }
}

fn action_name(action: &Value) -> Option<&str> {
    let Value::Map(map) = action else { return None };
    match map.get(&text("action")) {
        Some(Value::Text(name)) => Some(name),
        _ => None,
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use contentauth_c2pa_primitives::SigningAlg;

    use super::*;
    use crate::builder::GeneratorInfo;

    fn settings() -> BuilderSettings {
        BuilderSettings::new(
            "xmp:iid:1",
            "urn:uuid:1",
            GeneratorInfo::new("test", "1"),
            SigningAlg::Es256,
            vec![vec![1]],
        )
    }

    fn resolved(settings: &BuilderSettings) -> Result<Vec<Assertion>, Error> {
        resolve(settings, HashAlgorithm::Sha256)
    }

    fn decode(assertion: &Assertion) -> Value {
        c2pa_cbor::from_slice(&assertion.cbor).unwrap()
    }

    fn find<'a>(assertions: &'a [Assertion], label: &str) -> &'a Assertion {
        assertions.iter().find(|a| a.label == label).unwrap()
    }

    /// Names of the actions in an actions assertion, in order.
    fn action_names(assertion: &Assertion) -> Vec<String> {
        action_list(&decode(assertion))
            .unwrap()
            .iter()
            .map(|a| action_name(a).unwrap().to_string())
            .collect()
    }

    #[test]
    fn no_ingredients_leaves_the_assertions_alone() {
        let mut settings = settings();
        settings.assertions = vec![Assertion::new("c2pa.actions.v2", vec![0xa0])];

        let assertions = resolved(&settings).unwrap();
        assert_eq!(assertions.len(), 1);
        assert_eq!(assertions[0].cbor, vec![0xa0]);
    }

    #[test]
    fn a_parent_gets_a_created_assertion_and_an_opened_action() {
        let mut settings = settings();
        let mut parent = IngredientSettings::new(Relationship::ParentOf);
        parent.title = Some("source.jpg".into());
        parent.format = Some("image/jpeg".into());
        settings.ingredients = vec![parent];

        let assertions = resolved(&settings).unwrap();

        let ingredient = find(&assertions, "c2pa.ingredient.v3");
        assert_eq!(ingredient.kind, AssertionKind::Created);
        let Value::Map(map) = decode(ingredient) else {
            panic!("not a map");
        };
        assert_eq!(map.get(&text("relationship")), Some(&text("parentOf")));
        assert_eq!(map.get(&text("dc:title")), Some(&text("source.jpg")));

        let actions = find(&assertions, "c2pa.actions.v2");
        assert_eq!(actions.kind, AssertionKind::Created);
        assert_eq!(action_names(actions), ["c2pa.opened"]);
    }

    #[test]
    fn the_opened_action_references_the_ingredient_assertion_by_hash() {
        let mut settings = settings();
        settings.ingredients = vec![IngredientSettings::new(Relationship::ParentOf)];

        let assertions = resolved(&settings).unwrap();
        let ingredient = find(&assertions, "c2pa.ingredient.v3");
        let expected = assertion_digest(
            HashAlgorithm::Sha256,
            "c2pa.ingredient.v3",
            &ingredient.cbor,
        )
        .unwrap();

        let actions = decode(find(&assertions, "c2pa.actions.v2"));
        let Some(Value::Map(opened)) = action_list(&actions).unwrap().first() else {
            panic!("no action");
        };
        let Some(Value::Map(parameters)) = opened.get(&text("parameters")) else {
            panic!("no parameters");
        };
        let Some(Value::Array(refs)) = parameters.get(&text("ingredients")) else {
            panic!("no ingredients");
        };
        let Value::Map(reference) = &refs[0] else {
            panic!("not a map");
        };
        assert_eq!(
            reference.get(&text("url")),
            Some(&text("self#jumbf=c2pa.assertions/c2pa.ingredient.v3"))
        );
        assert_eq!(reference.get(&text("hash")), Some(&Value::Bytes(expected)));
    }

    #[test]
    fn components_are_gathered_unless_marked_created_and_numbered_in_order() {
        let mut settings = settings();
        let mut created = IngredientSettings::new(Relationship::ComponentOf);
        created.created = true;
        settings.ingredients = vec![
            IngredientSettings::new(Relationship::ComponentOf),
            created,
            IngredientSettings::new(Relationship::InputTo),
        ];

        let assertions = resolved(&settings).unwrap();

        assert_eq!(
            find(&assertions, "c2pa.ingredient.v3").kind,
            AssertionKind::Gathered
        );
        assert_eq!(
            find(&assertions, "c2pa.ingredient.v3__1").kind,
            AssertionKind::Created
        );
        assert_eq!(
            find(&assertions, "c2pa.ingredient.v3__2").kind,
            AssertionKind::Gathered
        );

        // Each component is placed; an input is not.
        assert_eq!(
            action_names(find(&assertions, "c2pa.actions.v2")),
            ["c2pa.placed", "c2pa.placed"]
        );
    }

    #[test]
    fn a_missing_opened_action_goes_first_in_the_hosts_own_actions() {
        let mut settings = settings();
        let actions = c2pa_cbor::to_vec(&Value::Map(BTreeMap::from([(
            text("actions"),
            Value::Array(vec![Value::Map(BTreeMap::from([(
                text("action"),
                text("c2pa.cropped"),
            )]))]),
        )])))
        .unwrap();
        settings.assertions = vec![Assertion::new("c2pa.actions.v2", actions)];
        settings.ingredients = vec![IngredientSettings::new(Relationship::ParentOf)];

        let assertions = resolved(&settings).unwrap();

        assert_eq!(
            assertions
                .iter()
                .filter(|a| a.label.starts_with("c2pa.actions"))
                .count(),
            1
        );
        assert_eq!(
            action_names(find(&assertions, "c2pa.actions.v2")),
            ["c2pa.opened", "c2pa.cropped"]
        );
    }

    #[test]
    fn ingredient_ids_become_hashed_references_and_suppress_auto_placement() {
        let mut settings = settings();
        let placed = Value::Map(BTreeMap::from([
            (text("action"), text("c2pa.placed")),
            (
                text("parameters"),
                Value::Map(BTreeMap::from([(
                    text("ingredientIds"),
                    Value::Array(vec![text("logo")]),
                )])),
            ),
        ]));
        let actions = c2pa_cbor::to_vec(&Value::Map(BTreeMap::from([(
            text("actions"),
            Value::Array(vec![placed]),
        )])))
        .unwrap();
        settings.assertions = vec![Assertion::new("c2pa.actions.v2", actions)];
        let mut logo = IngredientSettings::new(Relationship::ComponentOf);
        logo.label = Some("logo".into());
        settings.ingredients = vec![logo];

        let assertions = resolved(&settings).unwrap();

        let actions = find(&assertions, "c2pa.actions.v2");
        assert_eq!(action_names(actions), ["c2pa.placed"]);
        let decoded = decode(actions);
        let Some(Value::Map(action)) = action_list(&decoded).unwrap().first() else {
            panic!("no action");
        };
        let Some(Value::Map(parameters)) = action.get(&text("parameters")) else {
            panic!("no parameters");
        };
        assert!(parameters.get(&text("ingredientIds")).is_none());
        assert!(parameters.get(&text("ingredients")).is_some());
    }

    #[test]
    fn auto_actions_can_be_turned_off() {
        let mut settings = settings();
        settings.auto_ingredient_actions = false;
        settings.ingredients = vec![
            IngredientSettings::new(Relationship::ParentOf),
            IngredientSettings::new(Relationship::ComponentOf),
        ];

        let assertions = resolved(&settings).unwrap();
        assert!(assertions
            .iter()
            .all(|a| !a.label.starts_with("c2pa.actions")));
    }

    #[test]
    fn two_parents_are_refused() {
        let mut settings = settings();
        settings.ingredients = vec![
            IngredientSettings::new(Relationship::ParentOf),
            IngredientSettings::new(Relationship::ParentOf),
        ];
        assert!(matches!(resolved(&settings), Err(Error::MultipleParents)));
    }

    #[test]
    fn an_unknown_or_duplicate_ingredient_id_is_refused() {
        let mut settings = settings();
        let action = Value::Map(BTreeMap::from([
            (text("action"), text("c2pa.placed")),
            (
                text("parameters"),
                Value::Map(BTreeMap::from([(
                    text("ingredientIds"),
                    Value::Array(vec![text("nope")]),
                )])),
            ),
        ]));
        let actions = c2pa_cbor::to_vec(&Value::Map(BTreeMap::from([(
            text("actions"),
            Value::Array(vec![action]),
        )])))
        .unwrap();
        settings.assertions = vec![Assertion::new("c2pa.actions.v2", actions)];
        assert!(matches!(
            resolved(&settings),
            Err(Error::UnknownIngredientId(id)) if id == "nope"
        ));

        let mut settings = self::settings();
        let mut a = IngredientSettings::new(Relationship::ComponentOf);
        a.label = Some("same".into());
        settings.ingredients = vec![a.clone(), a];
        assert!(matches!(
            resolved(&settings),
            Err(Error::DuplicateIngredientLabel(_))
        ));
    }

    #[test]
    fn a_synthesized_actions_assertion_takes_a_free_label() {
        let mut settings = settings();
        // A *gathered* actions assertion cannot carry the inception action,
        // so a created one is added beside it.
        settings.assertions = vec![Assertion::gathered("c2pa.actions.v2", vec![0xa0])];
        settings.ingredients = vec![IngredientSettings::new(Relationship::ParentOf)];

        let assertions = resolved(&settings).unwrap();
        assert_eq!(
            action_names(find(&assertions, "c2pa.actions.v2__1")),
            ["c2pa.opened"]
        );
    }
}
