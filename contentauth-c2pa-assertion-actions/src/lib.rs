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

//! The `c2pa.actions.v2` assertion — what was done to produce this version
//! of the asset — as a self-contained element.
//!
//! Like `contentauth-c2pa-assertion-data-hash`, this crate's whole output
//! is an [`EncodedAssertion`]: a label and opaque CBOR. It is pure data in,
//! pure data out — no session, because nothing here ever needs the host.
//!
//! It models a deliberate subset of the specification's `actions-map-v2`
//! (the action, its digital source type, its software agent, `when`), and
//! refuses to encode what a validator would refuse to accept:
//! [`Actions::encode`] fails for an empty list, an action with no name, and
//! a `c2pa.created` action with no `digitalSourceType`.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::EncodedAssertion;

/// The assertion's label.
pub const LABEL: &str = "c2pa.actions.v2";

/// The action name for "this asset was created".
pub const CREATED: &str = "c2pa.created";

/// IPTC digital source type: no particular source claimed. A reasonable
/// default for placeholder or synthetic content.
pub const DIGITAL_SOURCE_TYPE_EMPTY: &str = "http://c2pa.org/digitalsourcetype/empty";

/// Why an actions assertion could not be encoded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The assertion has no actions; a valid one has at least one.
    #[error("an actions assertion needs at least one action")]
    NoActions,

    /// An action has an empty name.
    #[error("an action has no name")]
    UnnamedAction,

    /// A `c2pa.created` action lacks the `digitalSourceType` validators
    /// require of it.
    #[error("a c2pa.created action needs a digitalSourceType")]
    CreatedWithoutSourceType,

    /// The CBOR encoder failed.
    #[error(transparent)]
    Cbor(#[from] c2pa_cbor::Error),
}

/// One action (`action-item-map-v2`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    action: String,
    digital_source_type: Option<String>,
    software_agent: Option<String>,
    when: Option<String>,
}

impl Action {
    /// An action by name (for example [`CREATED`], `c2pa.edited`).
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            digital_source_type: None,
            software_agent: None,
            when: None,
        }
    }

    /// A `c2pa.created` action with the given IPTC digital source type URI.
    pub fn created(digital_source_type: impl Into<String>) -> Self {
        Self::new(CREATED).with_digital_source_type(digital_source_type)
    }

    /// Sets the IPTC digital source type URI.
    pub fn with_digital_source_type(mut self, uri: impl Into<String>) -> Self {
        self.digital_source_type = Some(uri.into());
        self
    }

    /// Names the software that performed the action.
    pub fn with_software_agent(mut self, agent: impl Into<String>) -> Self {
        self.software_agent = Some(agent.into());
        self
    }

    /// Records when the action happened, as an RFC 3339 date-time string.
    /// This crate has no clock; the host supplies the text.
    pub fn with_when(mut self, when: impl Into<String>) -> Self {
        self.when = Some(when.into());
        self
    }

    fn to_value(&self) -> Result<Value, Error> {
        if self.action.is_empty() {
            return Err(Error::UnnamedAction);
        }
        if self.action == CREATED && self.digital_source_type.is_none() {
            return Err(Error::CreatedWithoutSourceType);
        }

        let mut map = BTreeMap::new();
        map.insert(
            Value::Text("action".into()),
            Value::Text(self.action.clone()),
        );
        for (key, value) in [
            ("digitalSourceType", &self.digital_source_type),
            ("softwareAgent", &self.software_agent),
            ("when", &self.when),
        ] {
            if let Some(v) = value {
                map.insert(Value::Text(key.into()), Value::Text(v.clone()));
            }
        }
        Ok(Value::Map(map))
    }
}

/// A `c2pa.actions.v2` assertion: the actions, in the order performed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Actions {
    actions: Vec<Action>,
}

impl Actions {
    /// An assertion with no actions yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an action.
    pub fn with(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Encodes the assertion: label and CBOR, nothing else.
    pub fn encode(&self) -> Result<EncodedAssertion, Error> {
        if self.actions.is_empty() {
            return Err(Error::NoActions);
        }
        let items = self
            .actions
            .iter()
            .map(Action::to_value)
            .collect::<Result<Vec<_>, _>>()?;

        let map = BTreeMap::from([(Value::Text("actions".into()), Value::Array(items))]);
        Ok(EncodedAssertion::new(
            LABEL,
            c2pa_cbor::to_vec(&Value::Map(map))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn encodes_a_created_action() {
        let a = Actions::new()
            .with(Action::created(DIGITAL_SOURCE_TYPE_EMPTY).with_software_agent("t/1"))
            .encode()
            .unwrap();
        assert_eq!(a.label, "c2pa.actions.v2");

        let v: Value = c2pa_cbor::from_slice(&a.cbor).unwrap();
        let Some(Value::Array(items)) = v.as_map().unwrap().get(&Value::Text("actions".into()))
        else {
            panic!("no actions array");
        };
        let item = items[0].as_map().unwrap();
        assert_eq!(
            item.get(&Value::Text("action".into())),
            Some(&Value::Text("c2pa.created".into()))
        );
        assert_eq!(
            item.get(&Value::Text("digitalSourceType".into())),
            Some(&Value::Text(DIGITAL_SOURCE_TYPE_EMPTY.into()))
        );
        assert_eq!(
            item.get(&Value::Text("softwareAgent".into())),
            Some(&Value::Text("t/1".into()))
        );
        assert!(!item.contains_key(&Value::Text("when".into())));
    }

    #[test]
    fn refuses_what_validators_refuse() {
        assert!(matches!(Actions::new().encode(), Err(Error::NoActions)));
        assert!(matches!(
            Actions::new().with(Action::new("")).encode(),
            Err(Error::UnnamedAction)
        ));
        assert!(matches!(
            Actions::new().with(Action::new(CREATED)).encode(),
            Err(Error::CreatedWithoutSourceType)
        ));
    }
}
