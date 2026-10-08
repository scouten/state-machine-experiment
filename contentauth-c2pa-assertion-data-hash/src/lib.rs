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

//! The `c2pa.hash.data` assertion — a manifest's hard binding to the asset
//! it describes — as a self-contained element.
//!
//! # Independent by construction
//!
//! Nothing here knows about claims, JUMBF, signing, or any other
//! assertion. The crate's whole output is an
//! [`EncodedAssertion`]: a label and some CBOR. A workflow that composes
//! it with other elements (see `contentauth-c2pa-sidecar-builder`) cannot
//! depend on the assertion's fields, because it is never handed them.
//!
//! There are two ways in:
//!
//! * [`DataHash`] — when a digest is already in hand: describe it, call
//!   [`DataHash::encode`].
//! * [`DataHashSession`] — when the *asset* is what is in hand. A sans-I/O
//!   [`Session`](contentauth_state_machine::Session) that asks its host for the asset's length and bytes
//!   ([`DataHashRequest`]), hashes everything outside the configured
//!   exclusions in bounded memory, and finishes with the encoded
//!   assertion. It composes into a larger session the same way
//!   `contentauth-c2pa-file-reader`'s `FileReadSession` composes a
//!   `ReadSession`: the parent forwards its requests and replies.
//!
//! The assertion's `pad` field is always written empty: padding exists to
//! size-match a placeholder that is patched in place, which only the
//! embedding builder does, and it does so with its own encoder.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod session;

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::{ByteRange, EncodedAssertion, HashAlgorithm};
pub use session::{DataHashReply, DataHashRequest, DataHashSession, DataHashSettings, Error};

/// The assertion's label.
pub const LABEL: &str = "c2pa.hash.data";

/// A `c2pa.hash.data` assertion: a digest, and the ranges it leaves out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataHash {
    alg: HashAlgorithm,
    hash: Vec<u8>,
    exclusions: Vec<ByteRange>,
    name: Option<String>,
}

impl DataHash {
    /// Describes `hash`, computed under `alg` over a whole asset (no
    /// exclusions — right for a sidecar manifest, which has nothing of its
    /// own inside the asset).
    pub fn new(alg: HashAlgorithm, hash: Vec<u8>) -> Self {
        Self {
            alg,
            hash,
            exclusions: Vec::new(),
            name: None,
        }
    }

    /// Records the ranges the digest leaves out (an embedded manifest's
    /// own bytes).
    pub fn with_exclusions(mut self, exclusions: Vec<ByteRange>) -> Self {
        self.exclusions = exclusions;
        self
    }

    /// Records a human-readable name for the binding's target, such as
    /// `"jumbf manifest"`.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Encodes the assertion: label and CBOR, nothing else.
    pub fn encode(&self) -> Result<EncodedAssertion, c2pa_cbor::Error> {
        let mut map = BTreeMap::new();

        if !self.exclusions.is_empty() {
            let ranges = self
                .exclusions
                .iter()
                .map(|r| {
                    Value::Map(BTreeMap::from([
                        (Value::Text("start".into()), Value::Integer(r.start as i64)),
                        (Value::Text("length".into()), Value::Integer(r.len as i64)),
                    ]))
                })
                .collect();
            map.insert(Value::Text("exclusions".into()), Value::Array(ranges));
        }
        if let Some(name) = &self.name {
            map.insert(Value::Text("name".into()), Value::Text(name.clone()));
        }
        map.insert(
            Value::Text("alg".into()),
            Value::Text(self.alg.c2pa_name().into()),
        );
        map.insert(Value::Text("hash".into()), Value::Bytes(self.hash.clone()));
        map.insert(Value::Text("pad".into()), Value::Bytes(Vec::new()));

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
    fn encodes_to_the_c2pa_rs_shape() {
        let encoded = DataHash::new(HashAlgorithm::Sha256, vec![9; 32])
            .with_exclusions(vec![ByteRange { start: 4, len: 8 }])
            .with_name("jumbf manifest")
            .encode()
            .unwrap();
        assert_eq!(encoded.label, LABEL);

        let v: Value = c2pa_cbor::from_slice(&encoded.cbor).unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(
            m.get(&Value::Text("alg".into())),
            Some(&Value::Text("sha256".into()))
        );
        assert_eq!(
            m.get(&Value::Text("pad".into())),
            Some(&Value::Bytes(vec![]))
        );
        assert_eq!(
            m.get(&Value::Text("hash".into())),
            Some(&Value::Bytes(vec![9; 32]))
        );
        assert!(m.contains_key(&Value::Text("exclusions".into())));
    }

    #[test]
    fn no_exclusions_means_no_exclusions_key() {
        let encoded = DataHash::new(HashAlgorithm::Sha256, vec![0; 32])
            .encode()
            .unwrap();
        let v: Value = c2pa_cbor::from_slice(&encoded.cbor).unwrap();
        assert!(!v
            .as_map()
            .unwrap()
            .contains_key(&Value::Text("exclusions".into())));
    }
}
