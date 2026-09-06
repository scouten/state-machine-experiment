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

//! Encoder for the C2PA v2 claim. The counterpart to
//! `contentauth-c2pa-reader`'s `claim` module, which decodes both claim
//! versions — this crate only ever builds v2 claims (v1 is a read-only
//! concern, for interoperating with manifests this crate did not write).
//!
//! Emits `dc:title`, `dc:format`, `instanceID`, `claim_generator_info`,
//! `signature`, `alg`, and `created_assertions`. `gathered_assertions`
//! (assertions carried over from an ingredient) is out of scope, since
//! this crate does not yet support ingredients — see this crate's README.
//!
//! # Why this needs no padding
//!
//! Every value that changes between this crate's placeholder and final
//! passes is a fixed-length digest (an assertion's hashed-URI reference),
//! never a value whose *encoded length* varies — so, unlike `data_hash` or
//! `cose`'s timestamp header, the claim's own CBOR length never needs a
//! two-pass reconciliation.

use std::collections::BTreeMap;

use c2pa_cbor::Value;

use crate::error::Error;

/// JUMBF URI of a manifest's own claim signature, relative to the
/// manifest. Matches the literal string
/// `contentauth_c2pa_reader::claim`'s decoder tests expect a claim to
/// carry.
const SIGNATURE_URI: &str = "self#jumbf=c2pa.signature";

/// The subset of a [`BuilderSettings`](crate::BuilderSettings) that
/// [`encode`] needs, decoupled from that type so this module can be
/// exercised independently of it.
pub(crate) struct ClaimFields<'a> {
    pub(crate) title: Option<&'a str>,
    pub(crate) format: &'a str,
    pub(crate) instance_id: &'a str,
    pub(crate) generator_name: &'a str,
    pub(crate) generator_version: &'a str,
    pub(crate) alg_name: &'a str,
}

/// Encodes a C2PA v2 claim.
///
/// `assertion_refs` is every assertion this claim covers, as
/// `(url, hash)` pairs, in the order they should appear — including the
/// hard binding. Every one is a *created* assertion: this crate has no
/// notion of an assertion gathered from an ingredient. Reused unchanged
/// between this crate's placeholder and final passes except for the hard
/// binding's own `hash` value, which is fixed-length either way (see the
/// module docs).
pub(crate) fn encode(
    fields: &ClaimFields<'_>,
    assertion_refs: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();

    if let Some(title) = fields.title {
        map.insert(
            Value::Text("dc:title".to_string()),
            Value::Text(title.to_string()),
        );
    }

    map.insert(
        Value::Text("dc:format".to_string()),
        Value::Text(fields.format.to_string()),
    );
    map.insert(
        Value::Text("instanceID".to_string()),
        Value::Text(fields.instance_id.to_string()),
    );
    map.insert(
        Value::Text("claim_generator_info".to_string()),
        Value::Array(vec![Value::Map(BTreeMap::from([
            (
                Value::Text("name".to_string()),
                Value::Text(fields.generator_name.to_string()),
            ),
            (
                Value::Text("version".to_string()),
                Value::Text(fields.generator_version.to_string()),
            ),
        ]))]),
    );
    map.insert(
        Value::Text("signature".to_string()),
        Value::Text(SIGNATURE_URI.to_string()),
    );
    map.insert(
        Value::Text("alg".to_string()),
        Value::Text(fields.alg_name.to_string()),
    );
    map.insert(
        Value::Text("created_assertions".to_string()),
        Value::Array(
            assertion_refs
                .iter()
                .map(|(url, hash)| {
                    Value::Map(BTreeMap::from([
                        (Value::Text("url".to_string()), Value::Text(url.clone())),
                        (Value::Text("hash".to_string()), Value::Bytes(hash.clone())),
                    ]))
                })
                .collect(),
        ),
    );

    Ok(c2pa_cbor::to_vec(&Value::Map(map))?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn fields() -> ClaimFields<'static> {
        ClaimFields {
            title: Some("A.jpg"),
            format: "image/jpeg",
            instance_id: "xmp:iid:1234",
            generator_name: "test",
            generator_version: "1.0",
            alg_name: "sha256",
        }
    }

    #[test]
    fn encodes_every_field_the_reader_decodes() {
        let refs = vec![
            (
                "self#jumbf=c2pa.assertions/c2pa.actions".to_string(),
                vec![1u8; 32],
            ),
            (
                "self#jumbf=c2pa.assertions/c2pa.hash.data".to_string(),
                vec![2u8; 32],
            ),
        ];

        let bytes = encode(&fields(), &refs).unwrap();
        let decoded: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = decoded.as_map().unwrap();

        assert_eq!(
            map.get(&Value::Text("dc:title".to_string())),
            Some(&Value::Text("A.jpg".to_string()))
        );
        assert_eq!(
            map.get(&Value::Text("dc:format".to_string())),
            Some(&Value::Text("image/jpeg".to_string()))
        );
        assert_eq!(
            map.get(&Value::Text("instanceID".to_string())),
            Some(&Value::Text("xmp:iid:1234".to_string()))
        );
        assert_eq!(
            map.get(&Value::Text("signature".to_string())),
            Some(&Value::Text(SIGNATURE_URI.to_string()))
        );
        assert_eq!(
            map.get(&Value::Text("alg".to_string())),
            Some(&Value::Text("sha256".to_string()))
        );

        let Some(Value::Array(generators)) =
            map.get(&Value::Text("claim_generator_info".to_string()))
        else {
            panic!("expected claim_generator_info array");
        };
        assert_eq!(generators.len(), 1);

        let Some(Value::Array(assertions)) =
            map.get(&Value::Text("created_assertions".to_string()))
        else {
            panic!("expected created_assertions array");
        };
        assert_eq!(assertions.len(), 2);
    }

    #[test]
    fn omits_title_when_absent() {
        let mut f = fields();
        f.title = None;
        let bytes = encode(&f, &[]).unwrap();
        let decoded: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        assert!(decoded
            .as_map()
            .unwrap()
            .get(&Value::Text("dc:title".to_string()))
            .is_none());
    }

    #[test]
    fn changing_only_a_hash_value_does_not_change_the_encoded_length() {
        let refs_zero = vec![("self#jumbf=x".to_string(), vec![0u8; 32])];
        let refs_real = vec![("self#jumbf=x".to_string(), vec![0xab; 32])];

        let zero = encode(&fields(), &refs_zero).unwrap();
        let real = encode(&fields(), &refs_real).unwrap();

        assert_eq!(zero.len(), real.len());
        assert_ne!(zero, real);
    }
}
