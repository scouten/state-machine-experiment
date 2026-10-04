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
//! Emits `dc:title`, `instanceID`, `claim_generator_info`, `signature`,
//! `alg`, and `created_assertions` — plus `gathered_assertions` when the
//! host marked any assertion as gathered rather than created (see
//! [`crate::AssertionKind`]).
//!
//! The shape follows the specification's `claim-map-v2`, which departs
//! from v1 in ways a v1-shaped writer would get wrong: `claim_generator_info`
//! is a single `generator-info-map` (carrying `specVersion`), not an array,
//! and the v1 `dc:format` and `claim_generator` fields do not exist. A
//! claim generator "shall not" produce a v1 claim, so there is no option to.
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

/// The version of the C2PA specification this encoder follows, written as
/// the generator's `specVersion` (SemVer, per the specification). Matches
/// the snapshot under `reference/c2pa-spec`.
const SPEC_VERSION: &str = "2.4.0";

/// The subset of a [`BuilderSettings`](crate::BuilderSettings) that
/// [`encode`] needs, decoupled from that type so this module can be
/// exercised independently of it.
pub(crate) struct ClaimFields<'a> {
    pub(crate) title: Option<&'a str>,
    pub(crate) instance_id: &'a str,
    pub(crate) generator_name: &'a str,
    pub(crate) generator_version: &'a str,
    pub(crate) alg_name: &'a str,
}

/// Encodes a C2PA v2 claim.
///
/// `created_assertion_refs` and `gathered_assertion_refs` are this claim's
/// assertions, split by the [`AssertionKind`](crate::AssertionKind) the
/// host declared each to be, each as `(url, hash)` pairs in the order they
/// should appear — the hard binding is always among the former, since a
/// hard binding this session computes itself is never gathered. Reused
/// unchanged between this crate's placeholder and final passes except for
/// the hard binding's own `hash` value, which is fixed-length either way
/// (see the module docs).
pub(crate) fn encode(
    fields: &ClaimFields<'_>,
    created_assertion_refs: &[(String, Vec<u8>)],
    gathered_assertion_refs: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, Error> {
    let mut map = BTreeMap::new();

    if let Some(title) = fields.title {
        map.insert(
            Value::Text("dc:title".to_string()),
            Value::Text(title.to_string()),
        );
    }

    map.insert(
        Value::Text("instanceID".to_string()),
        Value::Text(fields.instance_id.to_string()),
    );
    map.insert(
        Value::Text("claim_generator_info".to_string()),
        Value::Map(BTreeMap::from([
            (
                Value::Text("name".to_string()),
                Value::Text(fields.generator_name.to_string()),
            ),
            (
                Value::Text("version".to_string()),
                Value::Text(fields.generator_version.to_string()),
            ),
            (
                Value::Text("specVersion".to_string()),
                Value::Text(SPEC_VERSION.to_string()),
            ),
        ])),
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
        Value::Array(hashed_uri_array(created_assertion_refs)),
    );

    // Omitted rather than encoded as an empty array when there is nothing
    // gathered, matching how `dc:title` is omitted when absent: this
    // module never encodes a field that a real writer would leave out.
    if !gathered_assertion_refs.is_empty() {
        map.insert(
            Value::Text("gathered_assertions".to_string()),
            Value::Array(hashed_uri_array(gathered_assertion_refs)),
        );
    }

    Ok(c2pa_cbor::to_vec(&Value::Map(map))?)
}

/// Encodes a list of `(url, hash)` pairs as the CBOR array of hashed-URI
/// maps `created_assertions`/`gathered_assertions` both use.
fn hashed_uri_array(refs: &[(String, Vec<u8>)]) -> Vec<Value> {
    refs.iter()
        .map(|(url, hash)| {
            Value::Map(BTreeMap::from([
                (Value::Text("url".to_string()), Value::Text(url.clone())),
                (Value::Text("hash".to_string()), Value::Bytes(hash.clone())),
            ]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn fields() -> ClaimFields<'static> {
        ClaimFields {
            title: Some("A.jpg"),
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

        let bytes = encode(&fields(), &refs, &[]).unwrap();
        let decoded: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = decoded.as_map().unwrap();

        assert_eq!(
            map.get(&Value::Text("dc:title".to_string())),
            Some(&Value::Text("A.jpg".to_string()))
        );
        assert!(
            map.get(&Value::Text("dc:format".to_string())).is_none(),
            "dc:format does not exist in a v2 claim"
        );
        assert!(
            map.get(&Value::Text("claim_generator".to_string()))
                .is_none(),
            "claim_generator does not exist in a v2 claim"
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

        // A single map, not v1's array of maps.
        let Some(Value::Map(generator)) = map.get(&Value::Text("claim_generator_info".to_string()))
        else {
            panic!("expected claim_generator_info map");
        };
        assert_eq!(
            generator.get(&Value::Text("name".to_string())),
            Some(&Value::Text("test".to_string()))
        );
        assert_eq!(
            generator.get(&Value::Text("version".to_string())),
            Some(&Value::Text("1.0".to_string()))
        );
        assert_eq!(
            generator.get(&Value::Text("specVersion".to_string())),
            Some(&Value::Text(SPEC_VERSION.to_string()))
        );

        let Some(Value::Array(assertions)) =
            map.get(&Value::Text("created_assertions".to_string()))
        else {
            panic!("expected created_assertions array");
        };
        assert_eq!(assertions.len(), 2);

        assert!(
            map.get(&Value::Text("gathered_assertions".to_string()))
                .is_none(),
            "an empty gathered list should be omitted, not encoded as an empty array"
        );
    }

    #[test]
    fn encodes_gathered_assertions_separately_from_created() {
        let created = vec![(
            "self#jumbf=c2pa.assertions/c2pa.actions".to_string(),
            vec![1u8; 32],
        )];
        let gathered = vec![(
            "self#jumbf=c2pa.assertions/c2pa.metadata".to_string(),
            vec![2u8; 32],
        )];

        let bytes = encode(&fields(), &created, &gathered).unwrap();
        let decoded: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = decoded.as_map().unwrap();

        let Some(Value::Array(created_out)) =
            map.get(&Value::Text("created_assertions".to_string()))
        else {
            panic!("expected created_assertions array");
        };
        assert_eq!(created_out.len(), 1);

        let Some(Value::Array(gathered_out)) =
            map.get(&Value::Text("gathered_assertions".to_string()))
        else {
            panic!("expected gathered_assertions array");
        };
        assert_eq!(gathered_out.len(), 1);
    }

    #[test]
    fn omits_title_when_absent() {
        let mut f = fields();
        f.title = None;
        let bytes = encode(&f, &[], &[]).unwrap();
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

        let zero = encode(&fields(), &refs_zero, &[]).unwrap();
        let real = encode(&fields(), &refs_real, &[]).unwrap();

        assert_eq!(zero.len(), real.len());
        assert_ne!(zero, real);
    }
}
