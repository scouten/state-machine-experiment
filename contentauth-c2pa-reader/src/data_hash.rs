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
//! it describes.
//!
//! The assertion records a digest over the whole asset *except* the ranges
//! it excludes, which are the ranges the manifest itself occupies (a
//! manifest cannot cover its own bytes). Verifying it therefore means
//! hashing everything outside those exclusions, which the read workflow
//! does from chunks the host streams in.

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::ByteRange;

/// Label of the data hash assertion.
pub(crate) const LABEL: &str = "c2pa.hash.data";

/// A decoded `c2pa.hash.data` assertion.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct DataHash {
    /// Ranges of the asset the hash deliberately does not cover.
    pub exclusions: Vec<ByteRange>,

    /// Hash algorithm, when the assertion names one of its own.
    pub alg: Option<String>,

    /// The recorded digest of the asset outside the exclusions.
    pub hash: Vec<u8>,

    /// Human-readable name for the binding.
    pub name: Option<String>,
}

/// Decodes a `c2pa.hash.data` assertion from its CBOR payload.
///
/// Returns `None` if the payload is not a well-formed data hash — a
/// malformed hard binding is reported as a validation status rather than
/// failing the read, so the caller needs to distinguish it from a decode
/// that simply found nothing.
pub(crate) fn decode(cbor: &[u8]) -> Option<DataHash> {
    let value: Value = c2pa_cbor::from_slice(cbor).ok()?;
    let map = value.as_map()?;

    let mut data_hash = DataHash::default();
    let mut saw_hash = false;

    for (key, value) in map {
        match key.as_str() {
            Some("exclusions") => {
                let entries = value.as_array()?;
                data_hash.exclusions = entries.iter().map(exclusion).collect::<Option<Vec<_>>>()?;
            }

            Some("alg") => data_hash.alg = Some(value.as_str()?.to_string()),

            Some("hash") => {
                data_hash.hash = value.as_bytes()?.to_vec();
                saw_hash = true;
            }

            Some("name") => data_hash.name = Some(value.as_str()?.to_string()),

            // `pad` / `pad2` exist only to reserve space in the encoded
            // assertion, and anything else is not part of this shape.
            _ => {}
        }
    }

    // A data hash without a hash is not a hard binding at all.
    saw_hash.then_some(data_hash)
}

/// Decodes one exclusion range.
fn exclusion(value: &Value) -> Option<ByteRange> {
    let map = value.as_map()?;
    let mut start = None;
    let mut len = None;

    for (key, value) in map {
        match key.as_str() {
            // Negative offsets and lengths are meaningless here, so a
            // negative value makes the exclusion malformed rather than
            // wrapping into an enormous unsigned range.
            Some("start") => start = Some(u64::try_from(value.as_i64()?).ok()?),
            Some("length") => len = Some(u64::try_from(value.as_i64()?).ok()?),
            _ => {}
        }
    }

    Some(ByteRange {
        start: start?,
        len: len?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use super::*;

    fn encode(value: &Value) -> Vec<u8> {
        c2pa_cbor::to_vec(value).unwrap()
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries.into_iter().collect::<BTreeMap<_, _>>())
    }

    fn exclusion_value(start: i64, length: i64) -> Value {
        map(vec![
            (text("start"), Value::Integer(start)),
            (text("length"), Value::Integer(length)),
        ])
    }

    #[test]
    fn decodes_a_full_data_hash() {
        let assertion = map(vec![
            (
                text("exclusions"),
                Value::Array(vec![exclusion_value(20, 45884)]),
            ),
            (text("name"), text("jumbf manifest")),
            (text("alg"), text("sha256")),
            (text("hash"), Value::Bytes(vec![0xab; 32])),
            (text("pad"), Value::Bytes(vec![0; 9])),
        ]);

        let decoded = decode(&encode(&assertion)).unwrap();

        assert_eq!(
            decoded.exclusions,
            [ByteRange {
                start: 20,
                len: 45884
            }]
        );
        assert_eq!(decoded.alg.as_deref(), Some("sha256"));
        assert_eq!(decoded.hash, vec![0xab; 32]);
        assert_eq!(decoded.name.as_deref(), Some("jumbf manifest"));
    }

    #[test]
    fn decodes_a_data_hash_with_no_exclusions() {
        let assertion = map(vec![(text("hash"), Value::Bytes(vec![1, 2, 3]))]);

        let decoded = decode(&encode(&assertion)).unwrap();
        assert!(decoded.exclusions.is_empty());
        assert_eq!(decoded.hash, vec![1, 2, 3]);
    }

    #[test]
    fn ignores_unknown_keys_inside_an_exclusion() {
        let exclusion = map(vec![
            (text("start"), Value::Integer(5)),
            (text("length"), Value::Integer(10)),
            (text("future"), text("ignored")),
        ]);

        let assertion = map(vec![
            (text("hash"), Value::Bytes(vec![1])),
            (text("exclusions"), Value::Array(vec![exclusion])),
        ]);

        assert_eq!(
            decode(&encode(&assertion)).unwrap().exclusions,
            [ByteRange { start: 5, len: 10 }]
        );
    }

    #[test]
    fn rejects_a_data_hash_without_a_hash() {
        let assertion = map(vec![(
            text("exclusions"),
            Value::Array(vec![exclusion_value(0, 1)]),
        )]);

        assert_eq!(decode(&encode(&assertion)), None);
    }

    #[test]
    fn rejects_malformed_shapes() {
        // Not CBOR at all.
        assert_eq!(decode(&[0xff, 0xff]), None);

        // Not a map.
        assert_eq!(decode(&encode(&Value::Array(vec![]))), None);

        // Wrongly typed fields.
        for assertion in [
            map(vec![
                (text("hash"), Value::Bytes(vec![1])),
                (text("exclusions"), text("not-an-array")),
            ]),
            map(vec![(text("hash"), text("not-bytes"))]),
            map(vec![
                (text("hash"), Value::Bytes(vec![1])),
                (text("alg"), Value::Integer(7)),
            ]),
        ] {
            assert_eq!(decode(&encode(&assertion)), None);
        }
    }

    #[test]
    fn rejects_exclusions_missing_a_field_or_holding_negatives() {
        for exclusions in [
            vec![map(vec![(text("start"), Value::Integer(0))])],
            vec![map(vec![(text("length"), Value::Integer(1))])],
            vec![exclusion_value(-1, 10)],
            vec![exclusion_value(10, -1)],
        ] {
            let assertion = map(vec![
                (text("hash"), Value::Bytes(vec![1])),
                (text("exclusions"), Value::Array(exclusions)),
            ]);

            assert_eq!(decode(&encode(&assertion)), None);
        }
    }
}
