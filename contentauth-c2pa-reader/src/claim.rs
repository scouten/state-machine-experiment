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

//! Decoding of the CBOR-encoded C2PA claim.
//!
//! The claim is walked field by field out of a [`c2pa_cbor::Value`] rather
//! than deserialized through serde derives, so the set of fields the core
//! understands stays explicit and unknown fields are ignored rather than
//! silently absorbed.
//!
//! Skeleton: this covers the C2PA v1 claim shape. Claim v2 (with its
//! `created_assertions` / `gathered_assertions` split) is not yet handled.

use c2pa_cbor::Value;

/// Reasons a claim box's CBOR could not be decoded.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// The bytes were not well-formed CBOR.
    #[error("claim is not well-formed CBOR")]
    MalformedCbor,

    /// The claim's top-level CBOR value was not a map.
    #[error("claim is not a CBOR map")]
    NotAMap,

    /// A field was present but had the wrong CBOR type.
    #[error("claim field `{field}` has an unexpected type")]
    UnexpectedType {
        /// Name of the offending field.
        field: &'static str,
    },
}

impl GeneratorInfo {
    /// Describes a claim generator by name and version.
    ///
    /// A constructor rather than a literal because this type is also an
    /// *input* to signing, and the C2PA specification has more fields for
    /// it than this crate reads — so it stays open to growth while
    /// remaining constructible.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            version: Some(version.into()),
        }
    }
}

/// A decoded C2PA claim.
///
/// Every field is optional: a claim that omits one is structurally valid
/// CBOR, and whether the omission is *legal* is a validation question
/// (roadmap step 4) rather than a decoding one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Claim {
    /// `dc:title` — human-readable title of the asset.
    pub title: Option<String>,

    /// `dc:format` — MIME type of the asset.
    pub format: Option<String>,

    /// `instanceID` — identifier for this specific instance of the asset.
    pub instance_id: Option<String>,

    /// `claim_generator` — legacy free-form generator string.
    pub claim_generator: Option<String>,

    /// `claim_generator_info` — structured generator descriptions.
    pub claim_generator_info: Vec<GeneratorInfo>,

    /// `signature` — JUMBF URI of this claim's signature box.
    pub signature: Option<String>,

    /// `alg` — hash algorithm used for this claim's hashed URIs.
    pub alg: Option<String>,

    /// `assertions` — hashed references to the assertions this claim
    /// covers.
    pub assertions: Vec<HashedUri>,
}

/// One entry of a claim's `claim_generator_info`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratorInfo {
    /// Name of the generating product.
    pub name: Option<String>,

    /// Version of the generating product.
    pub version: Option<String>,
}

/// A JUMBF URI paired with a cryptographic hash of what it points at.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct HashedUri {
    /// JUMBF URI of the referenced box.
    pub url: String,

    /// Hash of the referenced box's contents. Verifying this hash is a
    /// validation concern and is not performed during decoding.
    pub hash: Vec<u8>,

    /// Hash algorithm, when the reference overrides the claim's `alg`.
    pub alg: Option<String>,
}

/// Decodes a claim from the CBOR payload of a `c2pa.claim` box.
pub(crate) fn decode(cbor: &[u8]) -> Result<Claim, ClaimError> {
    // `from_slice` bounds allocation and rejects trailing bytes, which
    // suits a claim box payload: exactly one CBOR item, from an untrusted
    // source.
    let value: Value = c2pa_cbor::from_slice(cbor).map_err(|_| ClaimError::MalformedCbor)?;
    let map = value.as_map().ok_or(ClaimError::NotAMap)?;

    let mut claim = Claim::default();

    for (key, value) in map {
        let Some(key) = key.as_str() else {
            // Non-text keys are not part of the claim schema; ignore them
            // rather than failing the whole claim.
            continue;
        };

        match key {
            "dc:title" => claim.title = Some(text(value, "dc:title")?),
            "dc:format" => claim.format = Some(text(value, "dc:format")?),
            "instanceID" => claim.instance_id = Some(text(value, "instanceID")?),
            "claim_generator" => claim.claim_generator = Some(text(value, "claim_generator")?),
            "signature" => claim.signature = Some(text(value, "signature")?),
            "alg" => claim.alg = Some(text(value, "alg")?),

            "claim_generator_info" => {
                let entries = value.as_array().ok_or(ClaimError::UnexpectedType {
                    field: "claim_generator_info",
                })?;

                claim.claim_generator_info = entries
                    .iter()
                    .map(generator_info)
                    .collect::<Result<_, _>>()?;
            }

            "assertions" => {
                let entries = value.as_array().ok_or(ClaimError::UnexpectedType {
                    field: "assertions",
                })?;

                claim.assertions = entries.iter().map(hashed_uri).collect::<Result<_, _>>()?;
            }

            // Unknown fields are ignored: a newer writer may include fields
            // this core does not model.
            _ => {}
        }
    }

    Ok(claim)
}

/// Reads a CBOR text value, naming the field if it is the wrong type.
fn text(value: &Value, field: &'static str) -> Result<String, ClaimError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or(ClaimError::UnexpectedType { field })
}

/// Decodes one `claim_generator_info` entry.
fn generator_info(value: &Value) -> Result<GeneratorInfo, ClaimError> {
    let map = value.as_map().ok_or(ClaimError::UnexpectedType {
        field: "claim_generator_info",
    })?;

    let mut info = GeneratorInfo::default();

    for (key, value) in map {
        match key.as_str() {
            Some("name") => info.name = Some(text(value, "claim_generator_info.name")?),
            Some("version") => info.version = Some(text(value, "claim_generator_info.version")?),
            _ => {}
        }
    }

    Ok(info)
}

/// Decodes one hashed-URI reference.
fn hashed_uri(value: &Value) -> Result<HashedUri, ClaimError> {
    let map = value.as_map().ok_or(ClaimError::UnexpectedType {
        field: "assertions",
    })?;

    let mut uri = HashedUri::default();
    let mut saw_url = false;

    for (key, value) in map {
        match key.as_str() {
            Some("url") => {
                uri.url = text(value, "assertions.url")?;
                saw_url = true;
            }

            Some("hash") => {
                uri.hash =
                    value
                        .as_bytes()
                        .map(<[u8]>::to_vec)
                        .ok_or(ClaimError::UnexpectedType {
                            field: "assertions.hash",
                        })?;
            }

            Some("alg") => uri.alg = Some(text(value, "assertions.alg")?),

            _ => {}
        }
    }

    if !saw_url {
        return Err(ClaimError::UnexpectedType {
            field: "assertions.url",
        });
    }

    Ok(uri)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Encodes a `c2pa_cbor::Value` to bytes, for building test claims.
    fn encode(value: &Value) -> Vec<u8> {
        c2pa_cbor::to_vec(value).unwrap()
    }

    /// Builds a CBOR map from (key, value) pairs.
    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries.into_iter().collect())
    }

    fn text_value(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    #[test]
    fn decodes_a_full_v1_claim() {
        let claim = map(vec![
            (text_value("dc:title"), text_value("C.jpg")),
            (text_value("dc:format"), text_value("image/jpeg")),
            (text_value("instanceID"), text_value("xmp:iid:1234")),
            (text_value("claim_generator"), text_value("test/1.0")),
            (
                text_value("claim_generator_info"),
                Value::Array(vec![map(vec![
                    (text_value("name"), text_value("test")),
                    (text_value("version"), text_value("1.0")),
                ])]),
            ),
            (
                text_value("signature"),
                text_value("self#jumbf=c2pa.signature"),
            ),
            (text_value("alg"), text_value("sha256")),
            (
                text_value("assertions"),
                Value::Array(vec![map(vec![
                    (
                        text_value("url"),
                        text_value("self#jumbf=c2pa.assertions/c2pa.actions"),
                    ),
                    (text_value("hash"), Value::Bytes(vec![0xab; 32])),
                ])]),
            ),
            // An unknown field a newer writer might emit.
            (text_value("future_field"), Value::Integer(42)),
        ]);

        let decoded = decode(&encode(&claim)).unwrap();

        assert_eq!(decoded.title.as_deref(), Some("C.jpg"));
        assert_eq!(decoded.format.as_deref(), Some("image/jpeg"));
        assert_eq!(decoded.instance_id.as_deref(), Some("xmp:iid:1234"));
        assert_eq!(decoded.claim_generator.as_deref(), Some("test/1.0"));
        assert_eq!(decoded.alg.as_deref(), Some("sha256"));
        assert_eq!(
            decoded.signature.as_deref(),
            Some("self#jumbf=c2pa.signature")
        );

        assert_eq!(decoded.claim_generator_info.len(), 1);
        assert_eq!(
            decoded.claim_generator_info[0].name.as_deref(),
            Some("test")
        );
        assert_eq!(
            decoded.claim_generator_info[0].version.as_deref(),
            Some("1.0")
        );

        assert_eq!(decoded.assertions.len(), 1);
        assert_eq!(
            decoded.assertions[0].url,
            "self#jumbf=c2pa.assertions/c2pa.actions"
        );
        assert_eq!(decoded.assertions[0].hash, vec![0xab; 32]);
        assert_eq!(decoded.assertions[0].alg, None);
    }

    #[test]
    fn decodes_a_minimal_claim() {
        let decoded = decode(&encode(&map(vec![]))).unwrap();
        assert_eq!(decoded, Claim::default());
    }

    #[test]
    fn ignores_non_text_keys() {
        let claim = map(vec![
            (Value::Integer(1), text_value("ignored")),
            (text_value("dc:title"), text_value("kept")),
        ]);

        assert_eq!(
            decode(&encode(&claim)).unwrap().title.as_deref(),
            Some("kept")
        );
    }

    #[test]
    fn reads_per_reference_hash_algorithm() {
        let claim = map(vec![(
            text_value("assertions"),
            Value::Array(vec![map(vec![
                (text_value("url"), text_value("self#jumbf=x")),
                (text_value("hash"), Value::Bytes(vec![1, 2, 3])),
                (text_value("alg"), text_value("sha512")),
                // A field this core does not model.
                (text_value("unknown"), Value::Integer(7)),
            ])]),
        )]);

        let decoded = decode(&encode(&claim)).unwrap();
        assert_eq!(decoded.assertions[0].alg.as_deref(), Some("sha512"));
        assert_eq!(decoded.assertions[0].hash, vec![1, 2, 3]);
    }

    #[test]
    fn ignores_unknown_generator_info_fields() {
        let claim = map(vec![(
            text_value("claim_generator_info"),
            Value::Array(vec![map(vec![
                (text_value("name"), text_value("tool")),
                (text_value("icon"), text_value("ignored")),
            ])]),
        )]);

        let decoded = decode(&encode(&claim)).unwrap();
        assert_eq!(
            decoded.claim_generator_info[0].name.as_deref(),
            Some("tool")
        );
        assert_eq!(decoded.claim_generator_info[0].version, None);
    }

    #[test]
    fn rejects_malformed_cbor() {
        assert_eq!(decode(&[0xff, 0xff]), Err(ClaimError::MalformedCbor));
    }

    #[test]
    fn rejects_non_map_claim() {
        assert_eq!(
            decode(&encode(&Value::Array(vec![]))),
            Err(ClaimError::NotAMap)
        );
    }

    #[test]
    fn rejects_wrong_field_types() {
        let cases: Vec<(Value, &'static str)> = vec![
            (
                map(vec![(text_value("dc:title"), Value::Integer(1))]),
                "dc:title",
            ),
            (
                map(vec![(text_value("assertions"), text_value("not-an-array"))]),
                "assertions",
            ),
            (
                map(vec![(
                    text_value("claim_generator_info"),
                    text_value("not-an-array"),
                )]),
                "claim_generator_info",
            ),
            (
                map(vec![(
                    text_value("assertions"),
                    Value::Array(vec![map(vec![
                        (text_value("url"), text_value("u")),
                        (text_value("hash"), text_value("not-bytes")),
                    ])]),
                )]),
                "assertions.hash",
            ),
        ];

        for (value, field) in cases {
            assert_eq!(
                decode(&encode(&value)),
                Err(ClaimError::UnexpectedType { field }),
                "expected {field} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_hashed_uri_without_url() {
        let claim = map(vec![(
            text_value("assertions"),
            Value::Array(vec![map(vec![(
                text_value("hash"),
                Value::Bytes(vec![1, 2, 3]),
            )])]),
        )]);

        assert_eq!(
            decode(&encode(&claim)),
            Err(ClaimError::UnexpectedType {
                field: "assertions.url"
            })
        );
    }
}
