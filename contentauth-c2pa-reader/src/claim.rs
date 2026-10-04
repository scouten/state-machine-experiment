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
//! Both the C2PA v1 claim shape (a flat `assertions` list) and the v2 shape
//! (`created_assertions` and `gathered_assertions`) are decoded into the
//! same [`Claim`] type: a claim populates whichever of the three fields its
//! version uses, and [`Claim::assertion_references`] iterates all of them
//! together so callers do not need to know which version they read.
//!
//! The two versions also differ in the shape of `claim_generator_info`: v1
//! carries an array of generator maps, v2 a single `generator-info-map`
//! (with `specVersion` and `icon` fields v1 lacks). Either decodes into
//! [`Claim::claim_generator_info`], a one-entry list for v2. v2's
//! `redacted_assertions` decode into [`Claim::redacted_assertions`].
//!
//! Decoding is deliberately lenient about *absent* fields — whether a v2
//! claim is missing one the specification requires is a validation
//! question, answered by [`Claim::missing_required_fields`].

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
            spec_version: None,
            icon: None,
        }
    }
}

/// Which C2PA claim version a [`Claim`] was decoded from.
///
/// Determined by the claim box's own JUMBF label (`c2pa.claim` for v1,
/// `c2pa.claim.v2` for v2) — a structural fact about which box the claim
/// came from, not something guessed from which of
/// [`Claim::assertions`]/[`Claim::created_assertions`] happen to be
/// populated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClaimVersion {
    /// A v1 claim: assertions in a flat [`Claim::assertions`] list.
    V1,

    /// A v2 claim: assertions split into [`Claim::created_assertions`]
    /// and [`Claim::gathered_assertions`].
    #[default]
    V2,
}

impl ClaimVersion {
    /// The number this version is written as in the specification and in
    /// c2pa-rs's JSON (`claim_version`): `1` or `2`.
    ///
    /// The one place a version becomes a number, so that code outside this
    /// crate (where the enum is `#[non_exhaustive]`) never has to pick a
    /// fallback for a version it does not know.
    pub const fn number(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

/// A decoded C2PA claim.
///
/// Every field but [`Self::version`] is optional: a claim that omits one
/// is structurally valid CBOR, and whether the omission is *legal* is a
/// validation question (roadmap step 4) rather than a decoding one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Claim {
    /// Which claim version this claim was decoded from.
    pub version: ClaimVersion,

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
    ///
    /// Populated for a v1 claim; empty for a v2 claim, which uses
    /// [`Self::created_assertions`] and [`Self::gathered_assertions`]
    /// instead. Use [`Self::assertion_references`] to iterate assertion
    /// references without checking the claim's version.
    pub assertions: Vec<HashedUri>,

    /// `created_assertions` — hashed references to assertions created by
    /// this claim's generator, in a v2 claim.
    ///
    /// Empty for a v1 claim, which uses [`Self::assertions`] instead.
    pub created_assertions: Vec<HashedUri>,

    /// `gathered_assertions` — hashed references to assertions gathered
    /// from a prior manifest, in a v2 claim.
    ///
    /// Empty for a v1 claim, which uses [`Self::assertions`] instead.
    pub gathered_assertions: Vec<HashedUri>,

    /// `redacted_assertions` — JUMBF URIs of assertions in *ingredient*
    /// manifests that this claim redacts, in a v2 claim.
    ///
    /// Plain URI references, not hashed ones: a redacted assertion's
    /// content is gone, so there is nothing left to hash. Empty for a v1
    /// claim and for a v2 claim that redacts nothing.
    pub redacted_assertions: Vec<String>,

    /// Which of the fields a v2 claim must carry appeared in the CBOR, so
    /// that [`Self::missing_required_fields`] can tell "absent" from
    /// "present but empty".
    presence: Presence,
}

/// Records which fields appeared in a claim's CBOR at all.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Presence {
    instance_id: bool,
    signature: bool,
    created_assertions: bool,
    claim_generator_info: bool,
}

impl Claim {
    /// For a v2 claim, names each field the C2PA specification requires
    /// of a claim that is absent: `instanceID`, `signature`,
    /// `created_assertions`, `claim_generator_info`, and — when the latter
    /// is present — its `name`.
    ///
    /// Always empty for a v1 claim, whose field requirements this reader
    /// does not enforce.
    pub fn missing_required_fields(&self) -> Vec<&'static str> {
        if self.version != ClaimVersion::V2 {
            return Vec::new();
        }

        let mut missing = Vec::new();
        if !self.presence.instance_id {
            missing.push("instanceID");
        }
        if !self.presence.signature {
            missing.push("signature");
        }
        if !self.presence.created_assertions {
            missing.push("created_assertions");
        }
        if !self.presence.claim_generator_info {
            missing.push("claim_generator_info");
        } else if self.claim_generator_info.iter().all(|g| g.name.is_none()) {
            missing.push("claim_generator_info.name");
        }
        missing
    }
}

impl Claim {
    /// Iterates every assertion reference this claim covers, regardless of
    /// whether it is a v1 claim (`assertions`) or a v2 claim
    /// (`created_assertions` and `gathered_assertions`).
    pub fn assertion_references(&self) -> impl Iterator<Item = &HashedUri> {
        self.assertions
            .iter()
            .chain(self.created_assertions.iter())
            .chain(self.gathered_assertions.iter())
    }
}

/// One entry of a claim's `claim_generator_info`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratorInfo {
    /// Name of the generating product.
    pub name: Option<String>,

    /// Version of the generating product.
    pub version: Option<String>,

    /// `specVersion` — SemVer of the C2PA specification the generator
    /// used as its normative reference (for example `"2.4.0"`). A v2
    /// field; purely informational.
    pub spec_version: Option<String>,

    /// `icon` — hashed reference to a `c2pa.icon` embedded-data assertion
    /// graphically representing the generator. A v2 field.
    pub icon: Option<HashedUri>,
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

/// Decodes a claim from the CBOR payload of a claim box, tagging the
/// result with the claim version its caller determined from the box's
/// JUMBF label.
pub(crate) fn decode(cbor: &[u8], version: ClaimVersion) -> Result<Claim, ClaimError> {
    // `from_slice` bounds allocation and rejects trailing bytes, which
    // suits a claim box payload: exactly one CBOR item, from an untrusted
    // source.
    let value: Value = c2pa_cbor::from_slice(cbor).map_err(|_| ClaimError::MalformedCbor)?;
    let map = value.as_map().ok_or(ClaimError::NotAMap)?;

    let mut claim = Claim {
        version,
        ..Claim::default()
    };

    for (key, value) in map {
        let Some(key) = key.as_str() else {
            // Non-text keys are not part of the claim schema; ignore them
            // rather than failing the whole claim.
            continue;
        };

        match key {
            "dc:title" => claim.title = Some(text(value, "dc:title")?),
            "dc:format" => claim.format = Some(text(value, "dc:format")?),
            "instanceID" => {
                claim.instance_id = Some(text(value, "instanceID")?);
                claim.presence.instance_id = true;
            }
            "claim_generator" => claim.claim_generator = Some(text(value, "claim_generator")?),
            "signature" => {
                claim.signature = Some(text(value, "signature")?);
                claim.presence.signature = true;
            }
            "alg" => claim.alg = Some(text(value, "alg")?),

            // A v1 claim carries an array of generator maps, a v2 claim a
            // single map; each shape is accepted whichever version the
            // box's label announced, since the shape is what is decoded.
            "claim_generator_info" => {
                claim.claim_generator_info = match value {
                    Value::Array(entries) => entries
                        .iter()
                        .map(generator_info)
                        .collect::<Result<_, _>>()?,
                    _ => vec![generator_info(value)?],
                };
                claim.presence.claim_generator_info = true;
            }

            "assertions" => claim.assertions = hashed_uri_array(value, "assertions")?,

            "created_assertions" => {
                claim.created_assertions = hashed_uri_array(value, "created_assertions")?;
                claim.presence.created_assertions = true;
            }

            "redacted_assertions" => {
                let entries = value.as_array().ok_or(ClaimError::UnexpectedType {
                    field: "redacted_assertions",
                })?;
                claim.redacted_assertions = entries
                    .iter()
                    .map(|entry| text(entry, "redacted_assertions"))
                    .collect::<Result<_, _>>()?;
            }

            "gathered_assertions" => {
                claim.gathered_assertions = hashed_uri_array(value, "gathered_assertions")?
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
            Some("specVersion") => {
                info.spec_version = Some(text(value, "claim_generator_info.specVersion")?)
            }
            Some("icon") => info.icon = Some(hashed_uri(value)?),
            _ => {}
        }
    }

    Ok(info)
}

/// Decodes a CBOR array of hashed-URI references, naming the field if it is
/// not itself an array.
///
/// Errors within an individual entry are still reported under the generic
/// `assertions.*` names `hashed_uri` uses, regardless of which of the
/// three top-level array fields it was decoded from: they identify the
/// malformed hashed-URI shape, not which list it lives in.
fn hashed_uri_array(value: &Value, field: &'static str) -> Result<Vec<HashedUri>, ClaimError> {
    let entries = value
        .as_array()
        .ok_or(ClaimError::UnexpectedType { field })?;
    entries.iter().map(hashed_uri).collect()
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
    fn generator_info_new_sets_both_fields() {
        let info = GeneratorInfo::new("test", "1.0");

        assert_eq!(info.name.as_deref(), Some("test"));
        assert_eq!(info.version.as_deref(), Some("1.0"));
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

        let decoded = decode(&encode(&claim), ClaimVersion::V1).unwrap();

        assert_eq!(decoded.version, ClaimVersion::V1);
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

        assert!(decoded.created_assertions.is_empty());
        assert!(decoded.gathered_assertions.is_empty());
        assert_eq!(decoded.assertion_references().count(), 1);
    }

    #[test]
    fn decodes_a_v2_claim_with_created_and_gathered_assertions() {
        let claim = map(vec![
            (text_value("instanceID"), text_value("xmp:iid:1234")),
            (
                text_value("claim_generator_info"),
                Value::Array(vec![map(vec![(text_value("name"), text_value("test"))])]),
            ),
            (
                text_value("created_assertions"),
                Value::Array(vec![map(vec![
                    (
                        text_value("url"),
                        text_value("self#jumbf=c2pa.assertions/c2pa.actions"),
                    ),
                    (text_value("hash"), Value::Bytes(vec![0xab; 32])),
                ])]),
            ),
            (
                text_value("gathered_assertions"),
                Value::Array(vec![map(vec![
                    (
                        text_value("url"),
                        text_value("self#jumbf=c2pa.assertions/c2pa.hash.data"),
                    ),
                    (text_value("hash"), Value::Bytes(vec![0xcd; 32])),
                ])]),
            ),
        ]);

        let decoded = decode(&encode(&claim), ClaimVersion::V2).unwrap();

        assert_eq!(decoded.version, ClaimVersion::V2);
        assert!(decoded.assertions.is_empty());

        assert_eq!(decoded.created_assertions.len(), 1);
        assert_eq!(
            decoded.created_assertions[0].url,
            "self#jumbf=c2pa.assertions/c2pa.actions"
        );
        assert_eq!(decoded.created_assertions[0].hash, vec![0xab; 32]);

        assert_eq!(decoded.gathered_assertions.len(), 1);
        assert_eq!(
            decoded.gathered_assertions[0].url,
            "self#jumbf=c2pa.assertions/c2pa.hash.data"
        );
        assert_eq!(decoded.gathered_assertions[0].hash, vec![0xcd; 32]);

        let references: Vec<_> = decoded.assertion_references().map(|r| &r.url).collect();
        assert_eq!(
            references,
            vec![
                "self#jumbf=c2pa.assertions/c2pa.actions",
                "self#jumbf=c2pa.assertions/c2pa.hash.data",
            ]
        );
    }

    #[test]
    fn rejects_wrong_field_type_for_created_assertions() {
        assert_eq!(
            decode(
                &encode(&map(vec![(
                    text_value("created_assertions"),
                    text_value("not-an-array"),
                )])),
                ClaimVersion::V2
            ),
            Err(ClaimError::UnexpectedType {
                field: "created_assertions"
            })
        );
    }

    #[test]
    fn rejects_wrong_field_type_for_gathered_assertions() {
        assert_eq!(
            decode(
                &encode(&map(vec![(
                    text_value("gathered_assertions"),
                    text_value("not-an-array"),
                )])),
                ClaimVersion::V2
            ),
            Err(ClaimError::UnexpectedType {
                field: "gathered_assertions"
            })
        );
    }

    #[test]
    fn decodes_a_minimal_claim() {
        let decoded = decode(&encode(&map(vec![])), ClaimVersion::V2).unwrap();
        assert_eq!(decoded, Claim::default());
    }

    #[test]
    fn ignores_non_text_keys() {
        let claim = map(vec![
            (Value::Integer(1), text_value("ignored")),
            (text_value("dc:title"), text_value("kept")),
        ]);

        assert_eq!(
            decode(&encode(&claim), ClaimVersion::V1)
                .unwrap()
                .title
                .as_deref(),
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

        let decoded = decode(&encode(&claim), ClaimVersion::V1).unwrap();
        assert_eq!(decoded.assertions[0].alg.as_deref(), Some("sha512"));
        assert_eq!(decoded.assertions[0].hash, vec![1, 2, 3]);
    }

    #[test]
    fn ignores_unknown_generator_info_fields() {
        let claim = map(vec![(
            text_value("claim_generator_info"),
            Value::Array(vec![map(vec![
                (text_value("name"), text_value("tool")),
                (text_value("operating_system"), text_value("ignored")),
            ])]),
        )]);

        let decoded = decode(&encode(&claim), ClaimVersion::V1).unwrap();
        assert_eq!(
            decoded.claim_generator_info[0].name.as_deref(),
            Some("tool")
        );
        assert_eq!(decoded.claim_generator_info[0].version, None);
    }

    /// A v2 claim carrying every required field, as a CBOR map.
    fn v2_claim_fields() -> Vec<(Value, Value)> {
        vec![
            (text_value("instanceID"), text_value("xmp:iid:1")),
            (
                text_value("signature"),
                text_value("self#jumbf=c2pa.signature"),
            ),
            (
                text_value("claim_generator_info"),
                map(vec![(text_value("name"), text_value("tool"))]),
            ),
            (text_value("created_assertions"), Value::Array(vec![])),
        ]
    }

    #[test]
    fn decodes_a_v2_generator_info_map_with_spec_version_and_icon() {
        let claim = map(vec![(
            text_value("claim_generator_info"),
            map(vec![
                (text_value("name"), text_value("tool")),
                (text_value("version"), text_value("2.0")),
                (text_value("specVersion"), text_value("2.4.0")),
                (
                    text_value("icon"),
                    map(vec![
                        (text_value("url"), text_value("self#jumbf=c2pa.icon")),
                        (text_value("hash"), Value::Bytes(vec![9; 32])),
                    ]),
                ),
            ]),
        )]);

        let decoded = decode(&encode(&claim), ClaimVersion::V2).unwrap();

        assert_eq!(decoded.claim_generator_info.len(), 1);
        let info = &decoded.claim_generator_info[0];
        assert_eq!(info.name.as_deref(), Some("tool"));
        assert_eq!(info.version.as_deref(), Some("2.0"));
        assert_eq!(info.spec_version.as_deref(), Some("2.4.0"));
        let icon = info.icon.as_ref().unwrap();
        assert_eq!(icon.url, "self#jumbf=c2pa.icon");
        assert_eq!(icon.hash, vec![9; 32]);
    }

    #[test]
    fn rejects_a_generator_info_that_is_neither_map_nor_array() {
        let claim = map(vec![(
            text_value("claim_generator_info"),
            text_value("tool/1.0"),
        )]);

        assert_eq!(
            decode(&encode(&claim), ClaimVersion::V2),
            Err(ClaimError::UnexpectedType {
                field: "claim_generator_info"
            })
        );
    }

    #[test]
    fn rejects_a_malformed_generator_icon() {
        let claim = map(vec![(
            text_value("claim_generator_info"),
            map(vec![
                (text_value("name"), text_value("tool")),
                (text_value("icon"), text_value("not-a-hashed-uri")),
            ]),
        )]);

        assert!(decode(&encode(&claim), ClaimVersion::V2).is_err());
    }

    #[test]
    fn decodes_redacted_assertions() {
        let mut fields = v2_claim_fields();
        fields.push((
            text_value("redacted_assertions"),
            Value::Array(vec![
                text_value("self#jumbf=/c2pa/urn:uuid:a/c2pa.assertions/c2pa.thumbnail"),
                text_value("self#jumbf=/c2pa/urn:uuid:b/c2pa.assertions/c2pa.actions"),
            ]),
        ));

        let decoded = decode(&encode(&map(fields)), ClaimVersion::V2).unwrap();

        assert_eq!(
            decoded.redacted_assertions,
            vec![
                "self#jumbf=/c2pa/urn:uuid:a/c2pa.assertions/c2pa.thumbnail",
                "self#jumbf=/c2pa/urn:uuid:b/c2pa.assertions/c2pa.actions",
            ]
        );
    }

    #[test]
    fn rejects_redacted_assertions_of_the_wrong_shape() {
        let not_an_array = map(vec![(text_value("redacted_assertions"), text_value("x"))]);
        assert_eq!(
            decode(&encode(&not_an_array), ClaimVersion::V2),
            Err(ClaimError::UnexpectedType {
                field: "redacted_assertions"
            })
        );

        let not_text = map(vec![(
            text_value("redacted_assertions"),
            Value::Array(vec![Value::Integer(1)]),
        )]);
        assert_eq!(
            decode(&encode(&not_text), ClaimVersion::V2),
            Err(ClaimError::UnexpectedType {
                field: "redacted_assertions"
            })
        );
    }

    #[test]
    fn a_complete_v2_claim_is_missing_nothing() {
        let decoded = decode(&encode(&map(v2_claim_fields())), ClaimVersion::V2).unwrap();
        assert!(decoded.missing_required_fields().is_empty());
    }

    #[test]
    fn each_absent_required_v2_field_is_named() {
        for field in [
            "instanceID",
            "signature",
            "created_assertions",
            "claim_generator_info",
        ] {
            let fields = v2_claim_fields()
                .into_iter()
                .filter(|(key, _)| key.as_str() != Some(field))
                .collect();

            let decoded = decode(&encode(&map(fields)), ClaimVersion::V2).unwrap();
            assert_eq!(decoded.missing_required_fields(), vec![field]);
        }
    }

    #[test]
    fn a_v2_generator_info_without_a_name_is_missing_it() {
        let mut fields = v2_claim_fields();
        fields.retain(|(key, _)| key.as_str() != Some("claim_generator_info"));
        fields.push((
            text_value("claim_generator_info"),
            map(vec![(text_value("version"), text_value("1"))]),
        ));

        let decoded = decode(&encode(&map(fields)), ClaimVersion::V2).unwrap();
        assert_eq!(
            decoded.missing_required_fields(),
            vec!["claim_generator_info.name"]
        );
    }

    #[test]
    fn a_v1_claim_is_never_missing_required_fields() {
        let decoded = decode(&encode(&map(vec![])), ClaimVersion::V1).unwrap();
        assert!(decoded.missing_required_fields().is_empty());
    }

    #[test]
    fn claim_versions_are_numbered_as_the_specification_names_them() {
        assert_eq!(ClaimVersion::V1.number(), 1);
        assert_eq!(ClaimVersion::V2.number(), 2);
    }

    #[test]
    fn rejects_malformed_cbor() {
        assert_eq!(
            decode(&[0xff, 0xff], ClaimVersion::V1),
            Err(ClaimError::MalformedCbor)
        );
    }

    #[test]
    fn rejects_non_map_claim() {
        assert_eq!(
            decode(&encode(&Value::Array(vec![])), ClaimVersion::V1),
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
                decode(&encode(&value), ClaimVersion::V1),
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
            decode(&encode(&claim), ClaimVersion::V1),
            Err(ClaimError::UnexpectedType {
                field: "assertions.url"
            })
        );
    }
}
