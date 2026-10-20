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

//! The objects [`crate::Reader::manifest_store`] and
//! [`crate::Reader::active_manifest`] return, and the JSON
//! [`crate::Reader::json`] produces.
//!
//! c2pa-wasm returns these as plain JavaScript objects — c2pa-rs's
//! `Reader` and `Manifest` serialized through `serde_wasm_bindgen` — whose
//! shape `@contentauth/c2pa-types` describes as `ManifestStore` and
//! `Manifest`. This projection reports decoded CBOR assertion payloads
//! and created relationships, alongside the validation summary. Resource-free
//! v1/v2/v3 ingredients have metadata and unknown-provenance deltas. Linked
//! manifests, recorded validation histories and unsupported resource targets
//! fail serialization rather than silently losing data. Embedded same-owner
//! ingredient thumbnails/data share the generator-icon resource resolver.
//! Claim thumbnails have embedded resource references; binary assertion
//! payloads are available separately through [`crate::Reader::resource_to_bytes`].
//!
//! Every type here owns its data and implements [`serde::Serialize`], so
//! a binding can hand it straight to `serde_wasm_bindgen` (as the `web`
//! feature's `WasmReader` does) or `serde_json` (as [`crate::Reader::json`]
//! does).

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use contentauth_c2pa_reader::{ClaimVersion, ReadReport};
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize, Serializer,
};

/// The asset's manifest store: what c2pa-wasm's `manifestStore()` returns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManifestStore {
    /// Label of the active manifest — the last one in the store — if the
    /// store contains any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_manifest: Option<String>,

    /// Every manifest in the store, keyed by label.
    pub manifests: BTreeMap<String, Manifest>,

    /// Overall validation outcome.
    pub validation_state: ValidationState,

    /// Validation failures across the store, omitted when there are none.
    /// Success and informational observations live in `validation_results`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub validation_status: Vec<ValidationStatus>,

    /// Validation results grouped by the active manifest and outcome.
    pub validation_results: ValidationResults,
}

/// Resolves retained embedded bytes by an exact absolute self JUMBF URI.
///
/// Shared by browser and Node hosts. Unknown or ambiguous identifiers fail;
/// this neither fetches external resources nor establishes trust in the bytes.
pub fn resource_bytes<'a>(report: &'a ReadReport, uri: &str) -> Result<&'a [u8], crate::Error> {
    let mut matches = report.manifests.iter().flat_map(|manifest| {
        manifest.resources.iter().filter(move |resource| {
            uri == format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
                manifest.label, resource.label
            )
        })
    });
    let resource = matches
        .next()
        .ok_or_else(|| crate::C2paError::ResourceNotFound(uri.to_string()))?;
    if matches.next().is_some() {
        return Err(crate::C2paError::ResourceNotFound(uri.to_string()).into());
    }
    Ok(&resource.bytes)
}

/// Serializes a [`ClaimVersion`] as the number c2pa-js reports
/// (`claim_version: 2`).
fn serialize_claim_version<S: serde::Serializer>(
    version: &ClaimVersion,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u8(version.number())
}

/// One entry of a manifest's `claim_generator_info`.
///
/// Embedded assertion icons resolve within their owning manifest. Unsupported,
/// missing or ambiguous icon targets fail serialization explicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClaimGeneratorInfo {
    /// Name of the generating product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Version of the generating product.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The C2PA specification version the generator followed (v2 only).
    #[serde(rename = "specVersion", skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<ResourceProjection>,

    /// Product-specific fields retained from the generator-info map.
    #[serde(flatten, serialize_with = "serialize_extensions")]
    pub extensions: BTreeMap<String, c2pa_cbor::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceProjection(Result<ResourceRef, String>);

impl Serialize for ResourceProjection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .as_ref()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

fn generator_icon(
    manifest: &contentauth_c2pa_reader::Manifest,
    reference: &contentauth_c2pa_reader::HashedUri,
) -> ResourceProjection {
    ResourceProjection(embedded_resource(
        manifest,
        &reference.url,
        "generator icon",
    ))
}

fn embedded_resource(
    manifest: &contentauth_c2pa_reader::Manifest,
    url: &str,
    kind: &str,
) -> Result<ResourceRef, String> {
    let prefix = format!("self#jumbf=/c2pa/{}/c2pa.assertions/", manifest.label);
    let label = url
        .strip_prefix("self#jumbf=c2pa.assertions/")
        .or_else(|| url.strip_prefix(&prefix));
    let Some(label) = label.filter(|label| !label.is_empty() && !label.contains('/')) else {
        return Err(format!(
            "{kind} {url:?}: only same-manifest embedded assertion references are supported"
        ));
    };
    let mut targets = manifest
        .resources
        .iter()
        .filter(|resource| resource.label == label);
    match (targets.next(), targets.next()) {
        (Some(resource), None) => Ok(ResourceRef {
            format: resource.format.clone(),
            identifier: format!("{prefix}{label}"),
        }),
        _ => Err(format!(
            "{kind} {url:?}: missing or ambiguous embedded resource"
        )),
    }
}

fn serialize_extensions<S: Serializer>(
    values: &BTreeMap<String, c2pa_cbor::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(values.len()))?;
    for (key, value) in values {
        map.serialize_entry(key, &JsonCbor(value))?;
    }
    map.end()
}

/// One manifest: what c2pa-wasm's `activeManifest()` returns, and the
/// values of [`ManifestStore::manifests`].
///
/// Carries the fields [`contentauth_c2pa_reader`] can populate today; see
/// the module docs for what `@contentauth/c2pa-types`' `Manifest` has that
/// this does not yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Manifest {
    /// The manifest's label, as referenced in the store.
    pub label: String,

    /// A user-agent-formatted string identifying the software that
    /// produced the claim, if the claim carries the legacy free-form
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator: Option<String>,

    /// Structured descriptions of the software that produced the claim:
    /// a v1 claim's `claim_generator_info` array, or a v2 claim's single
    /// `generator-info-map` as a one-entry list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// The version of the claim this manifest carries: `1` for a
    /// `c2pa.claim`, `2` for a `c2pa.claim.v2`.
    #[serde(serialize_with = "serialize_claim_version")]
    pub claim_version: ClaimVersion,

    /// A user-displayable title for the asset, if the claim carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// The asset's MIME type, if the claim carries one — a v1 claim
    /// only; the v2 claim has no `dc:format` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// The asset's instance identifier, or an empty string if the claim
    /// carries none — c2pa-rs's own `Manifest` has no way to say "absent"
    /// here either.
    pub instance_id: String,

    /// Public assertions in store order, excluding known internal
    /// hard bindings and embedded resources.
    pub assertions: Vec<ManifestAssertion>,

    /// Resource-free ingredient metadata in assertion-store order.
    ///
    /// Includes assertion review ratings, creation time and custom metadata.
    /// Linked manifests, resources, structured metadata references and recorded
    /// validation results are not projected and fail serialization explicitly.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ingredients: Vec<Ingredient>,

    /// The claim thumbnail's embedded resource reference, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<ResourceRef>,

    /// Metadata from the cryptographically verified claim signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_info: Option<SignatureInfo>,
}

/// Legacy-shaped signer metadata; validation results determine trust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignatureInfo {
    /// COSE signing algorithm in c2pa-rs report spelling.
    pub alg: String,
    /// Organization in the signer certificate's subject, not its issuer DN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Subject common name, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Certificate serial number, in decimal.
    pub cert_serial_number: String,
    /// Authenticated timestamp time, not necessarily trusted time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

impl SignatureInfo {
    fn from_inner(info: &contentauth_c2pa_reader::SignatureInfo) -> Self {
        Self {
            alg: format!("{:?}", info.alg),
            issuer: info.organization.clone(),
            common_name: info.common_name.clone(),
            cert_serial_number: decimal_serial(&info.serial_number),
            time: info.time.clone(),
        }
    }

    fn identity_data(&self) -> c2pa_cbor::Value {
        use c2pa_cbor::Value;
        let mut fields = BTreeMap::from([
            (Value::Text("alg".into()), Value::Text(self.alg.clone())),
            (
                Value::Text("cert_serial_number".into()),
                Value::Text(self.cert_serial_number.clone()),
            ),
            // The pinned legacy identity report uses true for a verified
            // credential even when it performs no OCSP check. It is not
            // an affirmative revocation result; consult validation statuses.
            (Value::Text("revocation_status".into()), Value::Bool(true)),
        ]);
        for (key, value) in [
            ("issuer", &self.issuer),
            ("common_name", &self.common_name),
            ("time", &self.time),
        ] {
            if let Some(value) = value {
                fields.insert(Value::Text(key.into()), Value::Text(value.clone()));
            }
        }
        Value::Map(fields)
    }
}

fn decimal_serial(bytes: &[u8]) -> String {
    let mut digits = vec![0u16];
    for byte in bytes {
        let mut carry = u16::from(*byte);
        for digit in &mut digits {
            let value = *digit * 256 + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        while carry != 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit as u8))
        .collect()
}

/// A reference to an embedded binary resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceRef {
    /// Media type declared by the resource.
    pub format: String,
    /// Absolute self JUMBF URI identifying the assertion.
    pub identifier: String,
}

/// A legacy ingredient view over a decoded signed assertion.
///
/// Serialization translates the versioned CBOR vocabulary to the public
/// ingredient vocabulary. Same-owner embedded thumbnails and data reuse the
/// resource resolver. Unsupported histories/resource targets and malformed
/// metadata produce serialization errors, never an apparently complete view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ingredient {
    label: String,
    version: String,
    data: Option<c2pa_cbor::Value>,
    thumbnail: Option<ResourceProjection>,
    data_resource: Option<ResourceProjection>,
}

fn ingredient_thumbnail(
    manifest: &contentauth_c2pa_reader::Manifest,
    data: Option<&c2pa_cbor::Value>,
) -> Option<ResourceProjection> {
    ingredient_resource(manifest, data, "thumbnail")
}

fn ingredient_resource(
    manifest: &contentauth_c2pa_reader::Manifest,
    data: Option<&c2pa_cbor::Value>,
    field: &str,
) -> Option<ResourceProjection> {
    use c2pa_cbor::Value;

    let resource = data?
        .as_map()?
        .get(&Value::Text(field.into()))
        .filter(|value| **value != Value::Null)?;
    let reference = || {
        let error = || {
            format!("ingredient {field}: expected a hashed URI with text url, byte hash and optional text alg")
        };
        let fields = resource.as_map().ok_or_else(error)?;
        let url = fields
            .get(&Value::Text("url".into()))
            .and_then(Value::as_str)
            .ok_or_else(error)?;
        if !matches!(
            fields.get(&Value::Text("hash".into())),
            Some(Value::Bytes(_))
        ) || fields
            .get(&Value::Text("alg".into()))
            .is_some_and(|alg| alg.as_str().is_none())
        {
            return Err(error());
        }
        embedded_resource(manifest, url, &format!("ingredient {field}"))
    };
    Some(ResourceProjection(reference()))
}

impl Serialize for Ingredient {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use c2pa_cbor::Value;
        let error = |reason: &str| {
            serde::ser::Error::custom(format!("ingredient {:?}: {reason}", self.label))
        };
        let version = self.version.as_str();
        if !matches!(version, "1" | "2" | "3") {
            return Err(error("unsupported assertion version"));
        }
        let fields = self
            .data
            .as_ref()
            .and_then(Value::as_map)
            .ok_or_else(|| error("expected a CBOR map"))?;
        let field = |name: &str| {
            fields
                .get(&Value::Text(name.into()))
                .filter(|value| **value != Value::Null)
        };
        for name in [
            "c2pa_manifest",
            "activeManifest",
            "claimSignature",
            "validationStatus",
            "validationResults",
        ] {
            if field(name).is_some() {
                return Err(error(&format!("{name} reporting is not yet supported")));
            }
        }
        let required = if version == "1" {
            &["dc:title", "dc:format", "instanceID"][..]
        } else if version == "2" {
            &["dc:title", "dc:format"][..]
        } else {
            &[][..]
        };
        for name in required {
            if field(name).is_none() {
                return Err(error(&format!("missing required {name}")));
            }
        }
        let relationship = field("relationship")
            .and_then(Value::as_str)
            .ok_or_else(|| error("missing or malformed relationship"))?;
        if !matches!(relationship, "parentOf" | "componentOf" | "inputTo") {
            return Err(error("unknown relationship"));
        }
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("label", &self.label)?;
        map.serialize_entry("relationship", relationship)?;
        if field("thumbnail").is_some() {
            map.serialize_entry(
                "thumbnail",
                self.thumbnail
                    .as_ref()
                    .ok_or_else(|| error("thumbnail has no resource projection"))?,
            )?;
        }
        if field("data").is_some() {
            map.serialize_entry(
                "data",
                self.data_resource
                    .as_ref()
                    .ok_or_else(|| error("data has no resource projection"))?,
            )?;
        }
        for (source, target, enabled) in [
            ("dc:title", "title", true),
            ("dc:format", "format", true),
            ("instanceID", "instance_id", true),
            ("documentID", "document_id", version != "3"),
            ("description", "description", version != "1"),
            ("informational_URI", "informational_URI", version == "2"),
            ("informationalURI", "informational_URI", version == "3"),
            ("digitalSourceType", "digital_source_type", version == "3"),
        ] {
            if enabled {
                if let Some(value) = field(source) {
                    let text = value
                        .as_str()
                        .ok_or_else(|| error(&format!("{source} must be text")))?;
                    map.serialize_entry(target, text)?;
                }
            }
        }
        let data_types = if version == "2" {
            field("data_types")
        } else if version == "3" {
            field("dataTypes")
        } else {
            None
        };
        if let Some(data_types) = data_types {
            let values = data_types
                .as_array()
                .ok_or_else(|| error("data types must be an array"))?;
            for value in values {
                let entry = value
                    .as_map()
                    .ok_or_else(|| error("data type must be a map"))?;
                if !entry
                    .get(&Value::Text("type".into()))
                    .is_some_and(|v| v.as_str().is_some())
                    || entry
                        .get(&Value::Text("version".into()))
                        .is_some_and(|v| v.as_str().is_none())
                    || entry
                        .keys()
                        .any(|key| !matches!(key.as_str(), Some("type" | "version")))
                {
                    return Err(error(
                        "data type requires text type and optional text version",
                    ));
                }
            }
            map.serialize_entry("data_types", &JsonCbor(data_types))?;
        }
        if let Some(metadata) = field("metadata") {
            map.serialize_entry("metadata", &IngredientMetadata(metadata))?;
        }
        map.end()
    }
}

struct IngredientMetadata<'a>(&'a c2pa_cbor::Value);

impl Serialize for IngredientMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use c2pa_cbor::Value;
        let error =
            |reason: &str| serde::ser::Error::custom(format!("ingredient metadata: {reason}"));
        let fields = self
            .0
            .as_map()
            .ok_or_else(|| error("expected a CBOR map"))?;
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in fields {
            let name = key
                .as_str()
                .ok_or_else(|| error("field name must be text"))?;
            match name {
                "reference" | "dataSource" | "localizations" | "regionOfInterest" => {
                    if *value != Value::Null {
                        return Err(error(&format!("{name} reporting is not yet supported")));
                    }
                }
                "dateTime" if *value != Value::Null => {
                    let date = value
                        .as_str()
                        .ok_or_else(|| error("dateTime must be text"))?;
                    map.serialize_entry(name, date)?;
                }
                "reviewRatings" if *value != Value::Null => {
                    #[derive(Serialize)]
                    struct Review<'a> {
                        explanation: &'a str,
                        #[serde(skip_serializing_if = "Option::is_none")]
                        code: Option<&'a str>,
                        value: u8,
                    }
                    let ratings = value
                        .as_array()
                        .ok_or_else(|| error("reviewRatings must be an array"))?;
                    let mut reviews = Vec::with_capacity(ratings.len());
                    for rating in ratings {
                        let fields = rating
                            .as_map()
                            .ok_or_else(|| error("review rating must be a map"))?;
                        let field = |name: &str| fields.get(&Value::Text(name.into()));
                        let explanation = field("explanation")
                            .and_then(Value::as_str)
                            .ok_or_else(|| error("review explanation must be text"))?;
                        let code = match field("code") {
                            None | Some(Value::Null) => None,
                            Some(value) => Some(
                                value
                                    .as_str()
                                    .ok_or_else(|| error("review code must be text"))?,
                            ),
                        };
                        let value = match field("value") {
                            Some(Value::Integer(value)) => u8::try_from(*value)
                                .map_err(|_| error("review value must be an unsigned byte"))?,
                            _ => return Err(error("review value must be an unsigned byte")),
                        };
                        reviews.push(Review {
                            explanation,
                            code,
                            value,
                        });
                    }
                    map.serialize_entry(name, &reviews)?;
                }
                "dateTime" | "reviewRatings" => {}
                _ => map.serialize_entry(name, &JsonCbor(value))?,
            }
        }
        map.end()
    }
}

/// One assertion in the manifest store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAssertion {
    /// Assertion label.
    pub label: String,

    /// True when the claim created this assertion.
    pub created: bool,

    /// Decoded payload, or the legacy signer report for a verified identity.
    pub data: Option<c2pa_cbor::Value>,

    /// JSON assertion data, serialized as `data` with the legacy `Json` kind.
    /// Kept separate so CBOR byte strings retain their existing projection.
    pub json_data: Option<serde_json::Value>,
}

impl Serialize for ManifestAssertion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("label", &self.label)?;
        if self.created {
            map.serialize_entry("created", &true)?;
        }
        if let Some(data) = &self.json_data {
            map.serialize_entry("data", data)?;
            map.serialize_entry("kind", "Json")?;
        } else if let Some(data) = &self.data {
            map.serialize_entry("data", &JsonCbor(data))?;
        }
        map.end()
    }
}

struct JsonCbor<'a>(&'a c2pa_cbor::Value);

impl Serialize for JsonCbor<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use c2pa_cbor::Value;

        match self.0 {
            Value::Null => serializer.serialize_none(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Integer(value) => serializer.serialize_i64(*value),
            Value::Float(value) => serializer.serialize_f64(*value),
            Value::Bytes(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Value::Text(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&JsonCbor(value))?;
                }
                sequence.end()
            }
            Value::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    let Value::Text(key) = key else {
                        return Err(serde::ser::Error::custom(
                            "assertion CBOR map key is not text",
                        ));
                    };
                    map.serialize_entry(key, &JsonCbor(value))?;
                }
                map.end()
            }
            Value::Tag(_, value) => JsonCbor(value).serialize(serializer),
        }
    }
}

/// Overall validation outcome for a manifest store, as c2pa-rs's
/// `ValidationState` names it.
///
/// [`contentauth_c2pa_reader::ValidationState`] has a fourth variant,
/// `Incomplete`, for a check that never ran rather than one that failed;
/// c2pa-rs (and so c2pa-js) has no such notion, so it folds into
/// [`Self::Invalid`] here — the conservative reading, and the same one
/// `contentauth-c2pa-rs-compat` makes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ValidationState {
    /// The manifest store failed validation, or nothing was validated, or
    /// the trust evaluation never ran at all.
    Invalid,

    /// Well-formed and every cryptographic check that ran passed, but the
    /// signer is not among the configured trust anchors.
    Valid,

    /// Valid, and the signer's credential chains to a configured trust
    /// anchor, with no compatibility failure observations (including CAWG).
    Trusted,
}

impl From<Option<contentauth_c2pa_reader::ValidationState>> for ValidationState {
    fn from(state: Option<contentauth_c2pa_reader::ValidationState>) -> Self {
        use contentauth_c2pa_reader::ValidationState as Inner;

        match state {
            Some(Inner::Trusted) => Self::Trusted,
            Some(Inner::Valid) => Self::Valid,
            // `Invalid`, `Incomplete`, and any future non-exhaustive
            // variant added upstream all fold in here.
            Some(_) | None => Self::Invalid,
        }
    }
}

/// One validation status observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationStatus {
    /// The status code, e.g. `assertion.dataHash.match`.
    pub code: String,

    /// JUMBF URI of the manifest store element this status pertains to,
    /// if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// A human-readable explanation of the check performed, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,

    /// On a trusted status, the URI of the trust list that matched, when
    /// the list was configured with a `trust_uri`.
    ///
    /// Never serialized: c2pa-rs 0.91 keeps this on its `ValidationStatus`
    /// behind an accessor and marks it `#[serde(skip)]`, so the JSON
    /// reported here stays identical to c2pa-rs's.
    #[serde(skip)]
    pub trust_list_uri: Option<String>,
}

/// Validation statuses grouped as c2pa-rs reports them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidationResults {
    /// Results for the active manifest.
    #[serde(rename = "activeManifest")]
    pub active_manifest: ValidationResultBuckets,

    /// New observations about resource-free ingredients without provenance.
    ///
    /// Historical and linked-manifest delta comparison is not implemented.
    #[serde(rename = "ingredientDeltas", skip_serializing_if = "Vec::is_empty")]
    pub ingredient_deltas: Vec<IngredientDelta>,

    /// C2PA specification version used by this report.
    #[serde(rename = "specVersion")]
    pub spec_version: &'static str,

    /// Named trust list that established the active claim signer's trust.
    #[serde(rename = "trustListUri", skip_serializing_if = "Option::is_none")]
    pub trust_list_uri: Option<String>,

    /// Named trust list that established its timestamp authority's trust.
    #[serde(
        rename = "timestampTrustListUri",
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp_trust_list_uri: Option<String>,
}

/// Validation observations scoped to one ingredient assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IngredientDelta {
    /// Absolute URI of the ingredient assertion, not its source manifest.
    #[serde(rename = "ingredientAssertionURI")]
    pub ingredient_assertion_uri: String,
    /// New checks grouped by outcome; never copied from asserted history.
    #[serde(rename = "validationDeltas")]
    pub validation_deltas: ValidationResultBuckets,
}

/// Statuses grouped by result category.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ValidationResultBuckets {
    /// Checks that passed.
    pub success: Vec<ValidationStatus>,

    /// Checks that did not establish success or failure.
    pub informational: Vec<ValidationStatus>,

    /// Checks that failed.
    pub failure: Vec<ValidationStatus>,
}

impl ManifestStore {
    /// Serializes the legacy JSON view without changing the object projection.
    ///
    /// Like the pinned SDK, nonempty all-number arrays in object fields become
    /// base64 strings regardless of field name. Negative and floating-point
    /// numbers are omitted, and unsigned integers contribute their low byte.
    /// Use ordinary serialization of this type to preserve the original arrays.
    pub fn json(&self) -> Result<String, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        format_legacy_json(&mut value);
        serde_json::to_string_pretty(&value)
    }

    /// Reports `report` in c2pa-rs's manifest-store shape.
    ///
    /// Public so that a sibling compatibility layer over another c2pa-rs
    /// surface (`contentauth-c2pa-node-compat`) can reuse the one
    /// reporting of the engine's result rather than copy it.
    pub fn from_report(report: &ReadReport) -> Self {
        let statuses: Vec<_> = report.statuses.iter().map(project_status).collect();
        let mut failures: Vec<_> = report
            .statuses
            .iter()
            .zip(&statuses)
            .filter(|(inner, _)| is_failure_bucket(inner))
            .map(|(_, status)| status.clone())
            .collect();
        failures.sort_by_key(status_order);
        let mut validation_state = report.validation_state.into();
        if validation_state == ValidationState::Trusted && !failures.is_empty() {
            validation_state = ValidationState::Valid;
        }

        Self {
            active_manifest: report.active_manifest.clone(),
            manifests: report
                .manifests
                .iter()
                .map(|manifest| (manifest.label.clone(), Manifest::from_inner(manifest)))
                .collect(),
            validation_state,
            validation_status: failures,
            validation_results: validation_results(report, statuses),
        }
    }
}

fn format_legacy_json(value: &mut serde_json::Value) {
    use serde_json::Value;

    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(fields) => {
                for field in fields.values_mut() {
                    if let Some(numbers) = field
                        .as_array()
                        .filter(|items| !items.is_empty() && items.iter().all(Value::is_number))
                    {
                        // This intentionally mirrors the legacy display formatter,
                        // not a lossless encoding of arbitrary assertion data.
                        let bytes: Vec<_> = numbers
                            .iter()
                            .filter_map(Value::as_u64)
                            .map(|number| number.to_le_bytes()[0])
                            .collect();
                        *field = Value::String(STANDARD.encode(bytes));
                    } else {
                        pending.push(field);
                    }
                }
            }
            Value::Array(items) => pending.extend(items),
            _ => {}
        }
    }
}

fn project_status(inner: &contentauth_c2pa_reader::ValidationStatus) -> ValidationStatus {
    let explanation = match inner.code.as_str() {
        "claimSignature.validated" | "claimSignature.insideValidity" => {
            Some("claim signature valid".into())
        }
        "assertion.dataHash.match" => Some("data hash valid".into()),
        "signingCredential.ocsp.skipped" => Some("OCSP fetching skipped".into()),
        "signingCredential.untrusted" | "cawg.x509.credential.untrusted" if !inner.is_failure() => {
            Some("signing certificate untrusted".into())
        }
        "signingCredential.trusted" | "cawg.x509.credential.trusted" => inner
            .trust_list_uri
            .as_ref()
            .map(|uri| format!("signing certificate trusted, found in [{uri}] trust anchors"))
            .or_else(|| inner.explanation.clone()),
        "cawg.x509.signature.validated" => {
            Some("X.509 identity assertion signature validated".into())
        }
        "cawg.identity.well-formed" => Some("CAWG X.509 identity signature valid".into()),
        _ => inner.explanation.clone(),
    };
    ValidationStatus {
        code: inner.code.clone(),
        url: inner.url.clone(),
        explanation,
        trust_list_uri: inner.trust_list_uri.clone(),
    }
}

// The core emits observations as its sans-I/O phases complete. Legacy reports
// them in validation order instead; stable sorting preserves assertion order
// and never deduplicates or drops an observation.
fn status_order(status: &ValidationStatus) -> u8 {
    match status.code.as_str() {
        "signingCredential.ocsp.skipped" => 0,
        "timeStamp.validated" | "timeStamp.untrusted" => 1,
        "signingCredential.trusted" | "signingCredential.untrusted" => 2,
        "claimSignature.insideValidity" => 3,
        "claimSignature.validated" => 4,
        "assertion.hashedURI.match" => 5,
        "assertion.dataHash.match" => 6,
        "cawg.x509.credential.trusted" | "cawg.x509.credential.untrusted" => 7,
        "cawg.x509.signature.validated" => 8,
        "cawg.identity.well-formed" => 9,
        _ => 10,
    }
}

fn validation_results(report: &ReadReport, statuses: Vec<ValidationStatus>) -> ValidationResults {
    let active_label = report.active_manifest.as_deref().unwrap_or_default();
    let mut active_manifest = ValidationResultBuckets::default();
    let mut ingredient_deltas = Vec::new();

    for (inner, status) in report.statuses.iter().zip(statuses) {
        let pertains_to_active = inner
            .url
            .as_ref()
            .is_none_or(|url| url.starts_with(&format!("self#jumbf=/c2pa/{active_label}/")));
        if !pertains_to_active {
            continue;
        }

        if inner.code
            == contentauth_c2pa_reader::validation::status_code::INGREDIENT_PROVENANCE_UNKNOWN
            && !is_failure_bucket(inner)
        {
            if let Some(uri) = inner.url.as_ref() {
                ingredient_deltas.push(IngredientDelta {
                    ingredient_assertion_uri: uri.clone(),
                    validation_deltas: ValidationResultBuckets {
                        informational: vec![status],
                        ..Default::default()
                    },
                });
                continue;
            }
        }

        if is_failure_bucket(inner) {
            active_manifest.failure.push(status);
        } else if is_informational_bucket(inner) {
            active_manifest.informational.push(status);
        } else {
            active_manifest.success.push(status);
        }
    }

    active_manifest.success.sort_by_key(status_order);
    active_manifest.informational.sort_by_key(status_order);
    active_manifest.failure.sort_by_key(status_order);
    let signature_url = format!("self#jumbf=/c2pa/{active_label}/c2pa.signature");
    let trust_uri = |code: &str| {
        report
            .statuses
            .iter()
            .find(|status| status.code == code && status.url.as_deref() == Some(&signature_url))
            .and_then(|status| status.trust_list_uri.clone())
    };
    ValidationResults {
        active_manifest,
        ingredient_deltas,
        spec_version: "2.4.0",
        trust_list_uri: trust_uri("signingCredential.trusted"),
        timestamp_trust_list_uri: trust_uri("timeStamp.trusted"),
    }
}

fn is_failure_bucket(status: &contentauth_c2pa_reader::ValidationStatus) -> bool {
    status.is_failure()
        || matches!(
            status.code.as_str(),
            "signingCredential.untrusted" | "cawg.x509.credential.untrusted"
        )
}

fn is_informational_bucket(status: &contentauth_c2pa_reader::ValidationStatus) -> bool {
    use contentauth_c2pa_reader::validation::status_code;

    status.is_unchecked()
        || matches!(
            status.code.as_str(),
            status_code::SIGNING_CREDENTIAL_OCSP_SKIPPED
                | status_code::INGREDIENT_PROVENANCE_UNKNOWN
                | status_code::ASSERTION_DATAHASH_ADDITIONAL_EXCLUSIONS
                | status_code::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE
                | status_code::SIGNING_CREDENTIAL_OCSP_UNKNOWN
                | status_code::TIMESTAMP_UNTRUSTED
                | status_code::TIMESTAMP_MISMATCH
                | status_code::TIMESTAMP_MALFORMED
                | status_code::TIMESTAMP_OUTSIDE_VALIDITY
                | status_code::CAWG_IDENTITY_SIG_TYPE_UNSUPPORTED
        )
}

impl Manifest {
    /// Reports one of `report`'s manifests; see [`ManifestStore::from_report`].
    pub fn from_inner(manifest: &contentauth_c2pa_reader::Manifest) -> Self {
        Self {
            label: manifest.label.clone(),
            claim_generator: manifest.claim.claim_generator.clone(),
            claim_generator_info: manifest
                .claim
                .claim_generator_info
                .iter()
                .map(|info| ClaimGeneratorInfo {
                    name: info.name.clone(),
                    version: info.version.clone(),
                    spec_version: info.spec_version.clone(),
                    icon: info
                        .icon
                        .as_ref()
                        .map(|icon| generator_icon(manifest, icon)),
                    extensions: info.extensions.clone(),
                })
                .collect(),
            claim_version: manifest.claim.version,
            title: manifest.claim.title.clone(),
            format: manifest.claim.format.clone(),
            instance_id: manifest.claim.instance_id.clone().unwrap_or_default(),
            signature_info: manifest
                .signature_info
                .as_ref()
                .map(SignatureInfo::from_inner),
            ingredients: manifest
                .assertions
                .iter()
                .filter_map(|assertion| {
                    Some(Ingredient {
                        version: assertion.ingredient_version()?.to_string(),
                        label: assertion.label.clone(),
                        data: assertion.data.clone(),
                        thumbnail: ingredient_thumbnail(manifest, assertion.data.as_ref()),
                        data_resource: ingredient_resource(
                            manifest,
                            assertion.data.as_ref(),
                            "data",
                        ),
                    })
                })
                .collect(),
            thumbnail: manifest
                .resources
                .iter()
                .find(|resource| {
                    resource.label == "c2pa.thumbnail.claim"
                        || resource.label.starts_with("c2pa.thumbnail.claim.")
                })
                .map(|resource| ResourceRef {
                    format: resource.format.clone(),
                    identifier: format!(
                        "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
                        manifest.label, resource.label
                    ),
                }),
            assertions: manifest
                .assertions
                .iter()
                .filter(|assertion| {
                    !matches!(
                        assertion.label.as_str(),
                        "c2pa.hash.data" | "c2pa.hash.bmff" | "c2pa.hash.boxes"
                    ) && assertion.ingredient_version().is_none()
                        && !manifest
                            .resources
                            .iter()
                            .any(|resource| resource.label == assertion.label)
                })
                .map(|assertion| ManifestAssertion {
                    label: match assertion.label.as_str() {
                        "c2pa.actions" => "c2pa.actions.v2".into(),
                        _ => assertion.label.clone(),
                    },
                    created: assertion.created,
                    json_data: assertion.json_data.clone(),
                    data: manifest
                        .identity_assertions
                        .iter()
                        .find(|identity| identity.label == assertion.label)
                        .and_then(|identity| identity.signature_info.as_ref())
                        .and_then(|info| {
                            let payload = assertion
                                .data
                                .as_ref()?
                                .as_map()?
                                .get(&c2pa_cbor::Value::Text("signer_payload".into()))?;
                            Some(c2pa_cbor::Value::Map(BTreeMap::from([
                                (
                                    c2pa_cbor::Value::Text("signer_payload".into()),
                                    payload.clone(),
                                ),
                                (
                                    c2pa_cbor::Value::Text("signature_info".into()),
                                    SignatureInfo::from_inner(info).identity_data(),
                                ),
                            ])))
                        })
                        .or_else(|| assertion.data.clone()),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use contentauth_c2pa_reader::ValidationState as Inner;

    use super::*;

    #[test]
    fn shared_resource_lookup_requires_exact_unique_owner_and_assertion(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = fixture_report()?;
        let original = report.manifests.first().ok_or("no manifest")?.clone();
        let resource = original.resources.first().ok_or("no resource")?.clone();
        let uri = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
            original.label, resource.label
        );
        assert_eq!(resource_bytes(&report, &uri)?, resource.bytes);
        for bad in [
            resource.label.clone(),
            format!("self#jumbf=c2pa.assertions/{}", resource.label),
            uri.replace("/c2pa.assertions/", "/c2pa.databoxes/"),
            format!("{uri}__999"),
            "https://example.invalid/resource".into(),
        ] {
            assert!(matches!(
                resource_bytes(&report, &bad),
                Err(crate::Error::C2pa(crate::C2paError::ResourceNotFound(_)))
            ));
        }
        let mut other = original.clone();
        other.label = "other-owner".into();
        report.manifests.push(other);
        assert_eq!(resource_bytes(&report, &uri)?, resource.bytes);
        report.manifests.push(original);
        assert!(resource_bytes(&report, &uri).is_err());
        report.manifests.pop();
        report
            .manifests
            .first_mut()
            .ok_or("no manifest")?
            .resources
            .push(resource);
        assert!(resource_bytes(&report, &uri).is_err());
        Ok(())
    }

    #[test]
    fn generator_icons_resolve_exact_owner_and_positional_resource_labels(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = fixture_report()?;
        let manifest = report
            .manifests
            .first_mut()
            .ok_or("fixture has no manifest")?;
        let mut resource = manifest
            .resources
            .first()
            .ok_or("fixture has no resource")?
            .clone();
        resource.label = "c2pa.icon__1".into();
        manifest.resources = vec![resource.clone()];
        let absolute = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
            manifest.label, resource.label
        );
        for url in [
            format!("self#jumbf=c2pa.assertions/{}", resource.label),
            absolute.clone(),
        ] {
            let mut reference = contentauth_c2pa_reader::HashedUri::default();
            reference.url = url;
            let info = manifest
                .claim
                .claim_generator_info
                .first_mut()
                .ok_or("no generator")?;
            info.icon = Some(reference);
            let projected = Manifest::from_inner(manifest);
            let value = serde_json::to_value(&projected)?;
            assert_eq!(
                value["claim_generator_info"][0]["icon"],
                serde_json::json!({
                    "format":resource.format, "identifier":absolute,
                })
            );
        }
        assert_eq!(manifest.resources[0].bytes, resource.bytes);
        Ok(())
    }

    #[test]
    fn unresolvable_generator_icons_error_instead_of_disappearing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = fixture_report()?;
        let manifest = report
            .manifests
            .first_mut()
            .ok_or("fixture has no manifest")?;
        let resource = manifest
            .resources
            .first()
            .ok_or("fixture has no resource")?
            .clone();
        for url in [
            "https://example.invalid/icon".to_string(),
            "self#jumbf=/c2pa/other/c2pa.assertions/c2pa.icon".into(),
            "self#jumbf=c2pa.databoxes/c2pa.icon".into(),
            "self#jumbf=c2pa.assertions/missing".into(),
            "self#jumbf=c2pa.assertions/".into(),
            "self#jumbf=c2pa.assertions/nested/c2pa.icon".into(),
        ] {
            let mut reference = contentauth_c2pa_reader::HashedUri::default();
            reference.url = url;
            let error = serde_json::to_value(generator_icon(manifest, &reference))
                .err()
                .ok_or("unsupported icon serialized successfully")?;
            assert!(error.to_string().contains("generator icon"));
        }
        manifest.resources.push(resource.clone());
        let mut reference = contentauth_c2pa_reader::HashedUri::default();
        reference.url = format!("self#jumbf=c2pa.assertions/{}", resource.label);
        assert!(serde_json::to_value(generator_icon(manifest, &reference)).is_err());
        Ok(())
    }

    fn ingredient(
        label: &str,
        version: &str,
        data: serde_json::Value,
    ) -> Result<Ingredient, Box<dyn std::error::Error>> {
        Ok(Ingredient {
            label: label.into(),
            version: version.into(),
            data: Some(c2pa_cbor::from_slice(&c2pa_cbor::to_vec(&data)?)?),
            thumbnail: None,
            data_resource: None,
        })
    }

    #[test]
    fn ingredient_data_resources_preserve_owner_shape_and_history_boundaries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use c2pa_cbor::Value;

        let mut report = fixture_report()?;
        let manifest = report.manifests.first_mut().ok_or("no fixture manifest")?;
        let mut resource = manifest
            .resources
            .first()
            .ok_or("no fixture resource")?
            .clone();
        resource.label = "c2pa.data__1".into();
        manifest.resources = vec![resource.clone()];
        let absolute = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
            manifest.label, resource.label
        );
        for version in ["1", "2", "3"] {
            for url in [
                format!("self#jumbf=c2pa.assertions/{}", resource.label),
                absolute.clone(),
                "self#jumbf=/c2pa/other/c2pa.assertions/c2pa.data__1".into(),
                "self#jumbf=c2pa.databoxes/c2pa.data".into(),
                "self#jumbf=c2pa.assertions/missing".into(),
                "https://example.invalid/data".into(),
                "self#jumbf=c2pa.assertions/".into(),
                "self#jumbf=c2pa.assertions/nested/data".into(),
            ] {
                let supported = url == absolute
                    || url == format!("self#jumbf=c2pa.assertions/{}", resource.label);
                let mut ingredient = ingredient(
                    "c2pa.ingredient",
                    version,
                    serde_json::json!({
                        "relationship":"componentOf","dc:title":"Dataset","dc:format":"application/json",
                        "instanceID":"xmp:iid:dataset",
                    }),
                )?;
                let reference = Value::Map(BTreeMap::from([
                    (Value::Text("url".into()), Value::Text(url)),
                    (Value::Text("hash".into()), Value::Bytes(vec![1; 32])),
                ]));
                let Some(Value::Map(fields)) = ingredient.data.as_mut() else {
                    return Err("not a map".into());
                };
                fields.insert(Value::Text("data".into()), reference);
                ingredient.data_resource =
                    ingredient_resource(manifest, ingredient.data.as_ref(), "data");
                let value = serde_json::to_value(&ingredient);
                if supported {
                    assert_eq!(
                        value?["data"],
                        serde_json::json!({"format":resource.format,"identifier":absolute})
                    );
                    let Some(Value::Map(fields)) = ingredient.data.as_mut() else {
                        return Err("not a map".into());
                    };
                    fields.insert(
                        Value::Text("activeManifest".into()),
                        Value::Map(BTreeMap::new()),
                    );
                    assert!(serde_json::to_value(ingredient).is_err());
                } else {
                    assert!(value
                        .err()
                        .ok_or("unsupported data serialized")?
                        .to_string()
                        .contains("ingredient data"));
                }
            }
        }
        for reference in [
            Value::Array(vec![]),
            Value::Map(BTreeMap::new()),
            Value::Map(BTreeMap::from([
                (Value::Text("url".into()), Value::Text(absolute.clone())),
                (
                    Value::Text("hash".into()),
                    Value::Array(vec![Value::Integer(1)]),
                ),
            ])),
            Value::Map(BTreeMap::from([
                (Value::Text("url".into()), Value::Text(absolute.clone())),
                (Value::Text("hash".into()), Value::Bytes(vec![1; 32])),
                (Value::Text("alg".into()), Value::Integer(1)),
            ])),
        ] {
            let data = Value::Map(BTreeMap::from([(Value::Text("data".into()), reference)]));
            let projected =
                ingredient_resource(manifest, Some(&data), "data").ok_or("no data projection")?;
            assert!(serde_json::to_value(projected).is_err());
        }
        manifest.resources.push(resource);
        let data = Value::Map(BTreeMap::from([(
            Value::Text("data".into()),
            Value::Map(BTreeMap::from([
                (Value::Text("url".into()), Value::Text(absolute)),
                (Value::Text("hash".into()), Value::Bytes(vec![1; 32])),
            ])),
        )]));
        assert!(serde_json::to_value(ingredient_resource(manifest, Some(&data), "data")).is_err());
        let absent = ingredient(
            "c2pa.ingredient.v3",
            "3",
            serde_json::json!({"relationship":"inputTo","data":null}),
        )?;
        assert!(ingredient_resource(manifest, absent.data.as_ref(), "data").is_none());
        assert!(serde_json::to_value(absent)?.get("data").is_none());
        Ok(())
    }

    #[test]
    fn ingredient_thumbnails_resolve_exact_resources_for_all_assertion_versions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use c2pa_cbor::Value;

        let mut report = fixture_report()?;
        let manifest = report.manifests.first_mut().ok_or("no fixture manifest")?;
        let mut resource = manifest
            .resources
            .first()
            .ok_or("no fixture resource")?
            .clone();
        resource.label = "c2pa.thumbnail.ingredient__1".into();
        manifest.resources = vec![resource.clone()];
        let absolute = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
            manifest.label, resource.label
        );
        for version in ["1", "2", "3"] {
            for url in [
                format!("self#jumbf=c2pa.assertions/{}", resource.label),
                absolute.clone(),
            ] {
                let mut ingredient = ingredient(
                    "c2pa.ingredient",
                    version,
                    serde_json::json!({
                        "relationship":"componentOf", "dc:title":"Source", "dc:format":"image/jpeg",
                        "instanceID":"xmp:iid:source", "metadata":{"dateTime":"2026-10-14T00:00:00Z"},
                    }),
                )?;
                let reference = Value::Map(BTreeMap::from([
                    (Value::Text("url".into()), Value::Text(url)),
                    (Value::Text("hash".into()), Value::Bytes(vec![1; 32])),
                    (Value::Text("alg".into()), Value::Text("sha256".into())),
                ]));
                let Some(Value::Map(fields)) = ingredient.data.as_mut() else {
                    return Err("fixture ingredient is not a map".into());
                };
                fields.insert(Value::Text("thumbnail".into()), reference);
                ingredient.thumbnail = ingredient_thumbnail(manifest, ingredient.data.as_ref());
                let value = serde_json::to_value(&ingredient)?;
                assert_eq!(
                    value["thumbnail"],
                    serde_json::json!({
                        "format":resource.format, "identifier":absolute,
                    })
                );
                assert_eq!(value["metadata"]["dateTime"], "2026-10-14T00:00:00Z");
                let Some(Value::Map(fields)) = ingredient.data.as_mut() else {
                    return Err("fixture ingredient is not a map".into());
                };
                fields.insert(
                    Value::Text("activeManifest".into()),
                    Value::Map(BTreeMap::new()),
                );
                assert!(
                    serde_json::to_value(&ingredient).is_err(),
                    "thumbnail must not enable linked histories"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn ingredient_thumbnail_errors_are_explicit_and_null_is_omitted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use c2pa_cbor::Value;

        let mut report = fixture_report()?;
        let manifest = report.manifests.first_mut().ok_or("no fixture manifest")?;
        for reference in [
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!({"url":1,"hash":[1]}),
            serde_json::json!({"url":"self#jumbf=c2pa.assertions/missing","hash":[1]}),
        ] {
            let ingredient = ingredient(
                "c2pa.ingredient.v3",
                "3",
                serde_json::json!({
                    "relationship":"inputTo", "thumbnail":reference,
                }),
            )?;
            let projected = ingredient_thumbnail(manifest, ingredient.data.as_ref())
                .ok_or("missing projection")?;
            assert!(serde_json::to_value(projected).is_err());
        }
        let mut reference = BTreeMap::from([
            (
                Value::Text("url".into()),
                Value::Text("self#jumbf=c2pa.assertions/missing".into()),
            ),
            (Value::Text("hash".into()), Value::Bytes(vec![1; 32])),
        ]);
        let resource = manifest
            .resources
            .first()
            .ok_or("no fixture resource")?
            .clone();
        for url in [
            "https://example.invalid/thumb".into(),
            "self#jumbf=/c2pa/other/c2pa.assertions/c2pa.thumbnail.ingredient".into(),
            "self#jumbf=c2pa.databoxes/c2pa.data".into(),
            "self#jumbf=c2pa.assertions/missing".into(),
            "self#jumbf=c2pa.assertions/".into(),
            "self#jumbf=c2pa.assertions/nested/thumbnail".into(),
        ] {
            reference.insert(Value::Text("url".into()), Value::Text(url));
            let data = Value::Map(BTreeMap::from([(
                Value::Text("thumbnail".into()),
                Value::Map(reference.clone()),
            )]));
            let projected =
                ingredient_thumbnail(manifest, Some(&data)).ok_or("missing projection")?;
            let error = serde_json::to_value(projected)
                .err()
                .ok_or("unsupported thumbnail serialized")?;
            assert!(error.to_string().contains("ingredient thumbnail"));
        }
        manifest.resources.push(resource.clone());
        reference.insert(
            Value::Text("url".into()),
            Value::Text(format!("self#jumbf=c2pa.assertions/{}", resource.label)),
        );
        for alg in [None, Some(Value::Integer(1)), Some(Value::Null)] {
            if let Some(alg) = alg {
                reference.insert(Value::Text("alg".into()), alg);
            }
            let data = Value::Map(BTreeMap::from([(
                Value::Text("thumbnail".into()),
                Value::Map(reference.clone()),
            )]));
            let projected =
                ingredient_thumbnail(manifest, Some(&data)).ok_or("missing projection")?;
            assert!(serde_json::to_value(projected).is_err());
        }
        let absent = ingredient(
            "c2pa.ingredient.v3",
            "3",
            serde_json::json!({
                "relationship":"inputTo","thumbnail":null,
            }),
        )?;
        assert!(ingredient_thumbnail(manifest, absent.data.as_ref()).is_none());
        assert!(serde_json::to_value(absent)?.get("thumbnail").is_none());
        Ok(())
    }

    #[test]
    fn ingredient_versions_translate_only_their_declared_metadata_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::json!({
            "dc:title": "Input", "dc:format": "image/jpeg", "instanceID": "instance",
            "documentID": "document", "relationship": "inputTo", "description": "Source",
            "informational_URI": "legacy", "informationalURI": "modern",
            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
            "data_types": [{"type":"dataset", "version":"2"}], "dataTypes": [],
            "unknown": "not a public ingredient field",
        });
        for version in ["1", "2", "3"] {
            let value =
                serde_json::to_value(ingredient("c2pa.ingredient", version, data.clone())?)?;
            assert_eq!(value["title"], "Input");
            assert_eq!(value["format"], "image/jpeg");
            assert_eq!(value["instance_id"], "instance");
            assert_eq!(value["relationship"], "inputTo");
            assert_eq!(value.get("document_id").is_some(), version != "3");
            assert_eq!(value.get("description").is_some(), version != "1");
            assert!(value.get("unknown").is_none());
            match version {
                "2" => {
                    assert_eq!(value["informational_URI"], "legacy");
                    assert_eq!(value["data_types"], data["data_types"]);
                }
                "3" => {
                    assert_eq!(value["informational_URI"], "modern");
                    assert_eq!(value["data_types"], data["dataTypes"]);
                }
                _ => {
                    assert!(value.get("data_types").is_none());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn ingredient_assertion_metadata_is_reported_without_becoming_validation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let metadata = serde_json::json!({
            "dateTime": "2026-10-14T10:20:30Z",
            "reviewRatings": [
                {"explanation": "An asserted review", "value": 5, "code": "ingredient.modified",
                 "ignored": "not a review field"},
                {"explanation": "Lower encoding boundary", "value": 0, "code": null},
                {"explanation": "Upper encoding boundary", "value": 255},
            ],
            "org.example.review": {"author":"Reviewer", "scores":[1,2,255]},
        });
        let mut expected = metadata.clone();
        expected["reviewRatings"][0]
            .as_object_mut()
            .ok_or("review is not an object")?
            .remove("ignored");
        expected["reviewRatings"][1]
            .as_object_mut()
            .ok_or("review is not an object")?
            .remove("code");
        for version in ["1", "2", "3"] {
            let data = serde_json::json!({
                "dc:title":"Source", "dc:format":"image/jpeg", "instanceID":"instance",
                "relationship":"componentOf", "metadata":metadata,
            });
            let value = serde_json::to_value(ingredient("c2pa.ingredient", version, data)?)?;
            assert_eq!(value["metadata"], expected);
            assert!(value.get("validation_status").is_none());
            assert!(value.get("validation_results").is_none());
        }
        for metadata in [
            serde_json::json!({}),
            serde_json::json!({"dateTime":null,"reviewRatings":null,"reference":null}),
        ] {
            let data = serde_json::json!({"relationship":"inputTo","metadata":metadata});
            let value = serde_json::to_value(ingredient("c2pa.ingredient.v3", "3", data)?)?;
            assert_eq!(value["metadata"], serde_json::json!({}));
        }
        Ok(())
    }

    #[test]
    fn malformed_or_unported_ingredient_assertion_metadata_is_an_explicit_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for metadata in [
            serde_json::json!([]),
            serde_json::json!({"dateTime":1}),
            serde_json::json!({"reviewRatings":{}}),
            serde_json::json!({"reviewRatings":[0]}),
            serde_json::json!({"reviewRatings":[{"value":5}]}),
            serde_json::json!({"reviewRatings":[{"explanation":"x"}]}),
            serde_json::json!({"reviewRatings":[{"explanation":null,"value":5}]}),
            serde_json::json!({"reviewRatings":[{"explanation":"x","value":-1}]}),
            serde_json::json!({"reviewRatings":[{"explanation":"x","value":256}]}),
            serde_json::json!({"reviewRatings":[{"explanation":"x","value":1.5}]}),
            serde_json::json!({"reviewRatings":[{"explanation":"x","value":5,"code":1}]}),
            serde_json::json!({"reference":{}}),
            serde_json::json!({"dataSource":{}}),
            serde_json::json!({"localizations":[]}),
            serde_json::json!({"regionOfInterest":{}}),
        ] {
            let data = serde_json::json!({"relationship":"componentOf","metadata":metadata});
            let error = serde_json::to_value(ingredient("c2pa.ingredient.v3", "3", data)?)
                .err()
                .ok_or("malformed metadata serialized successfully")?;
            assert!(error.to_string().contains("ingredient metadata"));
        }
        Ok(())
    }

    #[test]
    fn malformed_and_unported_ingredient_fields_are_serialization_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (version, data) in [
            ("4", serde_json::json!({"relationship":"componentOf"})),
            (
                "1",
                serde_json::json!({"dc:title":"x", "dc:format":"image/jpeg","relationship":"parentOf"}),
            ),
            ("2", serde_json::json!({"relationship":"componentOf"})),
            ("3", serde_json::json!({"relationship":"unexpected"})),
            (
                "3",
                serde_json::json!({"relationship":"componentOf", "dc:title":42}),
            ),
            (
                "3",
                serde_json::json!({"relationship":"componentOf", "dataTypes":"dataset"}),
            ),
            (
                "3",
                serde_json::json!({"relationship":"componentOf", "dataTypes":[{"version":"1"}]}),
            ),
            (
                "3",
                serde_json::json!({"relationship":"componentOf", "dataTypes":[{"type":"dataset", "version":3}]}),
            ),
            ("3", serde_json::json!([])),
        ] {
            assert!(
                serde_json::to_value(ingredient("c2pa.ingredient.v3", version, data)?).is_err()
            );
        }
        for name in [
            "activeManifest",
            "c2pa_manifest",
            "claimSignature",
            "thumbnail",
            "data",
            "validationStatus",
            "validationResults",
        ] {
            let mut data = serde_json::json!({"relationship":"componentOf"});
            data[name] = serde_json::json!({});
            let error = serde_json::to_value(ingredient("c2pa.ingredient.v3", "3", data)?).err();
            assert!(
                error.is_some_and(|error| error.to_string().contains(name)),
                "{name}"
            );
        }
        Ok(())
    }

    #[test]
    fn ingredient_deltas_do_not_absorb_active_failures_or_inactive_observations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = fixture_report()?;
        report.active_manifest = Some("active".into());
        let template = report.statuses[0].clone();
        report.statuses = vec![
            status(
                &template,
                "ingredient.unknownProvenance",
                "self#jumbf=/c2pa/inactive/c2pa.assertions/c2pa.ingredient",
                "inactive",
            ),
            status(
                &template,
                "ingredient.unknownProvenance",
                "self#jumbf=/c2pa/active/c2pa.assertions/c2pa.ingredient",
                "no provenance",
            ),
            status(
                &template,
                "claimSignature.mismatch",
                "self#jumbf=/c2pa/active/c2pa.signature",
                "active signature broken",
            ),
        ];
        let projected = ManifestStore::from_report(&report);
        assert_eq!(projected.validation_status.len(), 1);
        assert_eq!(
            projected.validation_results.active_manifest.failure[0].code,
            "claimSignature.mismatch"
        );
        assert!(projected
            .validation_results
            .active_manifest
            .informational
            .is_empty());
        let deltas = &projected.validation_results.ingredient_deltas;
        assert_eq!(deltas.len(), 1);
        assert_eq!(
            deltas[0].ingredient_assertion_uri,
            "self#jumbf=/c2pa/active/c2pa.assertions/c2pa.ingredient"
        );
        assert_eq!(
            deltas[0].validation_deltas.informational[0]
                .explanation
                .as_deref(),
            Some("no provenance")
        );
        assert!(deltas[0].validation_deltas.failure.is_empty());
        Ok(())
    }

    #[test]
    fn legacy_json_formats_numeric_object_fields_but_preserves_other_arrays() {
        let mut value = serde_json::json!({
            "hash": [0, 1, 254, 255],
            "not_a_hash": [256, 257, -1, 1.5],
            "no_unsigned": [-1, 0.5],
            "empty": [],
            "mixed": [1, "two", null, {"nested": [3, 4]}],
            "nested": [[1, 2], {"bytes": [5]}],
            "string": "already encoded",
        });
        format_legacy_json(&mut value);
        assert_eq!(
            value,
            serde_json::json!({
                "hash": "AAH+/w==",
                "not_a_hash": "AAE=",
                "no_unsigned": "",
                "empty": [],
                "mixed": [1, "two", null, {"nested": "AwQ="}],
                "nested": [[1, 2], {"bytes": "BQ=="}],
                "string": "already encoded",
            })
        );
        let mut direct = serde_json::json!([1, 2]);
        format_legacy_json(&mut direct);
        assert_eq!(direct, serde_json::json!([1, 2]));
    }

    #[test]
    fn legacy_json_is_a_separate_view_and_reports_serialization_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use c2pa_cbor::Value;

        let mut store = ManifestStore::from_report(&fixture_report()?);
        let manifest = store
            .manifests
            .values_mut()
            .next()
            .ok_or("missing fixture manifest")?;
        manifest.assertions.push(ManifestAssertion {
            label: "test.numeric".into(),
            created: true,
            json_data: None,
            data: Some(Value::Map(BTreeMap::from([
                (Value::Text("bytes".into()), Value::Bytes(vec![1, 2, 3])),
                (
                    Value::Text("numbers".into()),
                    Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
                ),
            ]))),
        });
        let before = store.clone();
        let json: serde_json::Value = serde_json::from_str(&store.json()?)?;
        let label = store
            .active_manifest
            .as_ref()
            .ok_or("missing active label")?;
        let data = &json["manifests"][label]["assertions"]
            .as_array()
            .ok_or("missing assertions")?
            .last()
            .ok_or("missing numeric assertion")?["data"];
        assert_eq!(
            data,
            &serde_json::json!({"bytes": "AQID", "numbers": "AQI="})
        );
        assert_eq!(store, before);
        let ordinary = serde_json::to_value(&store)?;
        assert_eq!(
            ordinary["manifests"][label]["assertions"]
                .as_array()
                .ok_or("missing assertions")?
                .last()
                .ok_or("missing numeric assertion")?["data"]["bytes"],
            serde_json::json!([1, 2, 3])
        );
        store
            .manifests
            .values_mut()
            .next()
            .ok_or("missing manifest")?
            .assertions
            .last_mut()
            .ok_or("missing assertion")?
            .data = Some(Value::Map(BTreeMap::from([(
            Value::Integer(7),
            Value::Null,
        )])));
        assert!(
            store.json().is_err(),
            "invalid CBOR keys must not yield an empty successful report"
        );
        Ok(())
    }

    fn fixture_report() -> Result<ReadReport, Box<dyn std::error::Error>> {
        use contentauth_c2pa_reader::{ReadHostReply, ReadRequest, ReadSession, ReadSettings};
        use contentauth_state_machine::{Session, Step};
        let mut session = ReadSession::new(ReadSettings {
            check_ocsp: false,
            ..ReadSettings::default()
        });
        while session.advance()? == Step::AwaitHost {
            let pending = &session.outstanding_requests()[0];
            let reply = match &pending.kind {
                ReadRequest::ManifestStore { .. } => ReadHostReply::ManifestStore(Some(
                    include_bytes!(
                        "../../contentauth-c2pa-reader/tests/fixtures/manifest_data.c2pa"
                    )
                    .to_vec(),
                )),
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(1_780_000_000),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(0),
                other => return Err(format!("unexpected fixture request: {other:?}").into()),
            };
            session.fulfill(pending.id, reply)?;
        }
        Ok(session.finish()?)
    }

    fn status(
        template: &contentauth_c2pa_reader::ValidationStatus,
        code: &str,
        url: &str,
        explanation: &str,
    ) -> contentauth_c2pa_reader::ValidationStatus {
        let mut status = template.clone();
        status.code = code.into();
        status.url = Some(url.into());
        status.explanation = Some(explanation.into());
        status.trust_list_uri = None;
        status
    }

    #[test]
    fn every_observation_is_bucketed_once_and_only_failures_reach_the_legacy_summary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = fixture_report()?;
        let template = report.statuses[0].clone();
        let status = |code, url, explanation| status(&template, code, url, explanation);
        report.active_manifest = Some("active".into());
        report.validation_state = Some(Inner::Valid);
        let url = "self#jumbf=/c2pa/active/c2pa.signature";
        report.statuses = vec![
            status("claimSignature.validated", url, "core detail"),
            status("claimSignature.validated", url, "duplicate"),
            status(
                "signingCredential.ocsp.inaccessible",
                url,
                "network failed: offline",
            ),
            status("cawg.x509.credential.untrusted", url, "not anchored"),
            status("claimSignature.mismatch", url, "a broken signature"),
            status("future.observation", url, "unknown observation"),
        ];
        let store = ManifestStore::from_report(&report);
        let buckets = &store.validation_results.active_manifest;
        assert_eq!(store.validation_state, ValidationState::Valid);
        assert_eq!(buckets.success.len(), 3);
        assert_eq!(buckets.informational.len(), 1);
        assert_eq!(buckets.failure.len(), 2);
        assert_eq!(store.validation_status, buckets.failure);
        assert_eq!(
            buckets.informational[0].explanation.as_deref(),
            Some("network failed: offline")
        );
        assert_eq!(
            buckets.failure[0].explanation.as_deref(),
            Some("signing certificate untrusted")
        );
        assert_eq!(
            buckets.failure[1].explanation.as_deref(),
            Some("a broken signature")
        );
        assert!(buckets
            .success
            .iter()
            .any(|status| status.code == "future.observation"
                && status.explanation.as_deref() == Some("unknown observation")));
        Ok(())
    }

    #[test]
    fn identity_distrust_limits_compatibility_trust_without_changing_engine_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use contentauth_c2pa_reader::ValidationState as Inner;
        let mut report = fixture_report()?;
        report.validation_state = Some(Inner::Trusted);
        let template = report.statuses[0].clone();
        report.statuses = vec![status(
            &template,
            "cawg.x509.credential.untrusted",
            "self#jumbf=/c2pa/active/c2pa.assertions/cawg.identity",
            "not anchored",
        )];
        assert_eq!(
            ManifestStore::from_report(&report).validation_state,
            ValidationState::Valid
        );
        assert_eq!(report.validation_state, Some(Inner::Trusted));
        report.statuses.clear();
        assert_eq!(
            ManifestStore::from_report(&report).validation_state,
            ValidationState::Trusted
        );
        for state in [Inner::Valid, Inner::Invalid, Inner::Incomplete] {
            report.validation_state = Some(state);
            assert_eq!(
                ManifestStore::from_report(&report).validation_state,
                Some(state).into()
            );
        }
        Ok(())
    }

    #[test]
    fn active_results_do_not_absorb_other_manifests_or_identity_trust_list_provenance(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut report = fixture_report()?;
        let template = report.statuses[0].clone();
        let status = |code, url, explanation| status(&template, code, url, explanation);
        report.active_manifest = Some("active".into());
        let mut claim = status(
            "signingCredential.trusted",
            "self#jumbf=/c2pa/active/c2pa.signature",
            "anchored",
        );
        claim.trust_list_uri = Some("claim-list".into());
        let mut identity = status(
            "cawg.x509.credential.trusted",
            "self#jumbf=/c2pa/active/c2pa.assertions/cawg.identity",
            "anchored",
        );
        identity.trust_list_uri = Some("identity-list".into());
        let mut timestamp = status(
            "timeStamp.trusted",
            "self#jumbf=/c2pa/active/c2pa.signature",
            "anchored",
        );
        timestamp.trust_list_uri = Some("tsa-list".into());
        let mut ingredient = status(
            "signingCredential.trusted",
            "self#jumbf=/c2pa/ingredient/c2pa.signature",
            "anchored",
        );
        ingredient.trust_list_uri = Some("ingredient-list".into());
        report.statuses = vec![
            ingredient,
            identity,
            timestamp,
            claim,
            status(
                "claimSignature.mismatch",
                "self#jumbf=/c2pa/ingredient/c2pa.assertions/a",
                "ingredient failed",
            ),
        ];
        let store = ManifestStore::from_report(&report);
        assert_eq!(store.validation_status.len(), 1);
        assert_eq!(
            store.validation_status[0].explanation.as_deref(),
            Some("ingredient failed")
        );
        let results = &store.validation_results;
        assert_eq!(results.active_manifest.success.len(), 3);
        assert!(results.active_manifest.failure.is_empty());
        assert_eq!(results.trust_list_uri.as_deref(), Some("claim-list"));
        assert_eq!(
            results.timestamp_trust_list_uri.as_deref(),
            Some("tsa-list")
        );
        Ok(())
    }

    #[test]
    fn trusted_and_valid_map_straight_across() {
        assert_eq!(
            ValidationState::from(Some(Inner::Trusted)),
            ValidationState::Trusted
        );
        assert_eq!(
            ValidationState::from(Some(Inner::Valid)),
            ValidationState::Valid
        );
    }

    #[test]
    fn invalid_incomplete_and_no_outcome_at_all_fold_into_invalid() {
        assert_eq!(
            ValidationState::from(Some(Inner::Invalid)),
            ValidationState::Invalid
        );
        assert_eq!(
            ValidationState::from(Some(Inner::Incomplete)),
            ValidationState::Invalid
        );
        assert_eq!(ValidationState::from(None), ValidationState::Invalid);
    }

    /// The optional fields are omitted rather than serialized as `null`,
    /// matching c2pa-rs's own `skip_serializing_if` treatment of them.
    #[test]
    fn an_empty_store_serializes_to_the_minimal_shape() {
        let store = ManifestStore {
            active_manifest: None,
            manifests: BTreeMap::new(),
            validation_state: ValidationState::Invalid,
            validation_status: vec![],
            validation_results: ValidationResults {
                active_manifest: ValidationResultBuckets::default(),
                ingredient_deltas: vec![],
                spec_version: "2.4.0",
                trust_list_uri: None,
                timestamp_trust_list_uri: None,
            },
        };

        let json = serde_json::to_value(store).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            json,
            serde_json::json!({
                "manifests": {},
                "validation_state": "Invalid",
                "validation_results": {
                    "activeManifest": {
                        "success": [],
                        "informational": [],
                        "failure": [],
                    },
                    "specVersion": "2.4.0",
                },
            })
        );
    }

    #[test]
    fn a_manifest_omits_the_optional_fields_it_does_not_have() {
        let manifest = Manifest {
            label: "urn:uuid:x".to_string(),
            claim_generator: None,
            claim_generator_info: vec![],
            claim_version: ClaimVersion::V1,
            title: None,
            format: Some("image/jpeg".to_string()),
            instance_id: String::new(),
            thumbnail: None,
            signature_info: None,
            ingredients: vec![],
            assertions: vec![ManifestAssertion {
                label: "c2pa.hash.data".to_string(),
                created: false,
                data: None,
                json_data: None,
            }],
        };

        let json = serde_json::to_value(manifest).unwrap_or(serde_json::Value::Null);
        assert_eq!(
            json,
            serde_json::json!({
                "label": "urn:uuid:x",
                "claim_version": 1,
                "format": "image/jpeg",
                "instance_id": "",
                "assertions": [{ "label": "c2pa.hash.data" }],
            })
        );
    }

    #[test]
    fn assertion_cbor_bytes_serialize_as_json_arrays() {
        let assertion = ManifestAssertion {
            label: "cawg.identity".to_string(),
            created: false,
            json_data: None,
            data: Some(c2pa_cbor::Value::Bytes(vec![1, 2, 255])),
        };

        let json = serde_json::to_value(assertion).unwrap_or(serde_json::Value::Null);
        assert_eq!(json["data"], serde_json::json!([1, 2, 255]));
    }

    #[test]
    fn json_assertions_preserve_json_types_and_unsigned_numbers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::json!({
            "mixed": [null, true, -1, 1.25, "text", {"nested": []}],
            "large": u64::MAX,
        });
        let assertion = ManifestAssertion {
            label: "example.json".into(),
            created: true,
            data: None,
            json_data: Some(data.clone()),
        };
        assert_eq!(
            serde_json::to_value(assertion)?,
            serde_json::json!({
                "label": "example.json",
                "created": true,
                "data": data,
                "kind": "Json",
            })
        );
        Ok(())
    }

    #[test]
    fn assertion_cbor_with_non_text_map_keys_fails_serialization() {
        let assertion = ManifestAssertion {
            label: "custom.assertion".to_string(),
            created: false,
            json_data: None,
            data: Some(c2pa_cbor::Value::Map(BTreeMap::from([(
                c2pa_cbor::Value::Integer(1),
                c2pa_cbor::Value::Null,
            )]))),
        };

        assert!(serde_json::to_value(assertion).is_err());
    }

    #[test]
    fn unsigned_serials_are_decimal_without_a_machine_integer_limit() {
        for (bytes, expected) in [
            (vec![], "0"),
            (vec![0, 0], "0"),
            (vec![0, 128], "128"),
            (vec![255], "255"),
            (
                vec![255; 20],
                "1461501637330902918203684832716283019655932542975",
            ),
        ] {
            assert_eq!(decimal_serial(&bytes), expected);
        }
    }

    #[test]
    fn generator_extensions_keep_their_json_types() {
        let info = ClaimGeneratorInfo {
            name: Some("tool".into()),
            version: None,
            spec_version: None,
            icon: None,
            extensions: BTreeMap::from([
                (
                    "org.example.version".into(),
                    c2pa_cbor::Value::Text("1".into()),
                ),
                (
                    "org.example.flags".into(),
                    c2pa_cbor::Value::Array(vec![
                        c2pa_cbor::Value::Bool(true),
                        c2pa_cbor::Value::Integer(7),
                    ]),
                ),
            ]),
        };
        assert_eq!(
            serde_json::to_value(info).unwrap_or(serde_json::Value::Null),
            serde_json::json!({
                "name": "tool", "org.example.version": "1", "org.example.flags": [true, 7],
            })
        );
    }
}
