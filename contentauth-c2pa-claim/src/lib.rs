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

//! The C2PA v2 claim, and the signature over it, as a self-contained
//! element.
//!
//! The claim is the one structure that ties a manifest together, and it
//! can be built knowing almost nothing: it holds [`HashedUri`]s — a URL and
//! a digest each — and never the assertions themselves. This crate
//! therefore depends on no assertion crate, no JUMBF, no certificate or
//! key handling, and no I/O. Its inputs are plain data and its outputs are
//! bytes:
//!
//! * [`Claim::encode`] — the claim's CBOR.
//! * [`signature`] — the `COSE_Sign1` envelope around it: the protected
//!   header, the exact bytes to sign ([`signature::to_be_signed`]), and
//!   assembly of the finished signature box content
//!   ([`signature::assemble`]). The signing itself is the host's.
//!
//! # TODO: `instanceID` should match the asset's XMP
//!
//! The specification says that if the asset contains XMP, its
//! `xmpMM:InstanceID` *should* be used as the claim's `instanceID`
//! ("Claims", `instanceID`). This crate takes the value as given and cannot
//! check it — it never sees the asset — and neither does any caller in this
//! workspace yet, nor does Gavin Peacock's `c2pa-core` sample. Whoever
//! builds a claim over an asset with XMP (the format handlers know how to
//! find it) should read the instance ID from there and pass it in. See
//! `docs/walkthrough/09-future.md`.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod signature;

use std::collections::BTreeMap;

use c2pa_cbor::Value;
use contentauth_c2pa_primitives::{hashed_uri::signature_uri, HashAlgorithm, HashedUri};

/// The label of a v2 claim's box.
pub const LABEL: &str = "c2pa.claim.v2";

/// The specification version written as the generator's `specVersion`.
pub const SPEC_VERSION: &str = "2.4.0";

/// Why a claim or its signature could not be encoded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A v2 claim lists at least one created assertion.
    #[error("a claim needs at least one created assertion")]
    NoCreatedAssertions,

    /// The `instanceID` is empty.
    #[error("a claim needs an instanceID")]
    NoInstanceId,

    /// A signature was assembled with no certificates, or with the wrong
    /// length for its algorithm.
    #[error("{0}")]
    Signature(&'static str),

    /// The CBOR encoder failed.
    #[error(transparent)]
    Cbor(#[from] c2pa_cbor::Error),
}

/// The software that generated a claim (`generator-info-map`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratorInfo {
    /// Product name.
    pub name: String,

    /// Product version, if known.
    pub version: Option<String>,
}

impl GeneratorInfo {
    /// Names a generator.
    pub fn new(name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }
}

/// A C2PA v2 claim (`claim-map-v2`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    manifest_label: String,
    instance_id: String,
    generator: GeneratorInfo,
    alg: HashAlgorithm,
    title: Option<String>,
    created: Vec<HashedUri>,
    gathered: Vec<HashedUri>,
}

impl Claim {
    /// Starts a claim for the manifest labelled `manifest_label`.
    ///
    /// `alg` is the default algorithm for the claim's hashed URIs, written
    /// as the claim's `alg`. `instance_id` identifies this version of the
    /// asset; see the crate documentation's TODO about XMP.
    pub fn new(
        manifest_label: impl Into<String>,
        instance_id: impl Into<String>,
        generator: GeneratorInfo,
        alg: HashAlgorithm,
    ) -> Self {
        Self {
            manifest_label: manifest_label.into(),
            instance_id: instance_id.into(),
            generator,
            alg,
            title: None,
            created: Vec::new(),
            gathered: Vec::new(),
        }
    }

    /// Sets the human-readable asset title (`dc:title`).
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// References an assertion this claim's generator created.
    pub fn with_created(mut self, assertion: HashedUri) -> Self {
        self.created.push(assertion);
        self
    }

    /// References an assertion gathered from elsewhere.
    pub fn with_gathered(mut self, assertion: HashedUri) -> Self {
        self.gathered.push(assertion);
        self
    }

    /// Encodes the claim.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.created.is_empty() {
            return Err(Error::NoCreatedAssertions);
        }
        if self.instance_id.is_empty() {
            return Err(Error::NoInstanceId);
        }

        let text = |s: &str| Value::Text(s.to_string());
        let key = |s: &str| Value::Text(s.to_string());

        let mut generator = BTreeMap::from([(key("name"), text(&self.generator.name))]);
        if let Some(version) = &self.generator.version {
            generator.insert(key("version"), text(version));
        }
        generator.insert(key("specVersion"), text(SPEC_VERSION));

        let refs =
            |uris: &[HashedUri]| Value::Array(uris.iter().map(HashedUri::to_value).collect());

        let mut map = BTreeMap::new();
        if let Some(title) = &self.title {
            map.insert(key("dc:title"), text(title));
        }
        map.insert(key("instanceID"), text(&self.instance_id));
        map.insert(key("claim_generator_info"), Value::Map(generator));
        map.insert(key("signature"), text(&signature_uri(&self.manifest_label)));
        map.insert(key("alg"), text(self.alg.c2pa_name()));
        map.insert(key("created_assertions"), refs(&self.created));
        if !self.gathered.is_empty() {
            map.insert(key("gathered_assertions"), refs(&self.gathered));
        }

        Ok(c2pa_cbor::to_vec(&Value::Map(map))?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn claim() -> Claim {
        Claim::new(
            "urn:uuid:m",
            "xmp:iid:1",
            GeneratorInfo::new("test", Some("1.0".into())),
            HashAlgorithm::Sha256,
        )
        .with_title("A.jpg")
        .with_created(HashedUri::new(
            "self#jumbf=c2pa.assertions/a",
            None,
            vec![1; 32],
        ))
    }

    #[test]
    fn encodes_the_v2_shape() {
        let v: Value = c2pa_cbor::from_slice(&claim().encode().unwrap()).unwrap();
        let m = v.as_map().unwrap();
        let get = |k: &str| m.get(&Value::Text(k.into()));

        assert_eq!(get("instanceID"), Some(&Value::Text("xmp:iid:1".into())));
        assert_eq!(get("alg"), Some(&Value::Text("sha256".into())));
        assert_eq!(
            get("signature"),
            Some(&Value::Text(
                "self#jumbf=/c2pa/urn:uuid:m/c2pa.signature".into()
            ))
        );
        assert!(get("dc:format").is_none() && get("claim_generator").is_none());
        assert!(get("gathered_assertions").is_none());

        let Some(Value::Map(g)) = get("claim_generator_info") else {
            panic!("generator info must be a single map");
        };
        assert_eq!(
            g.get(&Value::Text("specVersion".into())),
            Some(&Value::Text("2.4.0".into()))
        );
    }

    #[test]
    fn gathered_assertions_appear_only_when_there_are_some() {
        let c = claim().with_gathered(HashedUri::new("u", None, vec![2; 32]));
        let v: Value = c2pa_cbor::from_slice(&c.encode().unwrap()).unwrap();
        assert!(v
            .as_map()
            .unwrap()
            .contains_key(&Value::Text("gathered_assertions".into())));
    }

    #[test]
    fn invalid_claims_are_refused() {
        let empty = Claim::new(
            "m",
            "iid",
            GeneratorInfo::new("t", None),
            HashAlgorithm::Sha256,
        );
        assert!(matches!(empty.encode(), Err(Error::NoCreatedAssertions)));
        let no_id = Claim::new(
            "m",
            "",
            GeneratorInfo::new("t", None),
            HashAlgorithm::Sha256,
        )
        .with_created(HashedUri::new("u", None, vec![]));
        assert!(matches!(no_id.encode(), Err(Error::NoInstanceId)));
    }
}
