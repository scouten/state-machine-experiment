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

//! Hashed URIs: the reference one part of a manifest makes to another.
//!
//! A claim does not contain its assertions; it contains a [`HashedUri`] for
//! each — a JUMBF URI saying where the assertion is, and a digest of what
//! it contained when the claim was made. A CAWG identity assertion does the
//! same to the assertions it vouches for; an ingredient does the same to a
//! parent manifest's claim. They are all the one CDDL type (`hashed-uri`),
//! so they are all one Rust type, here, with no knowledge of what is being
//! referenced.
//!
//! # What is hashed
//!
//! The digest covers the *contents* of the referenced JUMBF box: the bytes
//! after the box's own length/type header (8 bytes, or 16 when it carries
//! an extended length). For an assertion that is its description box and
//! its `cbor` content box, but not the `LBox`/`TBox` that frame the
//! superbox. [`HashedUri::from_box`] takes the whole rendered box and
//! strips the header itself, so no caller can hash the wrong span.
//!
//! This crate reads no JUMBF beyond that header, builds none, and does no
//! I/O: it is a digest and a CBOR map.
//!
//! # URIs
//!
//! [`assertion_uri`] and friends build the URI forms a manifest uses;
//! they take the manifest's label where the spec requires an absolute URI.

use std::collections::BTreeMap;

use c2pa_cbor::Value;

use crate::types::HashAlgorithm;

/// Why a hashed URI could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes handed to [`HashedUri::from_box`] are not a JUMBF box:
    /// shorter than a box header, or with a length field that disagrees
    /// with the bytes.
    #[error("not a complete JUMBF box: {0}")]
    NotABox(&'static str),

    /// The CBOR encoder failed.
    #[error(transparent)]
    Cbor(#[from] c2pa_cbor::Error),
}

/// The URI of an assertion in the manifest that contains the reference,
/// in the relative form claims use: `self#jumbf=c2pa.assertions/<label>`.
pub fn assertion_uri(label: &str) -> String {
    format!("self#jumbf=c2pa.assertions/{label}")
}

/// The absolute URI of an assertion in the manifest labelled
/// `manifest_label`: `self#jumbf=/c2pa/<manifest>/c2pa.assertions/<label>`.
/// What a reference from *outside* the manifest (a CAWG identity
/// assertion, an ingredient) must use.
pub fn absolute_assertion_uri(manifest_label: &str, label: &str) -> String {
    format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}")
}

/// The absolute URI of a manifest's claim signature, which a claim's
/// `signature` field "shall" carry (C2PA 2.x, "Claims").
pub fn signature_uri(manifest_label: &str) -> String {
    format!("self#jumbf=/c2pa/{manifest_label}/c2pa.signature")
}

/// A reference to a JUMBF box: where it is, and what it contained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashedUri {
    url: String,
    alg: Option<HashAlgorithm>,
    hash: Vec<u8>,
}

impl HashedUri {
    /// Names a digest already computed. `alg` is `None` when the
    /// enclosing structure (a claim's top-level `alg`) supplies it.
    pub fn new(url: impl Into<String>, alg: Option<HashAlgorithm>, hash: Vec<u8>) -> Self {
        Self {
            url: url.into(),
            alg,
            hash,
        }
    }

    /// References `rendered_box` — the complete, framed bytes of a JUMBF
    /// box, header included — hashing its contents under `alg`.
    ///
    /// `record_alg` says whether the algorithm is written into the
    /// reference (`true`), or left for the enclosing claim's `alg` to
    /// supply (`false`; what c2pa-rs and this workspace's builder do).
    pub fn from_box(
        url: impl Into<String>,
        alg: HashAlgorithm,
        record_alg: bool,
        rendered_box: &[u8],
    ) -> Result<Self, Error> {
        let contents = box_contents(rendered_box)?;
        Ok(Self::new(
            url,
            record_alg.then_some(alg),
            alg.digest(contents),
        ))
    }

    /// The JUMBF URI referenced.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The algorithm written into the reference, if any.
    pub fn alg(&self) -> Option<HashAlgorithm> {
        self.alg
    }

    /// The digest of the referenced box's contents.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// The `hashed-uri` CBOR map, as a value to embed in a larger
    /// structure (a claim's `created_assertions` array, say).
    pub fn to_value(&self) -> Value {
        let mut map = BTreeMap::new();
        map.insert(Value::Text("url".into()), Value::Text(self.url.clone()));
        if let Some(alg) = self.alg {
            map.insert(
                Value::Text("alg".into()),
                Value::Text(alg.c2pa_name().into()),
            );
        }
        map.insert(Value::Text("hash".into()), Value::Bytes(self.hash.clone()));
        Value::Map(map)
    }

    /// The `hashed-uri` map as standalone CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        Ok(c2pa_cbor::to_vec(&self.to_value())?)
    }
}

/// The contents of a JUMBF box: everything after its `LBox`/`TBox` header.
fn box_contents(rendered: &[u8]) -> Result<&[u8], Error> {
    let header = rendered
        .get(..8)
        .ok_or(Error::NotABox("shorter than a box header"))?;
    let lbox = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);

    let (header_len, total) = match lbox {
        // Extends to the end of the data.
        0 => (8usize, rendered.len() as u64),
        // `XLBox` follows the type.
        1 => {
            let x = rendered
                .get(8..16)
                .ok_or(Error::NotABox("extended length is truncated"))?;
            let mut be = [0u8; 8];
            be.copy_from_slice(x);
            (16usize, u64::from_be_bytes(be))
        }
        n => (8usize, u64::from(n)),
    };

    if total != rendered.len() as u64 || total < header_len as u64 {
        return Err(Error::NotABox("length field disagrees with the bytes"));
    }
    Ok(&rendered[header_len..])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b"jumb");
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn hashes_the_contents_not_the_header() {
        let bytes = framed(b"payload");
        let uri = HashedUri::from_box(assertion_uri("a.b"), HashAlgorithm::Sha256, false, &bytes)
            .unwrap();
        assert_eq!(uri.hash(), HashAlgorithm::Sha256.digest(b"payload"));
        assert_eq!(uri.url(), "self#jumbf=c2pa.assertions/a.b");
        assert_eq!(uri.alg(), None);
    }

    #[test]
    fn extended_length_boxes_are_unframed_too() {
        let mut v = 1u32.to_be_bytes().to_vec();
        v.extend_from_slice(b"jumb");
        v.extend_from_slice(&(16u64 + 3).to_be_bytes());
        v.extend_from_slice(b"abc");
        let uri = HashedUri::from_box("u", HashAlgorithm::Sha384, true, &v).unwrap();
        assert_eq!(uri.hash(), HashAlgorithm::Sha384.digest(b"abc"));
        assert_eq!(uri.alg(), Some(HashAlgorithm::Sha384));
    }

    #[test]
    fn rejects_things_that_are_not_boxes() {
        assert!(HashedUri::from_box("u", HashAlgorithm::Sha256, false, b"abc").is_err());
        let mut bad = framed(b"xyz");
        bad.push(0);
        assert!(HashedUri::from_box("u", HashAlgorithm::Sha256, false, &bad).is_err());
    }

    #[test]
    fn encodes_the_cddl_map() {
        let uri = HashedUri::new("self#jumbf=x", Some(HashAlgorithm::Sha256), vec![7; 32]);
        let decoded: Value = c2pa_cbor::from_slice(&uri.to_cbor().unwrap()).unwrap();
        let map = decoded.as_map().unwrap();
        assert_eq!(
            map.get(&Value::Text("alg".into())),
            Some(&Value::Text("sha256".into()))
        );
        assert_eq!(
            map.get(&Value::Text("hash".into())),
            Some(&Value::Bytes(vec![7; 32]))
        );
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn uri_forms() {
        assert_eq!(
            absolute_assertion_uri("urn:m", "a"),
            "self#jumbf=/c2pa/urn:m/c2pa.assertions/a"
        );
        assert_eq!(
            signature_uri("urn:m"),
            "self#jumbf=/c2pa/urn:m/c2pa.signature"
        );
    }
}
