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

//! The one thing every independent assertion crate hands to the rest of
//! the system.

/// An assertion, encoded: its label, and its CBOR content.
///
/// This is the whole interface between a crate that *knows* an assertion's
/// structure (`contentauth-c2pa-assertion-data-hash`,
/// `contentauth-c2pa-assertion-actions`, …) and everything downstream of it
/// (JUMBF assembly, hashed-URI generation, the claim). Downstream code is
/// deliberately handed nothing but opaque CBOR bytes: it cannot depend on an
/// assertion's fields, so a new assertion type never touches it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EncodedAssertion {
    /// The assertion's label (for example, `"c2pa.actions.v2"`).
    pub label: String,

    /// The assertion's CBOR-encoded content, exactly as it will appear in
    /// the assertion's `cbor` JUMBF content box.
    pub cbor: Vec<u8>,
}

impl EncodedAssertion {
    /// Pairs a label with its already-encoded content.
    pub fn new(label: impl Into<String>, cbor: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            cbor,
        }
    }
}
