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

//! The JUMBF structure of a manifest store, assembled with the `jumbf`
//! crate. This is the only module that knows any JUMBF; everything above
//! it handles opaque CBOR and byte strings.

use std::io::Cursor;

use jumbf::{
    builder::{DataBoxBuilder, SuperBoxBuilder},
    BoxType,
};

use crate::Error;

/// Builds a JUMBF type UUID from its four-character code.
const fn type_uuid(fourcc: [u8; 4]) -> [u8; 16] {
    [
        fourcc[0], fourcc[1], fourcc[2], fourcc[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa,
        0x00, 0x38, 0x9b, 0x71,
    ]
}

const MANIFEST_STORE_UUID: [u8; 16] = type_uuid(*b"c2pa");
const MANIFEST_UUID: [u8; 16] = type_uuid(*b"c2ma");
const ASSERTIONS_UUID: [u8; 16] = type_uuid(*b"c2as");
const ASSERTION_UUID: [u8; 16] = type_uuid(*b"cbor");
const CLAIM_UUID: [u8; 16] = type_uuid(*b"c2cl");
const SIGNATURE_UUID: [u8; 16] = type_uuid(*b"c2cs");

const CBOR_BOX_TYPE: BoxType = BoxType(*b"cbor");

fn render(sbox: &SuperBoxBuilder<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Cursor::new(Vec::new());
    sbox.write_jumbf(&mut out)?;
    Ok(out.into_inner())
}

/// Renders one assertion as a complete, framed superbox. The bytes are
/// both what goes into the store and what its hashed URI is computed over.
pub(crate) fn assertion_box(label: &str, cbor: &[u8]) -> Result<Vec<u8>, Error> {
    let content = DataBoxBuilder::from_borrowed(CBOR_BOX_TYPE, cbor);
    render(
        &SuperBoxBuilder::new(&ASSERTION_UUID)
            .set_label(label)
            .add_borrowed_child_box(&content),
    )
}

/// Assembles the manifest store: one manifest holding the assertions, the
/// claim, and the claim signature.
///
/// `assertion_boxes` are the complete boxes [`assertion_box`] rendered —
/// the very bytes the hashed URIs were computed over. They are spliced in
/// as raw `jumb` boxes (their contents after the 8-byte header, borrowed)
/// rather than rebuilt, so each assertion is rendered once and the bytes
/// that were hashed are, by construction, the bytes stored. Measured
/// against rendering twice in `c2pa-core-comparison`: about a third less
/// time and 40% less allocation.
pub(crate) fn manifest_store(
    manifest_label: &str,
    assertion_boxes: &[Vec<u8>],
    claim_cbor: &[u8],
    signature_cbor: &[u8],
) -> Result<Vec<u8>, Error> {
    let spliced: Vec<DataBoxBuilder<'_>> = assertion_boxes
        .iter()
        .map(|b| DataBoxBuilder::from_borrowed(BoxType(*b"jumb"), b.get(8..).unwrap_or_default()))
        .collect();
    let mut assertion_store = SuperBoxBuilder::new(&ASSERTIONS_UUID).set_label("c2pa.assertions");
    for b in &spliced {
        assertion_store = assertion_store.add_borrowed_child_box(b);
    }

    let claim_data = DataBoxBuilder::from_borrowed(CBOR_BOX_TYPE, claim_cbor);
    let claim = SuperBoxBuilder::new(&CLAIM_UUID)
        .set_label(contentauth_c2pa_claim::LABEL)
        .add_borrowed_child_box(&claim_data);
    let signature_data = DataBoxBuilder::from_borrowed(CBOR_BOX_TYPE, signature_cbor);
    let signature = SuperBoxBuilder::new(&SIGNATURE_UUID)
        .set_label("c2pa.signature")
        .add_borrowed_child_box(&signature_data);

    let manifest = SuperBoxBuilder::new(&MANIFEST_UUID)
        .set_label(manifest_label)
        .add_borrowed_child_box(&assertion_store)
        .add_borrowed_child_box(&claim)
        .add_borrowed_child_box(&signature);

    render(
        &SuperBoxBuilder::new(&MANIFEST_STORE_UUID)
            .set_label("c2pa")
            .add_borrowed_child_box(&manifest),
    )
}
