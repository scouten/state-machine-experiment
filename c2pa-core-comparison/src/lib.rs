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

//! One logical manifest store, assembled and walked two ways.
//!
//! * `c2pa-store` — Gavin Peacock's hand-coded JUMBF (`c2pa-core`): a
//!   streaming, seek-and-backpatch writer that hashes each assertion as it
//!   writes it, and a zero-copy, `no_std` parser.
//! * `jumbf` — the crate this workspace uses: a builder that renders boxes
//!   from owned or borrowed children, and a parser that builds a tree.
//!
//! Nothing here is specific to either: a [`Scenario`] is just labelled
//! CBOR-box payloads plus a claim and a signature, and every function
//! returns something the others can be checked against.

pub mod alloc_count;

use std::io::Cursor;

use jumbf::{
    builder::{DataBoxBuilder, SuperBoxBuilder},
    BoxType,
};
use sha2::{Digest, Sha256};

/// One manifest's worth of content, independent of any JUMBF library.
pub struct Scenario {
    /// A short name for reports.
    pub name: &'static str,

    /// The manifest's label.
    pub manifest_label: String,

    /// `(label, cbor payload)` per assertion, in order.
    pub assertions: Vec<(String, Vec<u8>)>,

    /// The claim's CBOR.
    pub claim: Vec<u8>,

    /// The claim signature's CBOR.
    pub signature: Vec<u8>,
}

impl Scenario {
    /// `count` assertions of `size` bytes each, a 400-byte claim and a
    /// 3 KiB signature (about what a two-certificate chain costs).
    pub fn new(name: &'static str, count: usize, size: usize) -> Self {
        let fill = |seed: usize, n: usize| -> Vec<u8> {
            (0..n).map(|i| ((i * 31 + seed * 7) % 251) as u8).collect()
        };
        Self {
            name,
            manifest_label: "urn:uuid:00000000-0000-4000-8000-000000000000".into(),
            assertions: (0..count)
                .map(|i| (format!("test.assertion.{i}"), fill(i, size)))
                .collect(),
            claim: fill(1000, 400),
            signature: fill(2000, 3072),
        }
    }

    /// Total bytes of assertion payload.
    pub fn payload_bytes(&self) -> usize {
        self.assertions.iter().map(|(_, d)| d.len()).sum()
    }
}

/// What a walk of a parsed store found; equal across parsers on equal input.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Summary {
    pub assertions: usize,
    pub label_bytes: usize,
    pub payload_bytes: usize,
    pub payload_checksum: u64,
    pub claim_len: usize,
    pub signature_len: usize,
}

fn checksum(bytes: &[u8]) -> u64 {
    // Touch every byte, so a parser that merely points at the payload and a
    // parser that copied it are charged the same for reading it.
    bytes
        .iter()
        .fold(0u64, |acc, &b| acc.rotate_left(5) ^ u64::from(b))
}

// ---------------------------------------------------------------------
// c2pa-store
// ---------------------------------------------------------------------

/// Writes the store with `c2pa-store`, which hashes each assertion as it
/// goes. Returns the bytes and the assertion digests.
pub fn write_c2pa_store(s: &Scenario) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut b =
        c2pa_store::ManifestStoreBuilder::new(Vec::<u8>::new(), &s.manifest_label).expect("start");
    let mut hashes = Vec::with_capacity(s.assertions.len());
    for (label, data) in &s.assertions {
        hashes.push(
            b.add_cbor_assertion(label, None, data)
                .expect("assertion")
                .hash,
        );
    }
    b.add_claim("c2pa.claim.v2", &s.claim).expect("claim");
    b.add_signature(&s.signature).expect("signature");
    (b.finish().expect("finish"), hashes)
}

/// Walks a store with `c2pa-store`'s zero-copy parser.
pub fn walk_c2pa_store(bytes: &[u8]) -> Summary {
    let store = c2pa_store::ManifestStore::parse(bytes).expect("parse");
    let m = store.active_manifest().expect("manifest");
    let mut out = Summary::default();
    for a in m.assertions().expect("assertions") {
        out.assertions += 1;
        out.label_bytes += a.label().map_or(0, str::len);
        let p = a.payload().expect("payload").data;
        out.payload_bytes += p.len();
        out.payload_checksum ^= checksum(p);
    }
    out.claim_len = m.claim_cbor().expect("claim").len();
    out.signature_len = m.signature_cose().expect("sig").len();
    out
}

// ---------------------------------------------------------------------
// jumbf
// ---------------------------------------------------------------------

const fn uuid(fourcc: [u8; 4]) -> [u8; 16] {
    [
        fourcc[0], fourcc[1], fourcc[2], fourcc[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa,
        0x00, 0x38, 0x9b, 0x71,
    ]
}
const STORE: [u8; 16] = uuid(*b"c2pa");
const MANIFEST: [u8; 16] = uuid(*b"c2ma");
const ASSERTIONS: [u8; 16] = uuid(*b"c2as");
const CBOR_UUID: [u8; 16] = uuid(*b"cbor");
const CLAIM: [u8; 16] = uuid(*b"c2cl");
const SIGNATURE: [u8; 16] = uuid(*b"c2cs");
const CBOR: BoxType = BoxType(*b"cbor");

fn render(b: &SuperBoxBuilder<'_>) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    b.write_jumbf(&mut out).expect("render");
    out.into_inner()
}

/// Assembles the store with `jumbf`, **as `contentauth-c2pa-sidecar-builder`
/// does**: each assertion rendered once to hash it (the digest covers the
/// rendered box), then the whole store rendered, children owned (copied).
pub fn write_jumbf_as_sidecar_builder_does(s: &Scenario) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut hashes = Vec::with_capacity(s.assertions.len());
    for (label, data) in &s.assertions {
        let one = SuperBoxBuilder::new(&CBOR_UUID)
            .set_label(label)
            .add_child_box(DataBoxBuilder::from_owned(CBOR, data.clone()));
        let rendered = render(&one);
        hashes.push(Sha256::digest(&rendered[8..]).to_vec());
    }
    (write_jumbf_owned(s), hashes)
}

/// Assembles the store with `jumbf`, rendering each assertion **once**:
/// the rendered box is hashed, then spliced into the store as a raw `jumb`
/// box (its bytes after the header, borrowed). Byte-identical to the others.
pub fn write_jumbf_render_once(s: &Scenario) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut rendered = Vec::with_capacity(s.assertions.len());
    let mut hashes = Vec::with_capacity(s.assertions.len());
    for (label, data) in &s.assertions {
        let content = DataBoxBuilder::from_borrowed(CBOR, data);
        let one = SuperBoxBuilder::new(&CBOR_UUID)
            .set_label(label)
            .add_borrowed_child_box(&content);
        let bytes = render(&one);
        hashes.push(Sha256::digest(&bytes[8..]).to_vec());
        rendered.push(bytes);
    }

    let spliced: Vec<DataBoxBuilder<'_>> = rendered
        .iter()
        .map(|b| DataBoxBuilder::from_borrowed(BoxType(*b"jumb"), &b[8..]))
        .collect();
    let mut assertions = SuperBoxBuilder::new(&ASSERTIONS).set_label("c2pa.assertions");
    for b in &spliced {
        assertions = assertions.add_borrowed_child_box(b);
    }
    let claim_data = DataBoxBuilder::from_borrowed(CBOR, &s.claim);
    let claim = SuperBoxBuilder::new(&CLAIM)
        .set_label("c2pa.claim.v2")
        .add_borrowed_child_box(&claim_data);
    let sig_data = DataBoxBuilder::from_borrowed(CBOR, &s.signature);
    let signature = SuperBoxBuilder::new(&SIGNATURE)
        .set_label("c2pa.signature")
        .add_borrowed_child_box(&sig_data);
    let manifest = SuperBoxBuilder::new(&MANIFEST)
        .set_label(&s.manifest_label)
        .add_borrowed_child_box(&assertions)
        .add_borrowed_child_box(&claim)
        .add_borrowed_child_box(&signature);
    let store = render(
        &SuperBoxBuilder::new(&STORE)
            .set_label("c2pa")
            .add_borrowed_child_box(&manifest),
    );
    (store, hashes)
}

/// Whole-store assembly with owned children and no hashing.
pub fn write_jumbf_owned(s: &Scenario) -> Vec<u8> {
    let mut assertions = SuperBoxBuilder::new(&ASSERTIONS).set_label("c2pa.assertions");
    for (label, data) in &s.assertions {
        assertions = assertions.add_child_box(
            SuperBoxBuilder::new(&CBOR_UUID)
                .set_label(label)
                .add_child_box(DataBoxBuilder::from_owned(CBOR, data.clone())),
        );
    }
    let claim = SuperBoxBuilder::new(&CLAIM)
        .set_label("c2pa.claim.v2")
        .add_child_box(DataBoxBuilder::from_owned(CBOR, s.claim.clone()));
    let signature = SuperBoxBuilder::new(&SIGNATURE)
        .set_label("c2pa.signature")
        .add_child_box(DataBoxBuilder::from_owned(CBOR, s.signature.clone()));
    let manifest = SuperBoxBuilder::new(&MANIFEST)
        .set_label(&s.manifest_label)
        .add_child_box(assertions)
        .add_child_box(claim)
        .add_child_box(signature);
    render(
        &SuperBoxBuilder::new(&STORE)
            .set_label("c2pa")
            .add_child_box(manifest),
    )
}

/// Whole-store assembly with children borrowed (no copy of any payload into
/// the builder) and no hashing: the best case for `jumbf`'s builder.
pub fn write_jumbf_borrowed(s: &Scenario) -> Vec<u8> {
    let datas: Vec<DataBoxBuilder<'_>> = s
        .assertions
        .iter()
        .map(|(_, d)| DataBoxBuilder::from_borrowed(CBOR, d))
        .collect();
    let boxes: Vec<SuperBoxBuilder<'_>> = s
        .assertions
        .iter()
        .zip(&datas)
        .map(|((label, _), d)| {
            SuperBoxBuilder::new(&CBOR_UUID)
                .set_label(label)
                .add_borrowed_child_box(d)
        })
        .collect();
    let mut assertions = SuperBoxBuilder::new(&ASSERTIONS).set_label("c2pa.assertions");
    for b in &boxes {
        assertions = assertions.add_borrowed_child_box(b);
    }
    let claim_data = DataBoxBuilder::from_borrowed(CBOR, &s.claim);
    let claim = SuperBoxBuilder::new(&CLAIM)
        .set_label("c2pa.claim.v2")
        .add_borrowed_child_box(&claim_data);
    let sig_data = DataBoxBuilder::from_borrowed(CBOR, &s.signature);
    let signature = SuperBoxBuilder::new(&SIGNATURE)
        .set_label("c2pa.signature")
        .add_borrowed_child_box(&sig_data);
    let manifest = SuperBoxBuilder::new(&MANIFEST)
        .set_label(&s.manifest_label)
        .add_borrowed_child_box(&assertions)
        .add_borrowed_child_box(&claim)
        .add_borrowed_child_box(&signature);
    render(
        &SuperBoxBuilder::new(&STORE)
            .set_label("c2pa")
            .add_borrowed_child_box(&manifest),
    )
}

fn payload<'a>(sb: &'a jumbf::parser::SuperBox<'a>) -> &'a [u8] {
    sb.child_boxes
        .iter()
        .find_map(|c| c.as_data_box())
        .map(|d| d.data)
        .expect("cbor box")
}

/// Walks a store with the `jumbf` crate's parser.
pub fn walk_jumbf(bytes: &[u8]) -> Summary {
    let (store, _) = jumbf::parser::SuperBox::from_slice(bytes).expect("parse");
    let manifest = store
        .child_boxes
        .iter()
        .find_map(|c| c.as_super_box())
        .expect("manifest");
    let mut out = Summary::default();
    for child in &manifest.child_boxes {
        let Some(sb) = child.as_super_box() else {
            continue;
        };
        match sb.desc.label {
            Some("c2pa.assertions") => {
                for a in &sb.child_boxes {
                    let Some(a) = a.as_super_box() else { continue };
                    out.assertions += 1;
                    out.label_bytes += a.desc.label.map_or(0, str::len);
                    let p = payload(a);
                    out.payload_bytes += p.len();
                    out.payload_checksum ^= checksum(p);
                }
            }
            Some("c2pa.claim.v2") => out.claim_len = payload(sb).len(),
            Some("c2pa.signature") => out.signature_len = payload(sb).len(),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_parsers_agree_on_both_writers_output() {
        let s = Scenario::new("t", 5, 300);
        let (a, _) = write_c2pa_store(&s);
        let (b, _) = write_jumbf_as_sidecar_builder_does(&s);
        let expected = Summary {
            assertions: 5,
            label_bytes: s.assertions.iter().map(|(l, _)| l.len()).sum(),
            payload_bytes: 1500,
            payload_checksum: s.assertions.iter().fold(0, |acc, (_, d)| acc ^ checksum(d)),
            claim_len: 400,
            signature_len: 3072,
        };
        for bytes in [&a, &b] {
            assert_eq!(walk_c2pa_store(bytes), expected);
            assert_eq!(walk_jumbf(bytes), expected);
        }
    }

    #[test]
    fn owned_and_borrowed_jumbf_assembly_are_identical() {
        let s = Scenario::new("t", 7, 129);
        assert_eq!(write_jumbf_owned(&s), write_jumbf_borrowed(&s));
    }

    #[test]
    fn rendering_once_and_splicing_is_byte_identical() {
        let s = Scenario::new("t", 6, 211);
        assert_eq!(write_jumbf_render_once(&s).0, write_c2pa_store(&s).0);
        assert_eq!(write_jumbf_render_once(&s).1, write_c2pa_store(&s).1);
    }

    #[test]
    fn the_assertion_digests_agree() {
        let s = Scenario::new("t", 4, 77);
        assert_eq!(
            write_c2pa_store(&s).1,
            write_jumbf_as_sidecar_builder_does(&s).1
        );
    }

    /// The question the report leads with: do the two writers emit the same
    /// bytes? (If not, the test says where they first differ.)
    #[test]
    fn the_two_writers_emit_the_same_bytes() {
        let s = Scenario::new("t", 3, 50);
        let (a, _) = write_c2pa_store(&s);
        let b = write_jumbf_owned(&s);
        let first_diff = a.iter().zip(&b).position(|(x, y)| x != y);
        assert_eq!((a.len(), b.len(), first_diff), (b.len(), b.len(), None));
    }
}
