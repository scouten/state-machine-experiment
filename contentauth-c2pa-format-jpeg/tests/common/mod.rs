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

//! Synthetic JPEGs and manifest stores for the integration tests.

#![allow(dead_code)]

/// A real JPEG signed by c2pa-rs 0.33.1, copied from that project's test
/// fixtures via `contentauth-c2pa-reader`'s. Its manifest store occupies
/// the single `APP11` segment at offset 20, 45,884 bytes long — the
/// exclusion its hard binding records.
pub const C_JPG: &[u8] = include_bytes!("../../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// The raw manifest store embedded in [`C_JPG`], as c2pa-rs's own
/// fixture set ships it.
pub const C_MANIFEST_STORE: &[u8] =
    include_bytes!("../../../contentauth-c2pa-reader/tests/fixtures/manifest_data.c2pa");

/// The type UUID of a C2PA manifest store superbox.
const MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// A marker segment with a length field.
pub fn segment(marker: u8, contents: &[u8]) -> Vec<u8> {
    let le = u16::try_from(contents.len() + 2).unwrap();
    let mut bytes = vec![0xff, marker];
    bytes.extend_from_slice(&le.to_be_bytes());
    bytes.extend_from_slice(contents);
    bytes
}

/// A JUMBF `APP11` segment.
pub fn app11(en: [u8; 2], z: u32, payload: &[u8]) -> Vec<u8> {
    let mut contents = b"JP".to_vec();
    contents.extend_from_slice(&en);
    contents.extend_from_slice(&z.to_be_bytes());
    contents.extend_from_slice(payload);
    segment(0xeb, &contents)
}

/// A plausible manifest store of `len` bytes: a real superbox and
/// description-box header naming it a C2PA store, then a non-repeating
/// fill so a misplaced byte is caught.
pub fn store(len: usize) -> Vec<u8> {
    assert!(len >= 32);
    let mut store = (len as u32).to_be_bytes().to_vec();
    store.extend_from_slice(b"jumb");
    store.extend_from_slice(&[0, 0, 0, 0x1e]);
    store.extend_from_slice(b"jumd");
    store.extend_from_slice(&MANIFEST_STORE_UUID);
    store.extend((32..len).map(|i| (i % 251) as u8));
    store
}

/// An unsigned JPEG: `SOI`, optionally `APP0` (JFIF) and `APP1` (Exif),
/// `DQT`, `SOF0`, `SOS`, a little scan data, `EOI`. Structurally a JPEG
/// as far as marker parsing goes; no decoder would love it.
pub fn unsigned_jpeg(with_app0: bool, with_app1: bool) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8];
    if with_app0 {
        bytes.extend(segment(0xe0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
    }
    if with_app1 {
        bytes.extend(segment(0xe1, b"Exif\0\0MM\0\x2a\0\0\0\x08\0\0"));
    }
    bytes.extend(segment(0xdb, &[0u8; 65]));
    bytes.extend(segment(0xc0, &[8, 0, 8, 0, 8, 1, 1, 0x11, 0]));
    bytes.extend(segment(0xda, &[1, 1, 0, 0, 0x3f, 0]));
    bytes.extend_from_slice(&[0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56, 0x78]);
    bytes.extend_from_slice(&[0xff, 0xd9]);
    bytes
}

/// The offset right after the `APP0` segment in [`unsigned_jpeg`].
pub const AFTER_APP0: u64 = 20;
