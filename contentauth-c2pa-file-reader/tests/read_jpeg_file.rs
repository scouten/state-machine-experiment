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

//! Reads a real, on-disk JPEG file — not bytes embedded at compile time via
//! `include_bytes!` — proving `read_manifest_from_file` actually performs
//! file I/O rather than assuming its caller already has the asset in
//! memory. A companion test proves the lower-level `read_manifest` works
//! just as well over an in-memory `Read + Seek` source, for a caller that
//! already has the asset loaded.

#![allow(clippy::unwrap_used)]

use std::io::Cursor;

use contentauth_c2pa_file_reader::{read_manifest, read_manifest_from_file, ReadSettings};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_reader::{ByteRange, ValidationState};

/// `contentauth-c2pa-reader`'s own fixture: a real JPEG signed by c2pa-rs
/// 0.33.1, with its manifest store at a single `APP11` run.
const C_JPG_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../contentauth-c2pa-reader/tests/fixtures/C.jpg"
);

/// The same bytes as [`C_JPG_PATH`], embedded at compile time for the
/// in-memory `Cursor` test.
const C_JPG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// The intermediate CA that issued the fixture's claim signer.
const FIXTURE_ISSUER: &[u8] =
    include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/signer-issuer.der");

#[test]
fn reads_a_real_jpeg_file_from_disk() {
    let report = read_manifest_from_file(
        &JpegFormat,
        C_JPG_PATH,
        ReadSettings {
            trust_anchors: vec![FIXTURE_ISSUER.to_vec()],
            ..ReadSettings::default()
        },
    )
    .expect("C.jpg should read cleanly from disk");

    assert!(report.manifest_store_found);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));

    let active = report.active().expect("fixture has an active manifest");
    assert_eq!(
        active.label,
        "contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3"
    );
    assert_eq!(
        active.data_hash.as_ref().unwrap().exclusions,
        [ByteRange {
            start: 20,
            len: 45884
        }]
    );
}

#[test]
fn reads_the_same_jpeg_from_an_in_memory_cursor() {
    let report = read_manifest(
        &JpegFormat,
        Cursor::new(C_JPG),
        ReadSettings {
            trust_anchors: vec![FIXTURE_ISSUER.to_vec()],
            ..ReadSettings::default()
        },
    )
    .expect("C.jpg should read cleanly from an in-memory cursor");

    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn a_nonexistent_file_is_reported_as_an_io_error() {
    let err = read_manifest_from_file(
        &JpegFormat,
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/no-such-file.jpg"),
        ReadSettings::default(),
    )
    .expect_err("a missing file cannot be read");

    assert!(matches!(
        err,
        contentauth_c2pa_file_reader::Error::Io { .. }
    ));
}
