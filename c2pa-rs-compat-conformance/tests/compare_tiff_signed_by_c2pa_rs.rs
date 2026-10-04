// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Interoperability for a second container format, in the direction that
//! matters most: a TIFF signed by the *real* c2pa-rs, read by this
//! workspace's TIFF handler (through `contentauth-c2pa-rs-compat`).
//!
//! c2pa-rs's own TIFF writer lays the store out differently from
//! `contentauth-c2pa-format-tiff` — for a single-page file it clones the
//! first IFD and adds the C2PA entry to it, among the others — so this is
//! the test of whether the handler's *reading* is the specification's and
//! not merely its own writer's.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::path::PathBuf;

use c2pa_rs_compat_conformance::read_and_summarize;

const SIGNER_PEM: &[u8] = include_bytes!("fixtures/test-signer.pem");
const SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

fn path(name: &str) -> PathBuf {
    [env!("CARGO_TARGET_TMPDIR"), name].iter().collect()
}

/// A little-endian TIFF with one IFD and an `ImageWidth`, `ImageLength`,
/// and a strip of pixels the strip entries point at.
fn tiff() -> Vec<u8> {
    let mut out = b"II\x2a\0\x08\0\0\0".to_vec();
    out.extend([4, 0]);
    out.extend([0, 1, 3, 0, 1, 0, 0, 0, 2, 0, 0, 0]); // ImageWidth 2
    out.extend([1, 1, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0]); // ImageLength 1
    out.extend([0x11, 1, 4, 0, 1, 0, 0, 0, 62, 0, 0, 0]); // StripOffsets
    out.extend([0x17, 1, 4, 0, 1, 0, 0, 0, 2, 0, 0, 0]); // StripByteCounts
    out.extend([0, 0, 0, 0]);
    out.extend([0x7f, 0x80]);
    out
}

fn sign_with_c2pa_rs(name: &str) -> PathBuf {
    let source = path(&format!("{name}_unsigned.tif"));
    let dest = path(&format!("{name}_signed.tif"));
    std::fs::write(&source, tiff()).unwrap();
    let _ = std::fs::remove_file(&dest);

    let signer =
        c2pa::create_signer::from_keys(SIGNER_PEM, SIGNER_KEY, c2pa::SigningAlg::Es256, None)
            .expect("c2pa-rs accepts the test signer");
    // The test signer is untrusted, which c2pa-rs's verify-after-sign would
    // refuse; the question here is only what lands in the file.
    let context = c2pa::Context::new()
        .with_settings(r#"{"verify": {"verify_after_sign": false}}"#)
        .unwrap();
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(
            r#"{
              "title": "tiff",
              "assertions": [{
                "label": "c2pa.actions.v2",
                "data": {"actions": [{
                  "action": "c2pa.created",
                  "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                }]}
              }]
            }"#,
        )
        .unwrap();
    builder
        .sign_file(signer.as_ref(), &source, &dest)
        .expect("c2pa-rs signs a TIFF");
    dest
}

#[test]
fn the_tiff_handler_reads_a_store_c2pa_rs_wrote() {
    let signed = sign_with_c2pa_rs("by_c2pa_rs");

    let via_c2pa_rs = read_and_summarize::<c2pa::Reader>(&signed).expect("c2pa-rs reads its own");
    let via_compat = read_and_summarize::<contentauth_c2pa_rs_compat::Reader>(&signed)
        .expect("the TIFF handler reads what c2pa-rs wrote");

    assert_eq!(via_c2pa_rs, via_compat);
    // Valid, not merely readable: the hard binding checked out against the
    // exclusions c2pa-rs wrote for its own layout.
    assert_eq!(via_compat.validation_state, "Valid");
    // A v2 claim carries no `dc:format`; both readers agree on that.
    assert_eq!(via_compat.format, None);
    assert_eq!(via_compat.title.as_deref(), Some("tiff"));
}

#[test]
fn the_tiff_handler_reports_the_exclusions_c2pa_rs_wrote() {
    use contentauth_c2pa_format::{
        test_util::{MemoryHost, STREAM},
        FormatHandler,
    };

    let signed = sign_with_c2pa_rs("exclusions");
    let bytes = std::fs::read(&signed).unwrap();

    // What c2pa-rs recorded in its own hard binding (read back by this
    // workspace's reader, which decodes the assertion)…
    let report = contentauth_c2pa_file_reader::read_manifest_from_file(
        &contentauth_c2pa_format_tiff::TiffFormat,
        &signed,
        contentauth_c2pa_file_reader::ReadSettings::default(),
    )
    .unwrap();
    let mut recorded: Vec<(u64, u64)> = report
        .active()
        .unwrap()
        .data_hash
        .as_ref()
        .unwrap()
        .exclusions
        .iter()
        .map(|range| (range.start, range.len))
        .collect();
    recorded.sort();

    // …is what this crate's handler says a hard binding excludes.
    let located = MemoryHost::of(bytes)
        .run(contentauth_c2pa_format_tiff::TiffFormat.locate(STREAM))
        .unwrap()
        .embedded
        .unwrap();
    let reported: Vec<(u64, u64)> = located
        .exclusions
        .iter()
        .map(|range| (range.start, range.len))
        .collect();

    assert_eq!(reported, recorded);
    assert_eq!(reported.len(), 2, "the count field, and the store");
}
