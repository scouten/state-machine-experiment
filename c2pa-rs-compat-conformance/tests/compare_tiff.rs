// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Interoperability for a second container format: a TIFF signed by this
//! workspace's write path, read back by the *real* c2pa-rs.
//!
//! `contentauth-c2pa-format-tiff` follows the specification's TIFF
//! embedding rules (tag `0xCD41`, type `UNDEFINED`, in a trailing IFD,
//! with the entry's `count` field excluded from the hard binding), but
//! nothing inside this workspace can say whether c2pa-rs agrees with its
//! reading of them. This can.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::path::PathBuf;

use c2pa_rs_compat_conformance::read_and_summarize;
use contentauth_c2pa_builder::{
    BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep, SigningAlg,
};
use contentauth_c2pa_format::{
    test_util::{MemoryHost, STREAM},
    FormatHandler,
};
use contentauth_c2pa_format_tiff::TiffFormat;
use contentauth_c2pa_sign_baseline::{
    fixtures::{TEST_SIGNER_CERT, TEST_SIGNER_KEY_PEM},
    Definition, BASELINE_DEFINITION,
};
use contentauth_state_machine::Session;

/// Builds and signs a manifest and embeds it into `source` through
/// `handler`, as a host writing a file would.
fn sign<H: FormatHandler>(handler: &H, mime: &str, source: &[u8]) -> Vec<u8> {
    let settings: BuilderSettings = Definition::from_json(BASELINE_DEFINITION)
        .unwrap()
        .into_settings(mime, SigningAlg::Es256, vec![TEST_SIGNER_CERT.to_vec()])
        .unwrap();

    let mut session = BuilderSession::new(settings);
    let mut asset = source.to_vec();
    let mut plan = None;

    loop {
        if session.advance().unwrap() == BuilderStep::Complete {
            session.finish().unwrap();
            return asset;
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match &request.kind {
                BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                    let embed_plan = MemoryHost::of(source.to_vec())
                        .run(handler.plan_embed(STREAM, placeholder.len() as u64))
                        .unwrap();
                    asset = embed_plan.materialize(source, placeholder).unwrap();
                    let exclusion = embed_plan.exclusion;
                    plan = Some(embed_plan);
                    BuilderHostReply::PlaceholderReserved(exclusion)
                }
                BuilderRequest::AssetLength { .. } => {
                    BuilderHostReply::AssetLength(asset.len() as u64)
                }
                BuilderRequest::AssetBytes { range, .. } => BuilderHostReply::AssetBytes(
                    asset[range.start as usize..][..range.len as usize].to_vec(),
                ),
                BuilderRequest::Sign { data, .. } => {
                    let signer = c2pa_raw_crypto::signer_from_private_key(
                        TEST_SIGNER_KEY_PEM,
                        c2pa_raw_crypto::SigningAlg::Es256,
                    )
                    .unwrap();
                    BuilderHostReply::Signature(signer.sign(data).unwrap())
                }
                BuilderRequest::CommitManifest { manifest, .. } => {
                    let embed_plan = plan.as_ref().unwrap();
                    asset = embed_plan.materialize(source, manifest).unwrap();
                    for patch in handler.commit(embed_plan, manifest).unwrap() {
                        patch.apply(&mut asset).unwrap();
                    }
                    BuilderHostReply::ManifestCommitted
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), name].iter().collect();
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A little-endian TIFF with one IFD and one `ImageWidth` entry, and a
/// strip of pixels the entry points at, so that an embedding that moved
/// things would be caught by a stale offset.
fn tiff(extra_ifds: bool) -> Vec<u8> {
    let mut out = b"II\x2a\0\x08\0\0\0".to_vec();
    // IFD 0 at 8: ImageWidth, StripOffsets -> 50, StripByteCounts.
    out.extend([3, 0]);
    out.extend([0, 1, 3, 0, 1, 0, 0, 0, 4, 0, 0, 0]);
    out.extend([0x11, 1, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0]);
    out.extend([0x17, 1, 4, 0, 1, 0, 0, 0, 4, 0, 0, 0]);
    let next: u32 = if extra_ifds { 54 } else { 0 };
    out.extend(next.to_le_bytes());
    out.extend([1, 2, 3, 4]);
    if extra_ifds {
        out.extend([1, 0]);
        out.extend([0, 1, 3, 0, 1, 0, 0, 0, 9, 0, 0, 0]);
        out.extend([0, 0, 0, 0]);
    }
    out
}

/// Reads `signed` with real c2pa-rs and with the compat reader.
///
/// This workspace's builder does not yet emit a claim c2pa-rs 0.91
/// accepts, whatever the container: it writes `claim_generator_info` as
/// an array under a v2 claim, where c2pa-rs wants a map (the same failure
/// shows for a JPEG). So c2pa-rs cannot validate what the builder signs
/// today — but it must get *as far as the claim*, which is only possible if
/// it found the store through the TIFF handler's layout, parsed the JUMBF,
/// and reached the claim. Should the builder be fixed, this test starts
/// comparing the two readers outright instead.
fn compare(name: &str, source: &[u8]) {
    let signed = sign(&TiffFormat, "image/tiff", source);
    let path = write_temp(name, &signed);

    match read_and_summarize::<c2pa::Reader>(&path) {
        Ok(via_c2pa_rs) => {
            let via_compat = read_and_summarize::<contentauth_c2pa_rs_compat::Reader>(&path)
                .expect("the compat reader reads our own TIFF");
            assert_eq!(via_c2pa_rs, via_compat);
            assert_eq!(via_c2pa_rs.validation_state, "Valid", "{via_c2pa_rs:?}");
        }
        Err(err) => assert!(
            err.contains("claim could not be converted from CBOR"),
            "c2pa-rs should have found the store in our TIFF and failed only at the claim, not: {err}"
        ),
    }
}

#[test]
fn c2pa_rs_finds_the_store_in_a_tiff_signed_here() {
    compare("signed_single_ifd.tif", &tiff(false));
}

#[test]
fn c2pa_rs_finds_the_store_in_a_multi_ifd_tiff_signed_here() {
    compare("signed_two_ifds.tif", &tiff(true));
}
