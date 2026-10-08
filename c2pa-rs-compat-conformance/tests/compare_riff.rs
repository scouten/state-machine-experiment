// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Interoperability for a third container format, in both directions: a
//! WAV signed by the *real* c2pa-rs, read by this workspace's RIFF handler;
//! and a WAV signed here, validated by the real c2pa-rs.
//!
//! The question that matters most is which bytes a RIFF hard binding
//! excludes — the `C2PA` chunk's data and pad byte, or its 8-byte header
//! too — since a validator compares the exclusions exactly.

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
use contentauth_c2pa_format_riff::RiffFormat;
use contentauth_c2pa_sign_baseline::{
    fixtures::{TEST_SIGNER_CERT, TEST_SIGNER_KEY_PEM},
    Definition, BASELINE_DEFINITION,
};
use contentauth_state_machine::Session;

const SIGNER_PEM: &[u8] = include_bytes!("fixtures/test-signer.pem");
const SIGNER_KEY: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

fn path(name: &str) -> PathBuf {
    [env!("CARGO_TARGET_TMPDIR"), name].iter().collect()
}

/// A RIFF file of the given form with the given chunks, pad bytes and all.
fn riff(form: &[u8; 4], chunks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut body = form.to_vec();
    for (id, data) in chunks {
        body.extend_from_slice(*id);
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        if data.len() % 2 == 1 {
            body.push(0);
        }
    }
    let mut file = b"RIFF".to_vec();
    file.extend_from_slice(&(body.len() as u32).to_le_bytes());
    file.extend(body);
    file
}

/// A WAV with a PCM `fmt ` chunk and `samples` bytes of audio.
fn wav(samples: usize) -> Vec<u8> {
    let mut fmt = vec![1, 0, 1, 0]; // PCM, mono
    fmt.extend(8000u32.to_le_bytes()); // sample rate
    fmt.extend(8000u32.to_le_bytes()); // byte rate
    fmt.extend([1, 0, 8, 0]); // block align, bits per sample
    let audio: Vec<u8> = (0..samples).map(|i| (i % 251) as u8).collect();
    riff(b"WAVE", &[(b"fmt ", fmt), (b"data", audio)])
}

fn sign_with_c2pa_rs(name: &str, source_bytes: &[u8]) -> PathBuf {
    sign_titled(name, "wav", source_bytes)
}

/// As [`sign_with_c2pa_rs`], with a chosen title — a way to vary the
/// manifest store's length, and so its parity, which RIFF pads.
fn sign_titled(name: &str, title: &str, source_bytes: &[u8]) -> PathBuf {
    let source = path(&format!("{name}_unsigned.wav"));
    let dest = path(&format!("{name}_signed.wav"));
    std::fs::write(&source, source_bytes).unwrap();
    let _ = std::fs::remove_file(&dest);

    let signer =
        c2pa::create_signer::from_keys(SIGNER_PEM, SIGNER_KEY, c2pa::SigningAlg::Es256, None)
            .expect("c2pa-rs accepts the test signer");
    let context = c2pa::Context::new()
        .with_settings(r#"{"verify": {"verify_after_sign": false}}"#)
        .unwrap();
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(format!(
            r#"{{
              "title": "{title}",
              "assertions": [{{
                "label": "c2pa.actions.v2",
                "data": {{"actions": [{{
                  "action": "c2pa.created",
                  "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                }}]}}
              }}]
            }}"#
        ))
        .unwrap();
    builder
        .sign_file(signer.as_ref(), &source, &dest)
        .expect("c2pa-rs signs a WAV");
    dest
}

#[test]
fn the_riff_handler_reads_a_store_c2pa_rs_wrote() {
    for (name, samples) in [("even", 1000), ("odd", 1001)] {
        let signed = sign_with_c2pa_rs(name, &wav(samples));

        let via_c2pa_rs =
            read_and_summarize::<c2pa::Reader>(&signed).expect("c2pa-rs reads its own");
        let via_compat = read_and_summarize::<contentauth_c2pa_rs_compat::Reader>(&signed)
            .expect("the RIFF handler reads what c2pa-rs wrote");

        assert_eq!(via_c2pa_rs, via_compat, "{name}");
        // Valid, not merely readable: the hard binding checked out against
        // the exclusions c2pa-rs wrote.
        assert_eq!(via_compat.validation_state, "Valid", "{name}");
        assert_eq!(via_compat.title.as_deref(), Some("wav"), "{name}");
    }
}

#[test]
fn the_riff_handler_reports_the_exclusions_c2pa_rs_wrote() {
    let mut parities = std::collections::BTreeSet::new();

    // Vary the title a character at a time so the store's length takes
    // both parities: an odd-sized chunk is followed by a pad byte, and
    // whether that byte is excluded is half of what is being checked.
    for extra in 0..4 {
        let name = format!("excl_{extra}");
        let signed = sign_titled(&name, &format!("wav{}", "x".repeat(extra)), &wav(1000));
        let bytes = std::fs::read(&signed).unwrap();

        // What c2pa-rs recorded in its own hard binding…
        let report = contentauth_c2pa_file_reader::read_manifest_from_file(
            &RiffFormat,
            &signed,
            contentauth_c2pa_file_reader::ReadSettings::default(),
        )
        .unwrap();
        let recorded: Vec<(u64, u64)> = report
            .active()
            .unwrap()
            .data_hash
            .as_ref()
            .unwrap()
            .exclusions
            .iter()
            .map(|range| (range.start, range.len))
            .collect();

        // …is what this crate's handler says a hard binding excludes.
        let located = MemoryHost::of(bytes)
            .run(RiffFormat.locate(STREAM))
            .unwrap()
            .embedded
            .unwrap();
        let reported: Vec<(u64, u64)> = located
            .exclusions
            .iter()
            .map(|range| (range.start, range.len))
            .collect();

        assert_eq!(reported, recorded, "{name}");
        parities.insert(located.jumbf.len() % 2);
    }

    assert_eq!(parities.len(), 2, "both even and odd stores were exercised");
}

/// Signs `source` through the RIFF handler and this workspace's builder,
/// with a host that keeps the asset in memory.
fn sign_here(source: &[u8]) -> Vec<u8> {
    let settings: BuilderSettings = Definition::from_json(BASELINE_DEFINITION)
        .unwrap()
        .into_settings(SigningAlg::Es256, vec![TEST_SIGNER_CERT.to_vec()])
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
                        .run(RiffFormat.plan_embed(STREAM, placeholder.len() as u64))
                        .unwrap();
                    asset = embed_plan.materialize(source, placeholder).unwrap();
                    let exclusions = embed_plan.exclusions.clone();
                    plan = Some(embed_plan);
                    BuilderHostReply::PlaceholderReserved {
                        exclusions,
                        hash: None,
                    }
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
                    for patch in RiffFormat.commit(embed_plan, manifest).unwrap() {
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

fn compare(name: &str, source: &[u8]) {
    let signed = sign_here(source);
    let path = path(name);
    std::fs::write(&path, &signed).unwrap();

    let via_c2pa_rs = read_and_summarize::<c2pa::Reader>(&path)
        .unwrap_or_else(|err| panic!("c2pa-rs could not read our RIFF file: {err}"));
    let via_compat = read_and_summarize::<contentauth_c2pa_rs_compat::Reader>(&path)
        .expect("the compat reader reads our own RIFF file");

    assert_eq!(via_c2pa_rs, via_compat);
    assert_eq!(via_c2pa_rs.validation_state, "Valid", "{via_c2pa_rs:?}");
}

#[test]
fn c2pa_rs_validates_a_wav_signed_here() {
    compare("here_even.wav", &wav(1000));
}

#[test]
fn c2pa_rs_validates_a_wav_with_odd_sized_audio_signed_here() {
    compare("here_odd.wav", &wav(1001));
}

#[test]
fn c2pa_rs_validates_a_wav_with_a_trailing_chunk_signed_here() {
    let mut source = wav(1000);
    // A LIST/INFO chunk after the audio, as many WAV writers leave.
    let list = {
        let mut data = b"INFO".to_vec();
        data.extend_from_slice(b"ISFT\x06\0\0\0Test\0\0");
        data
    };
    let mut body = source.split_off(12);
    body.extend_from_slice(b"LIST");
    body.extend_from_slice(&(list.len() as u32).to_le_bytes());
    body.extend(list);
    source.extend(body);
    let size = (source.len() - 8) as u32;
    source[4..8].copy_from_slice(&size.to_le_bytes());

    compare("here_trailing_list.wav", &source);
}

#[test]
fn c2pa_rs_validates_a_wav_re_signed_here() {
    // Signed by c2pa-rs, then signed again here: the handler replaces the
    // existing `C2PA` chunk rather than adding a second.
    let signed_by_rs = sign_with_c2pa_rs("resign", &wav(1000));
    let bytes = std::fs::read(&signed_by_rs).unwrap();
    let resigned = sign_here(&bytes);

    let path = path("resigned.wav");
    std::fs::write(&path, resigned).unwrap();
    let via_c2pa_rs = read_and_summarize::<c2pa::Reader>(&path).unwrap();
    assert_eq!(via_c2pa_rs.validation_state, "Valid", "{via_c2pa_rs:?}");
}
