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
//! The baseline signing case through the Node binding, driven by a plain
//! synchronous loop (no async anywhere, as a Node host's loop would be but
//! without the event loop): in-memory source, a growing output `Vec`, and
//! a signature from the repository's test key. The result is read back
//! through the sibling read-side compat layer.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use contentauth_c2pa_node_compat_sign::{
    Error, NodeBuildSession, PendingRequest, Reply, SignReport, Step, Stream,
};
use contentauth_c2pa_rs_compat::{Context, ReadSettings, Reader, ValidationState};
use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

type Signed = Result<Vec<u8>, String>;

fn sign_with(
    session: NodeBuildSession,
    sign: &dyn Fn(&[u8]) -> Signed,
) -> Result<(Vec<u8>, SignReport, usize), Error> {
    sign_and_timestamp_with(session, sign, &|_, _| {
        Err("this test does not expect a timestamp request".to_string())
    })
}

/// `tsa` plays the time-stamp authority: given the URL and the DER
/// request, it returns the DER response body.
fn sign_and_timestamp_with(
    mut session: NodeBuildSession,
    sign: &dyn Fn(&[u8]) -> Signed,
    tsa: &dyn Fn(&str, &[u8]) -> Signed,
) -> Result<(Vec<u8>, SignReport, usize), Error> {
    let mut output: Vec<u8> = Vec::new();
    let mut signatures = 0;

    while let Step::Pending(requests) = session.advance()? {
        assert!(!requests.is_empty(), "stalled");
        for request in requests {
            let id = request.id();
            let reply = match request {
                PendingRequest::Read {
                    stream, start, len, ..
                } => {
                    let bytes = match stream {
                        Stream::Source => SOURCE_JPEG,
                        Stream::Output => &output[..],
                    };
                    Reply::Bytes(bytes[start as usize..(start + len) as usize].to_vec())
                }
                PendingRequest::Length { stream, .. } => Reply::Length(match stream {
                    Stream::Source => SOURCE_JPEG.len() as u64,
                    Stream::Output => output.len() as u64,
                }),
                PendingRequest::Write { offset, bytes, .. } => {
                    let end = offset as usize + bytes.len();
                    if output.len() < end {
                        output.resize(end, 0);
                    }
                    output[offset as usize..end].copy_from_slice(&bytes);
                    Reply::Written
                }
                PendingRequest::Sign { alg, data, .. } => {
                    assert_eq!(alg, "es256");
                    signatures += 1;
                    match sign(&data) {
                        Ok(sig) => Reply::Signature(sig),
                        Err(message) => Reply::Failed(message),
                    }
                }
                PendingRequest::Timestamp { url, request, .. } => match tsa(&url, &request) {
                    Ok(body) => Reply::TimestampResponse(body),
                    Err(message) => Reply::Failed(message),
                },
                other => panic!("unexpected {other:?}"),
            };
            session.fulfill(id, reply)?;
        }
    }
    Ok((output, session.finish()?, signatures))
}

fn test_sign(data: &[u8]) -> Result<Vec<u8>, String> {
    c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .and_then(|signer| signer.sign(data))
    .map_err(|err| err.to_string())
}

fn new_session() -> NodeBuildSession {
    NodeBuildSession::new(
        BASELINE_DEFINITION,
        "image/jpeg",
        "es256",
        vec![TEST_SIGNER_CERT.to_vec()],
    )
    .unwrap()
}

#[test]
fn the_baseline_case_signs_through_a_plain_loop_and_reads_back_trusted() {
    let session = new_session();
    let (output, report, signatures) = sign_with(session, &test_sign).unwrap();
    assert_eq!(signatures, 1);
    assert!(!report.manifest.is_empty());
    assert!(report.manifest_len >= report.manifest.len() as u64);
    assert!(report.manifest_start + report.manifest_len <= output.len() as u64);

    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "node-sign-out.jpg"]
        .iter()
        .collect();
    std::fs::write(&path, &output).unwrap();
    let reader = Reader::from_context(Context::new().with_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    }))
    .with_file(&path)
    .unwrap();

    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    assert_eq!(
        reader.active_label(),
        Some("urn:uuid:00000000-0000-4000-8000-000000000002")
    );
    assert_eq!(
        reader.active_manifest().unwrap().title(),
        Some("baseline.jpg")
    );
    let json: serde_json::Value = serde_json::from_str(&reader.json()).unwrap();
    let labels = json["manifests"][reader.active_label().unwrap()]["assertions"].to_string();
    assert!(labels.contains("c2pa.actions.v2"), "{labels}");
}

#[test]
fn a_rejected_signature_fails_the_build() {
    let session = new_session();
    let err = sign_with(session, &|_| Err("hsm unavailable".to_string())).unwrap_err();
    assert!(err.to_string().contains("hsm unavailable"), "{err}");
    assert!(
        err.js_message().starts_with("Build("),
        "{}",
        err.js_message()
    );
}

#[test]
fn a_bad_definition_is_rejected_before_any_request() {
    let err = NodeBuildSession::new("{", "image/jpeg", "es256", vec![])
        .err()
        .unwrap();
    assert!(
        err.js_message().starts_with("Definition("),
        "{}",
        err.js_message()
    );
}

fn timestamping_session() -> NodeBuildSession {
    let json = BASELINE_DEFINITION.replace(
        "\"title\"",
        "\"ta_url\": \"https://tsa.example/\", \"title\"",
    );
    NodeBuildSession::new(
        &json,
        "image/jpeg",
        "es256",
        vec![TEST_SIGNER_CERT.to_vec()],
    )
    .unwrap()
}

/// A canned `TimeStampResp`: granted, with an opaque 300-byte token (the
/// session embeds it without decoding it).
fn granted_response() -> Vec<u8> {
    let mut body = vec![0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x2c];
    body.extend([0x42; 300]);
    let mut out = vec![0x30, 0x82];
    out.extend((body.len() as u16).to_be_bytes());
    out.extend(body);
    out
}

#[test]
fn a_ta_url_makes_the_loop_answer_a_timestamp_request_and_embed_the_token() {
    let asked = std::cell::RefCell::new(Vec::new());
    let (output, report, _) =
        sign_and_timestamp_with(timestamping_session(), &test_sign, &|url, request| {
            asked.borrow_mut().push((url.to_string(), request.to_vec()));
            Ok(granted_response())
        })
        .unwrap();

    let asked = asked.borrow();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, "https://tsa.example/");
    assert_eq!(asked[0].1[0], 0x30);

    assert!(report.manifest.windows(300).any(|w| w == [0x42; 300]));
    assert!(output.len() as u64 >= report.manifest_start + report.manifest_len);
}

#[test]
fn a_refusing_authority_fails_the_build() {
    let refused = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
    let err = sign_and_timestamp_with(timestamping_session(), &test_sign, &|_, _| {
        Ok(refused.clone())
    })
    .unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
}

#[test]
fn an_unreachable_authority_fails_the_build() {
    let err = sign_and_timestamp_with(timestamping_session(), &test_sign, &|_, _| {
        Err("connection refused".to_string())
    })
    .unwrap_err();
    assert!(err.to_string().contains("connection refused"), "{err}");
}
