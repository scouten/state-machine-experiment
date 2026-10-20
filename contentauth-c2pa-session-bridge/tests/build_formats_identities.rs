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
//! The build bridge beyond the JPEG baseline: a TIFF source, and CAWG
//! identity assertions whose signing requests carry the identity's label.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use contentauth_c2pa_rs_compat::{Context, ReadSettings, Reader, ValidationState};
use contentauth_c2pa_session_bridge::{
    build::{BuildSessionBridge, IdentitySigner, PendingRequest, Reply, Step, Stream},
    compat::manifest_store::{Manifest, ValidationState as BridgeState},
    read::{
        PendingRequest as ReadRequest, ReadSessionBridge, Reply as ReadReply, Step as ReadStep,
    },
};
use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

/// A classic little-endian TIFF whose one IFD has a single entry.
const SOURCE_TIFF: &[u8] = &[
    b'I', b'I', 42, 0, 8, 0, 0, 0, // header: first IFD at 8
    1, 0, // one entry: ImageWidth, SHORT, count 1, value 1
    0, 1, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, //
    0, 0, 0, 0, // no next IFD
];

fn sign(data: &[u8]) -> Vec<u8> {
    c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .and_then(|signer| signer.sign(data))
    .unwrap()
}

/// Drives `session` over `source`, returning the output and the identity
/// label (or `None` for the claim) of every signature requested.
fn drive(mut session: BuildSessionBridge, source: &[u8]) -> (Vec<u8>, Vec<Option<String>>) {
    let mut output: Vec<u8> = Vec::new();
    let mut signed = Vec::new();
    while let Step::Pending(requests) = session.advance().unwrap() {
        for request in requests {
            let id = request.id();
            let reply = match request {
                PendingRequest::Read {
                    stream, start, len, ..
                } => {
                    let bytes = match stream {
                        Stream::Source => source,
                        Stream::Output => &output[..],
                    };
                    Reply::Bytes(bytes[start as usize..(start + len) as usize].to_vec())
                }
                PendingRequest::Length { stream, .. } => Reply::Length(match stream {
                    Stream::Source => source.len() as u64,
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
                PendingRequest::Sign { data, identity, .. } => {
                    signed.push(identity);
                    Reply::Signature(sign(&data))
                }
                other => panic!("unexpected {other:?}"),
            };
            session.fulfill(id, reply).unwrap();
        }
    }
    session.finish().unwrap();
    (output, signed)
}

fn read(output: &[u8], name: &str) -> Reader {
    let path: PathBuf = [env!("CARGO_TARGET_TMPDIR"), name].iter().collect();
    std::fs::write(&path, output).unwrap();
    Reader::from_context(Context::new().with_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    }))
    .with_file(&path)
    .unwrap()
}

fn session(format: &str, identities: Vec<IdentitySigner>) -> BuildSessionBridge {
    BuildSessionBridge::new(
        BASELINE_DEFINITION,
        format,
        "es256",
        vec![TEST_SIGNER_CERT.to_vec()],
        identities,
    )
    .unwrap()
}

#[test]
fn a_tiff_signs_through_the_bridge_and_reads_back_trusted() {
    for format in ["image/tiff", "tif"] {
        let (output, signed) = drive(session(format, Vec::new()), SOURCE_TIFF);
        assert_eq!(signed, [None]);
        let reader = read(&output, "bridge-out.tif");
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
    }
}

#[test]
fn an_identity_is_signed_with_its_own_label_before_the_claim() {
    let identity = IdentitySigner {
        alg: "es256".to_string(),
        certs: vec![TEST_SIGNER_CERT.to_vec()],
        roles: vec!["cawg.creator".to_string()],
        referenced_assertions: None,
    };
    let (output, signed) = drive(session("image/jpeg", vec![identity]), SOURCE_JPEG);
    assert_eq!(signed, [Some("cawg.identity".to_string()), None]);

    let reader = read(&output, "bridge-identity.jpg");
    let json = reader.json();
    assert!(json.contains("cawg.identity"), "{json}");
}

#[test]
fn ps256_with_a_non_rsa_certificate_is_rejected() {
    // The EC test certificate is not RSA, so the length cannot be derived.
    let err = BuildSessionBridge::new(
        BASELINE_DEFINITION,
        "image/jpeg",
        "ps256",
        vec![TEST_SIGNER_CERT.to_vec()],
        Vec::new(),
    )
    .err()
    .unwrap();
    assert!(
        err.js_message().contains("SignerCertificate"),
        "{}",
        err.js_message()
    );
}

/// Signs `SOURCE_JPEG` with one identity whose signature, if `forge`, is
/// corrupted, and reads the result back through the bridge's reader.
fn read_identity(forge: bool, tamper_asset: bool) -> (Manifest, BridgeState) {
    let identity = IdentitySigner {
        alg: "es256".to_string(),
        certs: vec![TEST_SIGNER_CERT.to_vec()],
        roles: Vec::new(),
        referenced_assertions: None,
    };
    let mut session = session("image/jpeg", vec![identity]);
    let mut output: Vec<u8> = Vec::new();
    while let Step::Pending(requests) = session.advance().unwrap() {
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
                PendingRequest::Sign { data, identity, .. } => {
                    let mut signature = sign(&data);
                    if forge && identity.is_some() {
                        signature[10] ^= 0xff;
                    }
                    Reply::Signature(signature)
                }
                other => panic!("unexpected {other:?}"),
            };
            session.fulfill(id, reply).unwrap();
        }
    }
    session.finish().unwrap();

    if tamper_asset {
        // The last bytes are image data, outside the manifest store.
        let last = output.len() - 3;
        output[last] ^= 0xff;
    }

    let mut reader = ReadSessionBridge::new("image/jpeg", None).unwrap();
    loop {
        match reader.advance().unwrap() {
            ReadStep::Complete => break,
            ReadStep::Pending(requests) => {
                for request in requests {
                    let reply = match &request {
                        ReadRequest::Read { start, len, .. } => ReadReply::Bytes(
                            output[*start as usize..(*start + *len) as usize].to_vec(),
                        ),
                        ReadRequest::Length { .. } => ReadReply::Length(output.len() as u64),
                        ReadRequest::CurrentDateTime { .. } => ReadReply::Time(1_800_000_000),
                        _ => ReadReply::Failed("unsupported".to_string()),
                    };
                    reader.fulfill(request.id(), reply).unwrap();
                }
            }
        }
    }
    let reader = reader.finish().unwrap().unwrap();
    let manifest = reader.active_manifest().unwrap();
    assert_eq!(manifest.identity_assertions.len(), 1);
    (manifest, reader.validation_state())
}

#[test]
fn a_verified_identity_is_reported_valid() {
    let (manifest, _) = read_identity(false, false);
    let identity = &manifest.identity_assertions[0];
    assert!(identity.signer.is_some());
    assert!(identity.valid);
}

#[test]
fn an_identity_with_a_forged_signature_is_not_valid() {
    let (manifest, _) = read_identity(true, false);
    let identity = &manifest.identity_assertions[0];
    assert!(identity.signer.is_none());
    assert!(!identity.valid);
    assert!(
        identity
            .validation_status
            .iter()
            .any(|status| status.code == "cawg.x509.signature.mismatch"),
        "{:?}",
        identity.validation_status
    );
}

#[test]
fn a_failure_that_does_not_name_the_identity_does_not_invalidate_it() {
    let (manifest, state) = read_identity(false, true);
    // The store itself fails (its asset hash no longer matches)...
    assert_ne!(state, BridgeState::Trusted);
    let identity = &manifest.identity_assertions[0];
    assert!(identity.signer.is_some());
    assert!(identity.valid);
}
