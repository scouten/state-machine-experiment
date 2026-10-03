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
//! Timestamping through the c2pa-rs-shaped `Builder`: the request the
//! signer is handed, the token that lands in the manifest, and the
//! default HTTP transport — against a local stand-in for an authority,
//! since a real one is neither reachable from CI nor deterministic.
//!
//! The "token" is an opaque stand-in: the builder embeds it without
//! decoding it, and whether a real token is trusted is the reader's
//! business (covered by its own suite).

#![allow(clippy::unwrap_used)]

use std::{
    io::{Cursor, Read, Write},
    net::TcpListener,
    sync::Mutex,
    thread,
};

use contentauth_c2pa_rs_compat::{Context, ReadSettings, Reader};
use contentauth_c2pa_rs_compat_sign::{Builder, Error, HostError, Signer, SigningAlg};
use contentauth_c2pa_sign_baseline::{fixtures::*, BASELINE_DEFINITION};

const TOKEN: [u8; 300] = [0x42; 300];

/// A DER `TimeStampResp`: `PKIStatusInfo { status }`, then (if granted) a
/// `TimeStampToken` whose content is [`TOKEN`].
fn response(status: u8) -> Vec<u8> {
    let mut body = vec![0x30, 0x03, 0x02, 0x01, status];
    if status == 0 {
        body.extend([0x30, 0x82, 0x01, 0x2c]);
        body.extend(TOKEN);
    }
    let mut out = vec![0x30, 0x82];
    out.extend((body.len() as u16).to_be_bytes());
    out.extend(body);
    out
}

fn token_der() -> Vec<u8> {
    let mut out = vec![0x30, 0x82, 0x01, 0x2c];
    out.extend(TOKEN);
    out
}

fn es256_sign(data: &[u8]) -> Result<Vec<u8>, HostError> {
    c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .and_then(|signer| signer.sign(data))
    .map_err(|err| HostError::new(err.to_string()))
}

/// A signer whose "authority" is an in-process function: records every
/// request it is sent and answers with `status`.
struct FakeAuthority {
    status: u8,
    url: Option<String>,
    seen: Mutex<Vec<(String, Vec<u8>)>>,
}

impl FakeAuthority {
    fn new(status: u8, url: Option<&str>) -> Self {
        Self {
            status,
            url: url.map(str::to_string),
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl Signer for FakeAuthority {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![TEST_SIGNER_CERT.to_vec()]
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        es256_sign(data)
    }

    fn time_authority_url(&self) -> Option<String> {
        self.url.clone()
    }

    fn send_timestamp_request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, HostError> {
        self.seen
            .lock()
            .unwrap()
            .push((url.to_string(), request.to_vec()));
        Ok(response(self.status))
    }
}

fn sign_to_memory(builder: &Builder, signer: &dyn Signer) -> Result<Vec<u8>, Error> {
    let mut dest = Cursor::new(Vec::new());
    let manifest = builder.sign(signer, "image/jpeg", Cursor::new(SOURCE_JPEG), &mut dest)?;
    // Keep what was written for the read-back below.
    LAST_ASSET.with(|cell| *cell.borrow_mut() = dest.into_inner());
    Ok(manifest)
}

thread_local! {
    static LAST_ASSET: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn definition_with_tsa_url(url: &str) -> Builder {
    Builder::from_json(
        &BASELINE_DEFINITION.replace("\"title\"", &format!("\"tsa_url\": \"{url}\", \"title\"")),
    )
    .unwrap()
}

#[test]
fn a_signer_supplied_authority_timestamps_the_claim() {
    let signer = FakeAuthority::new(0, Some("http://tsa.example/from-signer"));
    let builder = Builder::from_json(BASELINE_DEFINITION).unwrap();

    let manifest = sign_to_memory(&builder, &signer).unwrap();

    // The signer was asked exactly once, with a well-formed SHA-256
    // TimeStampReq (certReq set) for the URL it named.
    let seen = signer.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (url, request) = &seen[0];
    assert_eq!(url, "http://tsa.example/from-signer");
    assert_eq!(request[0], 0x30);
    assert!(request
        .windows(11)
        .any(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00]));
    assert!(request.ends_with(&[0x01, 0x01, 0xff]));

    // The token (not the whole response) is what the manifest carries.
    let token = token_der();
    assert!(manifest.windows(token.len()).any(|w| w == token));
    assert!(!manifest
        .windows(5)
        .any(|w| w == [0x30, 0x03, 0x02, 0x01, 0x00]));

    // And the signed asset still reads back, signature and hard binding intact.
    let asset = LAST_ASSET.with(|cell| cell.borrow().clone());
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("timestamped.jpg");
    std::fs::write(&path, asset).unwrap();
    let reader = Reader::from_context(Context::new().with_settings(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    }))
    .with_file(&path)
    .unwrap();
    assert!(reader.active_label().is_some());
}

#[test]
fn the_definitions_tsa_url_wins_over_the_signers() {
    let signer = FakeAuthority::new(0, Some("http://tsa.example/from-signer"));
    let builder = definition_with_tsa_url("https://tsa.example/from-definition");

    sign_to_memory(&builder, &signer).unwrap();

    assert_eq!(
        signer.seen.lock().unwrap()[0].0,
        "https://tsa.example/from-definition"
    );
}

#[test]
fn no_authority_means_no_request() {
    let signer = FakeAuthority::new(0, None);
    let builder = Builder::from_json(BASELINE_DEFINITION).unwrap();

    let manifest = sign_to_memory(&builder, &signer).unwrap();

    assert!(signer.seen.lock().unwrap().is_empty());
    let token = token_der();
    assert!(!manifest.windows(token.len()).any(|w| w == token));
}

#[test]
fn a_refusing_authority_fails_the_build() {
    let signer = FakeAuthority::new(2, Some("http://tsa.example/"));
    let builder = Builder::from_json(BASELINE_DEFINITION).unwrap();

    let err = sign_to_memory(&builder, &signer).unwrap_err();

    assert!(err.to_string().contains("refused"), "{err}");
}

/// A one-shot HTTP server: answers the first request with `reply`, and
/// returns what it received (headers and body).
fn serve_once(status: &'static str, reply: Vec<u8>) -> (String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsa", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];
        let body_start = loop {
            let n = stream.read(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
            if let Some(pos) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let headers = String::from_utf8_lossy(&received[..body_start]).to_lowercase();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        while received.len() < body_start + length {
            let n = stream.read(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
        }

        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        )
        .unwrap();
        stream.write_all(&reply).unwrap();
        received
    });
    (url, handle)
}

struct HttpSigner;

impl Signer for HttpSigner {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![TEST_SIGNER_CERT.to_vec()]
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        es256_sign(data)
    }
}

#[test]
fn the_default_transport_posts_the_request_over_http() {
    let (url, server) = serve_once("200 OK", response(0));
    let builder = definition_with_tsa_url(&url);

    let manifest = sign_to_memory(&builder, &HttpSigner).unwrap();

    let received = server.join().unwrap();
    let text = String::from_utf8_lossy(&received).to_lowercase();
    assert!(text.starts_with("post /tsa "), "{text}");
    assert!(
        text.contains("content-type: application/timestamp-query"),
        "{text}"
    );
    let token = token_der();
    assert!(manifest.windows(token.len()).any(|w| w == token));
}

#[test]
fn an_unreachable_authority_fails_the_build_rather_than_going_untimestamped() {
    // Bind then drop, so nothing is listening on the port.
    let url = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/", listener.local_addr().unwrap())
    };
    let builder = definition_with_tsa_url(&url);

    let err = sign_to_memory(&builder, &HttpSigner).unwrap_err();

    assert!(err.to_string().contains("timestamp request"), "{err}");
}

#[test]
fn an_authority_answering_with_an_http_error_fails_the_build() {
    let (url, server) = serve_once("503 Service Unavailable", b"busy".to_vec());
    let builder = definition_with_tsa_url(&url);

    let err = sign_to_memory(&builder, &HttpSigner).unwrap_err();

    server.join().unwrap();
    assert!(err.to_string().contains("answered 503"), "{err}");
}

#[test]
fn an_implausibly_large_response_fails_the_build() {
    let (url, server) = serve_once("200 OK", vec![0x30; 1024 * 1024 + 1]);
    let builder = definition_with_tsa_url(&url);

    let err = sign_to_memory(&builder, &HttpSigner).unwrap_err();

    server.join().unwrap();
    assert!(err.to_string().contains("implausibly large"), "{err}");
}

#[test]
fn sign_file_timestamps_too() {
    let source = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("ts-source.jpg");
    let dest = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("ts-dest.jpg");
    std::fs::write(&source, SOURCE_JPEG).unwrap();
    let signer = FakeAuthority::new(0, Some("http://tsa.example/"));
    let builder = Builder::from_json(BASELINE_DEFINITION).unwrap();

    let manifest = builder.sign_file(&signer, &source, &dest).unwrap();

    assert_eq!(signer.seen.lock().unwrap().len(), 1);
    let token = token_der();
    assert!(manifest.windows(token.len()).any(|w| w == token));
}
