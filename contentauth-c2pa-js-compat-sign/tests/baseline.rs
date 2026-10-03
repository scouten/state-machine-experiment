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
//! The baseline signing case through the async JS-shaped binding. A
//! signer and a blob whose every call genuinely suspends stand in for a
//! `Promise`-backed WebCrypto key and a `web_sys::Blob`; the output is
//! read back through the read-side async host. No async runtime anywhere:
//! a hand-rolled executor, as in `contentauth-c2pa-js-compat`'s own tests.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::{
    cell::Cell,
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};

use base64::Engine as _;
use contentauth_c2pa_file_builder::build_and_sign;
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_js_compat::{OfflinePlatform, Reader, ValidationState};
use contentauth_c2pa_js_compat_sign::{AsyncSigner, Blob, Builder, Error, HostError, SigningAlg};
use contentauth_c2pa_primitives::ByteRange;
use contentauth_c2pa_sign_baseline::{fixtures::*, Definition, BASELINE_DEFINITION};

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// Pending on its first poll, ready on its second: the smallest thing that
/// behaves like a `Promise` to whatever awaits it.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// A source whose every read suspends once.
struct SlowBlob<'a> {
    bytes: &'a [u8],
    reads: Cell<usize>,
}

impl Blob for SlowBlob<'_> {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
        YieldOnce(false).await;
        self.reads.set(self.reads.get() + 1);
        self.bytes.bytes(range).await
    }
}

/// The repository test key behind a suspension point, counting signatures.
struct SlowSigner {
    signed: Cell<usize>,
    fail: bool,
}

impl SlowSigner {
    fn new() -> Self {
        Self {
            signed: Cell::new(0),
            fail: false,
        }
    }
}

impl AsyncSigner for SlowSigner {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![TEST_SIGNER_CERT.to_vec()]
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        YieldOnce(false).await;
        if self.fail {
            return Err(HostError::new("the key service said no"));
        }
        self.signed.set(self.signed.get() + 1);
        sign_with_test_key(data)
    }
}

fn sign_with_test_key(data: &[u8]) -> Result<Vec<u8>, HostError> {
    c2pa_raw_crypto::signer_from_private_key(
        TEST_SIGNER_KEY_PEM,
        c2pa_raw_crypto::SigningAlg::Es256,
    )
    .and_then(|signer| signer.sign(data))
    .map_err(|err| HostError::new(err.to_string()))
}

fn context_json() -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(TEST_SIGNER_CERT);
    serde_json::json!({
        "trust": { "trust_anchors":
            format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n") },
        "verify": { "ocsp_fetch": false },
    })
    .to_string()
}

fn read_back(asset: &[u8]) -> Reader {
    block_on(Reader::from_blob(
        "image/jpeg",
        asset,
        Some(&context_json()),
        &OfflinePlatform,
    ))
    .unwrap()
}

#[test]
fn the_baseline_case_signs_a_blob_that_reads_back_trusted() {
    let source = SlowBlob {
        bytes: SOURCE_JPEG,
        reads: Cell::new(0),
    };
    let signer = SlowSigner::new();

    let signed = block_on(Builder::from_json(BASELINE_DEFINITION).unwrap().sign(
        &signer,
        "image/jpeg",
        &source,
    ))
    .unwrap();

    // Both hosts really were awaited.
    assert!(source.reads.get() > 0);
    assert_eq!(signer.signed.get(), 1);
    assert!(!signed.manifest.is_empty());

    let reader = read_back(&signed.asset);
    assert_eq!(
        reader.active_label().as_deref(),
        Some("urn:uuid:00000000-0000-4000-8000-000000000002")
    );
    let store = reader.manifest_store();
    assert_eq!(store.validation_state, ValidationState::Trusted);

    let active = reader.active_manifest().unwrap();
    assert_eq!(active.title.as_deref(), Some("baseline.jpg"));
    assert!(active.assertions.iter().any(|a| a == "c2pa.actions.v2"));
    assert!(active.assertions.iter().any(|a| a == "c2pa.hash.data"));
}

/// Same engine, different host: the async loop and the blocking
/// `build_and_sign` loop yield assets that read back identically.
#[test]
fn the_async_host_agrees_with_the_blocking_host() {
    let async_signed = block_on(Builder::from_json(BASELINE_DEFINITION).unwrap().sign(
        &SlowSigner::new(),
        "image/jpeg",
        SOURCE_JPEG,
    ))
    .unwrap();

    let settings = Definition::from_json(BASELINE_DEFINITION)
        .unwrap()
        .into_settings(
            "image/jpeg",
            SigningAlg::Es256,
            vec![TEST_SIGNER_CERT.to_vec()],
        )
        .unwrap();
    let mut sync_out = std::io::Cursor::new(Vec::new());
    let report = build_and_sign(
        JpegFormat,
        std::io::Cursor::new(SOURCE_JPEG),
        &mut sync_out,
        settings,
        |_, data| sign_with_test_key(data),
        None,
    )
    .unwrap();

    // Same layout (ECDSA signatures are randomized, so not the same
    // bytes), and the same report of what was read.
    let sync_out = sync_out.into_inner();
    assert_eq!(async_signed.asset.len(), sync_out.len());
    assert_eq!(async_signed.manifest.len(), report.manifest.len());
    assert_eq!(
        read_back(&async_signed.asset).json(),
        read_back(&sync_out).json()
    );
}

/// Two builds on one thread interleave at every request boundary — the
/// cooperative yielding a synchronous `Signer` cannot offer.
#[test]
fn two_builds_on_one_thread_interleave() {
    let log = std::cell::RefCell::new(Vec::new());

    struct Logged<'a> {
        name: &'static str,
        log: &'a std::cell::RefCell<Vec<&'static str>>,
    }
    impl AsyncSigner for Logged<'_> {
        fn alg(&self) -> SigningAlg {
            SigningAlg::Es256
        }

        fn certs(&self) -> Vec<Vec<u8>> {
            vec![TEST_SIGNER_CERT.to_vec()]
        }

        async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
            self.log.borrow_mut().push(self.name);
            YieldOnce(false).await;
            sign_with_test_key(data)
        }
    }

    let builder = Builder::from_json(BASELINE_DEFINITION).unwrap();
    let (a, b) = (
        Logged {
            name: "a",
            log: &log,
        },
        Logged {
            name: "b",
            log: &log,
        },
    );
    let blob_a = SlowBlob {
        bytes: SOURCE_JPEG,
        reads: Cell::new(0),
    };
    let blob_b = SlowBlob {
        bytes: SOURCE_JPEG,
        reads: Cell::new(0),
    };
    let mut fa = pin!(builder.sign(&a, "image/jpeg", &blob_a));
    let mut fb = pin!(builder.sign(&b, "image/jpeg", &blob_b));

    let mut cx = Context::from_waker(Waker::noop());
    let (mut ra, mut rb) = (None, None);
    while ra.is_none() || rb.is_none() {
        if ra.is_none() {
            if let Poll::Ready(v) = fa.as_mut().poll(&mut cx) {
                ra = Some(v.unwrap());
            }
        }
        if rb.is_none() {
            if let Poll::Ready(v) = fb.as_mut().poll(&mut cx) {
                rb = Some(v.unwrap());
            }
        }
    }

    // Both reached their signing request before either finished, and both
    // came out valid.
    assert_eq!(*log.borrow(), ["a", "b"]);
    for signed in [ra.unwrap(), rb.unwrap()] {
        assert_eq!(
            read_back(&signed.asset).manifest_store().validation_state,
            ValidationState::Trusted
        );
    }
}

#[test]
fn a_signer_that_fails_fails_the_build() {
    let mut signer = SlowSigner::new();
    signer.fail = true;

    let err = block_on(Builder::from_json(BASELINE_DEFINITION).unwrap().sign(
        &signer,
        "image/jpeg",
        SOURCE_JPEG,
    ))
    .unwrap_err();

    assert!(matches!(err, Error::Build(_)), "{err:?}");
    assert!(err.to_string().contains("the key service said no"), "{err}");
}

#[test]
fn a_blob_that_fails_fails_the_build() {
    struct Broken;
    impl Blob for Broken {
        fn size(&self) -> u64 {
            1000
        }

        async fn bytes(&self, _: ByteRange) -> Result<Vec<u8>, HostError> {
            Err(HostError::new("network down"))
        }
    }

    let err = block_on(Builder::from_json(BASELINE_DEFINITION).unwrap().sign(
        &SlowSigner::new(),
        "image/jpeg",
        &Broken,
    ))
    .unwrap_err();
    assert!(err.to_string().contains("network down"), "{err}");
}

#[test]
fn unsupported_formats_and_bad_definitions_are_rejected_with_js_strings() {
    let err = block_on(Builder::from_json(BASELINE_DEFINITION).unwrap().sign(
        &SlowSigner::new(),
        "image/png",
        SOURCE_JPEG,
    ))
    .unwrap_err();
    assert_eq!(err.js_message(), "UnsupportedType");

    let err = Builder::from_json("{").unwrap_err();
    assert!(
        err.js_message().starts_with("BadParam("),
        "{}",
        err.js_message()
    );
}

/// A signer that names its own time-stamp authority (the definition does
/// not) and answers the request in-process.
struct TimestampingSigner {
    seen: std::cell::RefCell<Vec<String>>,
}

impl AsyncSigner for TimestampingSigner {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        vec![TEST_SIGNER_CERT.to_vec()]
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        sign_with_test_key(data)
    }

    fn time_authority_url(&self) -> Option<String> {
        Some("https://tsa.example/from-signer".to_string())
    }

    async fn send_timestamp_request(
        &self,
        url: &str,
        _request: &[u8],
    ) -> Result<Vec<u8>, HostError> {
        YieldOnce(false).await;
        self.seen.borrow_mut().push(url.to_string());
        // Granted, with an opaque 300-byte token.
        let mut body = vec![0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x2c];
        body.extend([0x42; 300]);
        let mut response = vec![0x30, 0x82];
        response.extend((body.len() as u16).to_be_bytes());
        response.extend(body);
        Ok(response)
    }
}

#[test]
fn a_signers_time_authority_url_turns_timestamping_on() {
    let signer = TimestampingSigner {
        seen: Default::default(),
    };

    let signed = block_on(Builder::from_json(BASELINE_DEFINITION).unwrap().sign(
        &signer,
        "image/jpeg",
        SOURCE_JPEG,
    ))
    .unwrap();

    assert_eq!(*signer.seen.borrow(), ["https://tsa.example/from-signer"]);
    assert!(signed.manifest.windows(300).any(|w| w == [0x42; 300]));
}
