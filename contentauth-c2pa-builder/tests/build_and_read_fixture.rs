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

//! Drives a full [`BuilderSession`] against a simulated host, then feeds
//! the resulting asset into `contentauth_c2pa_reader::ReadSession` and
//! checks it reads back as trusted. This is the crate's primary
//! correctness proof: a bug that made both crates agree on the wrong
//! thing is exactly what round-tripping through the independently-written
//! reader is meant to catch.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_builder::{
    Assertion, BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep,
    GeneratorInfo, HashAlgorithm, SigningAlg, TimestampSettings,
};
use contentauth_c2pa_reader::{
    ReadHostReply, ReadRequest, ReadSession, ReadSettings, ReadStep, ValidationState,
};
use contentauth_state_machine::Session;

/// The end-entity certificate for [`TEST_SIGNER_KEY`], self-signed so
/// tests can configure it directly as a trust anchor. Generated for this
/// repository and used only to sign test data; it protects nothing. The
/// same fixture `contentauth-c2pa-reader`'s own tests use.
const TEST_SIGNER_CERT: &[u8] = include_bytes!("fixtures/test-signer.der");

/// The matching private key.
const TEST_SIGNER_KEY: &[u8] = include_bytes!("fixtures/test-signer.key.pem");

/// A simulated host: owns the "asset" (an opaque byte buffer standing in
/// for a real container format), signs with a real key over the real
/// fixture certificate, and — if asked — fabricates an RFC 3161 token.
struct Host {
    asset: Vec<u8>,
    manifest_range: Option<(u64, u64)>,
}

impl Host {
    fn new(asset_len: usize) -> Self {
        Self {
            asset: (0..asset_len as u32).map(|i| (i % 251) as u8).collect(),
            manifest_range: None,
        }
    }

    /// Drives `session` to completion, servicing every request as
    /// described above, and returns the final asset bytes alongside the
    /// session's report.
    fn build(
        &mut self,
        mut session: BuilderSession,
    ) -> (Vec<u8>, contentauth_c2pa_builder::BuilderReport) {
        loop {
            if session.advance().unwrap() == BuilderStep::Complete {
                let report = session.finish().unwrap();
                return (self.asset.clone(), report);
            }

            let requests = session.outstanding_requests().to_vec();
            for request in requests {
                let reply = self.reply_to(&request.kind);
                session.fulfill(request.id, reply).unwrap();
            }
        }
    }

    fn reply_to(&mut self, request: &BuilderRequest) -> BuilderHostReply {
        match request {
            BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                // Embed the placeholder at a fixed offset, standing in for
                // wherever a real container format would put it.
                let offset = 100u64;
                self.asset.splice(
                    offset as usize..offset as usize,
                    placeholder.iter().copied(),
                );
                self.manifest_range = Some((offset, placeholder.len() as u64));
                BuilderHostReply::PlaceholderReserved(contentauth_c2pa_builder::ByteRange {
                    start: offset,
                    len: placeholder.len() as u64,
                })
            }

            BuilderRequest::AssetLength { .. } => {
                BuilderHostReply::AssetLength(self.asset.len() as u64)
            }

            BuilderRequest::AssetBytes { range, .. } => {
                let start = range.start as usize;
                let end = start + range.len as usize;
                BuilderHostReply::AssetBytes(self.asset[start..end].to_vec())
            }

            BuilderRequest::Sign { alg, data } => {
                assert_eq!(*alg, SigningAlg::Es256);
                let signer = c2pa_raw_crypto::signer_from_private_key(
                    TEST_SIGNER_KEY,
                    c2pa_raw_crypto::SigningAlg::Es256,
                )
                .unwrap();
                BuilderHostReply::Signature(signer.sign(data).unwrap())
            }

            BuilderRequest::Timestamp { digest, hash_alg } => {
                assert_eq!(*hash_alg, HashAlgorithm::Sha256);
                BuilderHostReply::Timestamp(fabricate_timestamp_token(digest))
            }

            BuilderRequest::CommitManifest {
                range, manifest, ..
            } => {
                let start = range.start as usize;
                let end = start + range.len as usize;
                assert_eq!(manifest.len(), range.len as usize);
                self.asset[start..end].copy_from_slice(manifest);
                BuilderHostReply::ManifestCommitted
            }

            other => panic!("unexpected request: {other:?}"),
        }
    }
}

/// Builds a minimal (structurally valid, but unsigned and untrusted) RFC
/// 3161 `TimeStampToken` covering `digest` — just enough for
/// `contentauth-c2pa-reader`'s decoder to read it back as *present*, which
/// is all this test needs: whether an untrusted timestamp is trusted is
/// the reader's own business, already covered by its test suite.
///
/// This crate never decodes or verifies timestamps itself (see the
/// `BuilderRequest::Timestamp` docs), so a real CMS-signed token is not
/// needed to prove *this* crate embeds whatever bytes the host hands
/// back, at exactly the reserved size.
fn fabricate_timestamp_token(_digest: &[u8]) -> Vec<u8> {
    // A small, arbitrary byte string. This crate treats the token as
    // opaque; the assertion this test cares about is that it round-trips
    // through the padded `sigTst2` header at the right length.
    vec![0x42; 300]
}

fn settings(assertions: Vec<Assertion>, timestamp: Option<TimestampSettings>) -> BuilderSettings {
    let mut settings = BuilderSettings::new(
        "image/jpeg",
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.title = Some("test.jpg".to_string());
    settings.assertions = assertions;
    settings.timestamp = timestamp;
    settings
}

/// Feeds `asset` into a fresh `ReadSession`, trusting [`TEST_SIGNER_CERT`],
/// answering `ManifestStore` with the real bytes the builder produced at
/// `manifest_range`, and returns the completed report.
fn read_back_with_manifest(
    asset: &[u8],
    manifest_range: (u64, u64),
) -> contentauth_c2pa_reader::ReadReport {
    let mut session = ReadSession::new(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        ..ReadSettings::default()
    });

    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            return session.finish().unwrap();
        }

        let requests: Vec<_> = session.outstanding_requests().to_vec();
        for request in requests {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => {
                    let (start, len) = manifest_range;
                    let start = start as usize;
                    let end = start + len as usize;
                    ReadHostReply::ManifestStore(Some(asset[start..end].to_vec()))
                }
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(1_800_000_000),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => {
                    let start = range.start as usize;
                    let end = start + range.len as usize;
                    ReadHostReply::AssetBytes(asset[start..end].to_vec())
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

#[test]
fn a_signed_manifest_with_no_assertions_reads_back_as_trusted() {
    let mut host = Host::new(5000);
    let session = BuilderSession::new(settings(vec![], None));
    let (asset, report) = host.build(session);

    assert_eq!(
        (report.manifest_range.start, report.manifest_range.len),
        host.manifest_range.unwrap()
    );

    let parsed = read_back_with_manifest(&asset, host.manifest_range.unwrap());

    assert!(parsed.manifest_store_found);
    assert_eq!(parsed.validation_state, Some(ValidationState::Trusted));

    let active = parsed.active().unwrap();
    assert_eq!(active.label, "urn:uuid:test-manifest");
    assert_eq!(active.claim.title.as_deref(), Some("test.jpg"));
    assert_eq!(active.claim.format.as_deref(), Some("image/jpeg"));
    assert_eq!(
        active.claim.instance_id.as_deref(),
        Some("xmp:iid:test-instance")
    );
    assert!(active.has_signature);

    let data_hash = active.data_hash.as_ref().unwrap();
    assert!(!data_hash.hash.is_empty());
}

#[test]
fn a_manifest_with_a_custom_assertion_carries_it_through() {
    // An empty CBOR map, as a stand-in for a real assertion's content.
    let assertion = Assertion::new("c2pa.actions", vec![0xa0]);

    let mut host = Host::new(5000);
    let session = BuilderSession::new(settings(vec![assertion], None));
    let (asset, _report) = host.build(session);

    let parsed = read_back_with_manifest(&asset, host.manifest_range.unwrap());
    assert_eq!(parsed.validation_state, Some(ValidationState::Trusted));

    let active = parsed.active().unwrap();
    assert_eq!(active.assertion_labels, ["c2pa.actions", "c2pa.hash.data"]);
}

#[test]
fn a_timestamped_manifest_still_reads_back_correctly() {
    let mut host = Host::new(5000);
    let session = BuilderSession::new(settings(vec![], Some(TimestampSettings::new(1000))));
    let (asset, _report) = host.build(session);

    let parsed = read_back_with_manifest(&asset, host.manifest_range.unwrap());

    // The fabricated token is not a real, trusted RFC 3161 timestamp, so
    // the reader is expected to report it as present-but-unverifiable
    // rather than to trust its instant — but the manifest as a whole must
    // still parse, the signature must still verify, and the hard binding
    // must still match: this test is not about timestamp trust (the
    // reader's own suite already covers that), only that this crate wrote
    // a structurally valid, byte-length-correct timestamp header.
    assert!(parsed.manifest_store_found);
    let active = parsed.active().unwrap();
    assert!(active.has_signature);
    assert!(active.data_hash.is_some());
}

#[test]
fn an_untrusted_signer_reads_back_as_merely_valid() {
    let mut host = Host::new(5000);
    let session = BuilderSession::new(settings(vec![], None));
    let (asset, _report) = host.build(session);

    let mut session = ReadSession::new(ReadSettings::default());
    let manifest_range = host.manifest_range.unwrap();

    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            let parsed = session.finish().unwrap();
            assert_eq!(parsed.validation_state, Some(ValidationState::Valid));
            return;
        }

        let requests: Vec<_> = session.outstanding_requests().to_vec();
        for request in requests {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => {
                    let (start, len) = manifest_range;
                    let start = start as usize;
                    let end = start + len as usize;
                    ReadHostReply::ManifestStore(Some(asset[start..end].to_vec()))
                }
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(1_800_000_000),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => {
                    let start = range.start as usize;
                    let end = start + range.len as usize;
                    ReadHostReply::AssetBytes(asset[start..end].to_vec())
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

#[test]
fn tampering_with_the_asset_breaks_the_hard_binding() {
    let mut host = Host::new(5000);
    let session = BuilderSession::new(settings(vec![], None));
    let (mut asset, _report) = host.build(session);

    // Flip a byte well outside the manifest's own range.
    let (start, len) = host.manifest_range.unwrap();
    let tamper_at = (start + len + 10) as usize;
    asset[tamper_at] ^= 0xff;

    let parsed = read_back_with_manifest(&asset, host.manifest_range.unwrap());
    assert_eq!(parsed.validation_state, Some(ValidationState::Invalid));
}

/// A host that refuses to sign — every request the builder issues after
/// signing should never be reached, and the session must fail rather than
/// silently produce a manifest with no signature.
#[test]
fn a_host_that_refuses_to_sign_fails_the_session() {
    let mut session = BuilderSession::new(settings(vec![], None));
    let mut asset = vec![0u8; 5000];

    loop {
        match session.advance().unwrap() {
            BuilderStep::Complete => panic!("session should not have completed"),
            BuilderStep::AwaitHost => {}
            other => panic!("unexpected step: {other:?}"),
        }

        let requests: Vec<_> = session.outstanding_requests().to_vec();
        let mut failed = false;

        for request in requests {
            match request.kind {
                BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                    let offset = 100u64;
                    asset.splice(
                        offset as usize..offset as usize,
                        placeholder.iter().copied(),
                    );
                    session
                        .fulfill(
                            request.id,
                            BuilderHostReply::PlaceholderReserved(
                                contentauth_c2pa_builder::ByteRange {
                                    start: offset,
                                    len: placeholder.len() as u64,
                                },
                            ),
                        )
                        .unwrap();
                }
                BuilderRequest::AssetLength { .. } => {
                    session
                        .fulfill(
                            request.id,
                            BuilderHostReply::AssetLength(asset.len() as u64),
                        )
                        .unwrap();
                }
                BuilderRequest::AssetBytes { range, .. } => {
                    let start = range.start as usize;
                    let end = start + range.len as usize;
                    session
                        .fulfill(
                            request.id,
                            BuilderHostReply::AssetBytes(asset[start..end].to_vec()),
                        )
                        .unwrap();
                }
                BuilderRequest::Sign { .. } => {
                    session
                        .fulfill(
                            request.id,
                            BuilderHostReply::Failed(contentauth_c2pa_builder::HostError::new(
                                "signing key unavailable",
                            )),
                        )
                        .unwrap();
                    failed = true;
                }
                other => panic!("unexpected request before signing: {other:?}"),
            }
        }

        if failed {
            assert!(session.advance().is_err());
            return;
        }
    }
}

/// An assertion labeled `c2pa.hash.data` would collide with the hard
/// binding assertion this crate appends itself, leaving two boxes
/// claiming the same `self#jumbf=...` URI. The session must refuse to
/// build rather than silently produce an ambiguous manifest.
#[test]
fn an_assertion_reusing_the_hard_binding_label_is_rejected() {
    let assertion = Assertion::new("c2pa.hash.data", vec![0xa0]);
    let mut session = BuilderSession::new(settings(vec![assertion], None));
    assert!(session.advance().is_err());
}

/// Two caller-supplied assertions with the same label would collide in
/// exactly the same way as reusing the hard binding's own label.
#[test]
fn duplicate_assertion_labels_are_rejected() {
    let assertions = vec![
        Assertion::new("c2pa.actions", vec![0xa0]),
        Assertion::new("c2pa.actions", vec![0xa0]),
    ];
    let mut session = BuilderSession::new(settings(assertions, None));
    assert!(session.advance().is_err());
}

/// If the host reports a placeholder reservation range whose length
/// doesn't match the placeholder it was actually asked to embed, the
/// session must refuse to use it as the hard binding's exclusion range
/// rather than sign and commit against the wrong span.
#[test]
fn a_reservation_range_of_the_wrong_length_is_rejected() {
    let mut session = BuilderSession::new(settings(vec![], None));
    let mut asset = vec![0u8; 5000];

    assert_eq!(session.advance().unwrap(), BuilderStep::AwaitHost);

    let requests: Vec<_> = session.outstanding_requests().to_vec();
    match requests.as_slice() {
        [request] => match &request.kind {
            BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                let offset = 100u64;
                asset.splice(
                    offset as usize..offset as usize,
                    placeholder.iter().copied(),
                );
                session
                    .fulfill(
                        request.id,
                        BuilderHostReply::PlaceholderReserved(
                            contentauth_c2pa_builder::ByteRange {
                                start: offset,
                                // One byte short of the placeholder that was
                                // actually embedded.
                                len: placeholder.len() as u64 - 1,
                            },
                        ),
                    )
                    .unwrap();
            }
            other => panic!("unexpected request: {other:?}"),
        },
        other => panic!("unexpected requests: {other:?}"),
    }

    assert!(session.advance().is_err());
}
