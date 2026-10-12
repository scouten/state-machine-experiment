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

//! CAWG identity assertions written by [`BuilderSession`] and read back by
//! `contentauth_c2pa_reader::ReadSession`: the same round trip as
//! `build_and_read_fixture.rs`, which is the crate's proof that two
//! independently written halves agree.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use contentauth_c2pa_builder::{
    Assertion, BuilderHostReply, BuilderRequest, BuilderSession, BuilderSettings, BuilderStep,
    ByteRange, Error, GeneratorInfo, HostError, IdentitySettings, SignPurpose, SigningAlg,
};
use contentauth_c2pa_reader::{
    identity::IdentityCredential as ReadCredential, ReadHostReply, ReadReport, ReadRequest,
    ReadSession, ReadSettings, ReadStep, ValidationState,
};
use contentauth_state_machine::Session;

const TEST_SIGNER_CERT: &[u8] = include_bytes!("fixtures/test-signer.der");
const TEST_SIGNER_KEY: &[u8] = include_bytes!("fixtures/test-signer.key.pem");

/// What a host does with an identity signing request.
#[derive(Clone, Copy)]
enum IdentityBehaviour {
    /// Signs what it is asked to.
    Honest,
    /// Signs something else, so the signature cannot verify.
    SignsOtherBytes,
}

/// A simulated host that records what it is asked to sign.
struct Host {
    asset: Vec<u8>,
    manifest_range: Option<(u64, u64)>,
    purposes: Vec<SignPurpose>,
    identity: IdentityBehaviour,
}

impl Host {
    fn new(identity: IdentityBehaviour) -> Self {
        Self {
            asset: (0..5000u32).map(|i| (i % 251) as u8).collect(),
            manifest_range: None,
            purposes: Vec::new(),
            identity,
        }
    }

    fn build(&mut self, mut session: BuilderSession) -> Result<(), Error> {
        loop {
            if session.advance()? == BuilderStep::Complete {
                session.finish()?;
                return Ok(());
            }

            for request in session.outstanding_requests().to_vec() {
                let reply = self.reply_to(&request.kind);
                session.fulfill(request.id, reply)?;
            }
        }
    }

    fn reply_to(&mut self, request: &BuilderRequest) -> BuilderHostReply {
        match request {
            BuilderRequest::ReservePlaceholder { placeholder, .. } => {
                let offset = 100u64;
                self.asset.splice(
                    offset as usize..offset as usize,
                    placeholder.iter().copied(),
                );
                self.manifest_range = Some((offset, placeholder.len() as u64));
                BuilderHostReply::PlaceholderReserved {
                    exclusions: vec![ByteRange {
                        start: offset,
                        len: placeholder.len() as u64,
                    }],
                    hash: None,
                }
            }

            BuilderRequest::AssetLength { .. } => {
                BuilderHostReply::AssetLength(self.asset.len() as u64)
            }

            BuilderRequest::AssetBytes { range, .. } => {
                let start = range.start as usize;
                BuilderHostReply::AssetBytes(self.asset[start..start + range.len as usize].to_vec())
            }

            BuilderRequest::Sign {
                purpose, alg, data, ..
            } => {
                self.purposes.push(purpose.clone());
                assert_eq!(*alg, SigningAlg::Es256);

                let signer = c2pa_raw_crypto::signer_from_private_key(
                    TEST_SIGNER_KEY,
                    c2pa_raw_crypto::SigningAlg::Es256,
                )
                .unwrap();

                let data = match (purpose, self.identity) {
                    (SignPurpose::Identity { .. }, IdentityBehaviour::SignsOtherBytes) => {
                        b"something else".to_vec()
                    }
                    _ => data.clone(),
                };
                BuilderHostReply::Signature(signer.sign(&data).unwrap())
            }

            BuilderRequest::CommitManifest {
                exclusions,
                manifest,
                ..
            } => {
                let range = exclusions[0];
                let start = range.start as usize;
                assert_eq!(manifest.len(), range.len as usize);
                self.asset[start..start + range.len as usize].copy_from_slice(manifest);
                BuilderHostReply::ManifestCommitted
            }

            other => panic!("unexpected request: {other:?}"),
        }
    }
}

fn settings(identities: Vec<IdentitySettings>) -> BuilderSettings {
    let mut settings = BuilderSettings::new(
        "xmp:iid:test-instance",
        "urn:uuid:test-manifest",
        GeneratorInfo::new("contentauth-c2pa-builder-tests", "0.1"),
        SigningAlg::Es256,
        vec![TEST_SIGNER_CERT.to_vec()],
    );
    settings.assertions = vec![
        Assertion::new("c2pa.actions", vec![0xa0]),
        Assertion::gathered("c2pa.metadata", vec![0xa0]),
    ];
    settings.identities = identities;
    settings
}

fn x509() -> IdentitySettings {
    IdentitySettings::x509(SigningAlg::Es256, vec![TEST_SIGNER_CERT.to_vec()])
}

/// Reads the asset back trusting the test signer for claims and, if
/// `trust_identity`, for identities.
fn read_back(host: &Host, trust_identity: bool) -> ReadReport {
    let (start, len) = host.manifest_range.unwrap();
    let asset = &host.asset;

    let mut session = ReadSession::new(ReadSettings {
        trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
        identity_trust_anchors: if trust_identity {
            vec![TEST_SIGNER_CERT.to_vec()]
        } else {
            vec![]
        },
        ..ReadSettings::default()
    });

    loop {
        if session.advance().unwrap() == ReadStep::Complete {
            return session.finish().unwrap();
        }

        for request in session.outstanding_requests().to_vec() {
            let reply = match request.kind {
                ReadRequest::ManifestStore { .. } => ReadHostReply::ManifestStore(Some(
                    asset[start as usize..(start + len) as usize].to_vec(),
                )),
                ReadRequest::CurrentDateTime => ReadHostReply::CurrentDateTime(1_800_000_000),
                ReadRequest::AssetLength { .. } => ReadHostReply::AssetLength(asset.len() as u64),
                ReadRequest::AssetBytes { range, .. } => ReadHostReply::AssetBytes(
                    asset[range.start as usize..(range.start + range.len) as usize].to_vec(),
                ),
                other => panic!("unexpected request: {other:?}"),
            };
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

fn identity_codes(report: &ReadReport) -> Vec<&str> {
    report
        .statuses
        .iter()
        .filter(|s| s.is_identity_finding())
        .map(|s| s.code.as_str())
        .collect()
}

#[test]
fn an_identity_assertion_reads_back_well_formed_and_trusted() {
    let mut identity = x509();
    identity.roles = vec!["creator".to_string()];

    let mut host = Host::new(IdentityBehaviour::Honest);
    host.build(BuilderSession::new(settings(vec![identity])))
        .unwrap();

    // The identity is signed first (the claim lists its hash), then the
    // claim, each told which key is wanted.
    assert_eq!(
        host.purposes,
        [
            SignPurpose::Identity {
                label: "cawg.identity".to_string()
            },
            SignPurpose::Claim
        ]
    );

    let report = read_back(&host, true);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(report.statuses.iter().all(|s| !s.is_failure()));
    assert_eq!(
        identity_codes(&report),
        [
            "cawg.x509.signature.validated",
            "cawg.identity.well-formed",
            "cawg.x509.credential.trusted"
        ]
    );

    let active = report.active().unwrap();
    assert!(active
        .assertion_labels
        .contains(&"cawg.identity".to_string()));
    assert!(active
        .claim
        .created_assertions
        .iter()
        .any(|r| r.url.ends_with("cawg.identity")));

    let [identity] = active.identity_assertions.as_slice() else {
        panic!("expected one identity assertion");
    };
    assert_eq!(identity.sig_type, "cawg.x509.cose");
    assert_eq!(identity.roles, ["creator"]);
    assert!(matches!(
        &identity.credential,
        ReadCredential::X509Cose { signer: Some(_) }
    ));

    // By default it vouches for every assertion, and the hard binding.
    let urls: Vec<_> = identity
        .referenced_assertions
        .iter()
        .map(|r| r.url.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(urls, ["c2pa.actions", "c2pa.metadata", "c2pa.hash.data"]);
}

#[test]
fn an_identity_signer_not_on_the_identity_list_is_untrusted_without_harming_the_manifest() {
    let mut host = Host::new(IdentityBehaviour::Honest);
    host.build(BuilderSession::new(settings(vec![x509()])))
        .unwrap();

    let report = read_back(&host, false);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(identity_codes(&report).contains(&"cawg.x509.credential.untrusted"));
}

#[test]
fn several_identities_are_each_signed_and_labelled_in_order() {
    let mut second = x509();
    second.referenced_assertions = Some(vec!["c2pa.actions".to_string()]);
    second.roles = vec!["editor".to_string(), "publisher".to_string()];

    let mut host = Host::new(IdentityBehaviour::Honest);
    host.build(BuilderSession::new(settings(vec![x509(), second])))
        .unwrap();

    assert_eq!(
        host.purposes,
        [
            SignPurpose::Identity {
                label: "cawg.identity".to_string()
            },
            SignPurpose::Identity {
                label: "cawg.identity__1".to_string()
            },
            SignPurpose::Claim
        ]
    );

    let report = read_back(&host, true);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
    assert!(report.statuses.iter().all(|s| !s.is_failure()));

    let identities = &report.active().unwrap().identity_assertions;
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0].label, "cawg.identity");
    assert_eq!(identities[0].referenced_assertions.len(), 3);
    assert_eq!(identities[1].label, "cawg.identity__1");
    assert_eq!(identities[1].roles, ["editor", "publisher"]);
    // Only what it named, and the hard binding.
    assert_eq!(identities[1].referenced_assertions.len(), 2);
}

#[test]
fn an_identity_that_vouches_for_nothing_but_the_hard_binding_is_valid() {
    let mut only_binding = x509();
    only_binding.referenced_assertions = Some(vec![]);

    let mut host = Host::new(IdentityBehaviour::Honest);
    host.build(BuilderSession::new(settings(vec![only_binding])))
        .unwrap();

    let report = read_back(&host, true);
    assert!(report.statuses.iter().all(|s| !s.is_failure()));
    assert_eq!(
        report.active().unwrap().identity_assertions[0]
            .referenced_assertions
            .len(),
        1
    );
}

#[test]
fn a_host_that_signs_the_wrong_bytes_produces_an_identity_the_reader_rejects() {
    let mut host = Host::new(IdentityBehaviour::SignsOtherBytes);
    host.build(BuilderSession::new(settings(vec![x509()])))
        .unwrap();

    let report = read_back(&host, true);

    // The assertion fails; the manifest, whose own signature and binding
    // are fine, does not.
    assert_eq!(identity_codes(&report), ["cawg.x509.signature.mismatch"]);
    assert_eq!(report.validation_state, Some(ValidationState::Trusted));
}

#[test]
fn a_session_with_no_identities_never_asks_for_an_identity_signature() {
    let mut host = Host::new(IdentityBehaviour::Honest);
    host.build(BuilderSession::new(settings(vec![]))).unwrap();

    assert_eq!(host.purposes, [SignPurpose::Claim]);
    assert!(read_back(&host, true)
        .active()
        .unwrap()
        .identity_assertions
        .is_empty());
}

fn start_error(settings: BuilderSettings) -> Error {
    BuilderSession::new(settings).advance().unwrap_err()
}

#[test]
fn naming_an_assertion_that_does_not_exist_is_refused() {
    let mut identity = x509();
    identity.referenced_assertions = Some(vec!["c2pa.nothing".to_string()]);

    assert!(matches!(
        start_error(settings(vec![identity])),
        Error::UnknownReferencedAssertion(label) if label == "c2pa.nothing"
    ));
}

#[test]
fn naming_an_assertion_twice_is_refused() {
    let mut identity = x509();
    identity.referenced_assertions = Some(vec![
        "c2pa.actions".to_string(),
        "c2pa.metadata".to_string(),
        "c2pa.actions".to_string(),
    ]);

    assert!(matches!(
        start_error(settings(vec![identity])),
        Error::DuplicateReferencedAssertion(label) if label == "c2pa.actions"
    ));
}

#[test]
fn a_host_assertion_cannot_take_an_identity_assertions_label() {
    let mut s = settings(vec![x509(), x509()]);
    s.assertions
        .push(Assertion::new("cawg.identity__1", vec![0xa0]));

    assert!(matches!(
        start_error(s),
        Error::InvalidAssertionLabel(label) if label == "cawg.identity__1"
    ));

    // Without a second identity, that label is free for the host.
    let mut s = settings(vec![x509()]);
    s.assertions
        .push(Assertion::new("cawg.identity__1", vec![0xa0]));
    assert!(BuilderSession::new(s).advance().is_ok());
}

#[test]
fn an_identity_credential_with_no_certificates_is_refused() {
    let identity = IdentitySettings::x509(SigningAlg::Es256, vec![]);
    assert!(matches!(
        start_error(settings(vec![identity])),
        Error::NoCertificates
    ));
}

#[test]
fn an_rsa_identity_credential_needs_its_signature_length() {
    let identity = IdentitySettings::x509(SigningAlg::Ps256, vec![TEST_SIGNER_CERT.to_vec()]);
    assert!(matches!(
        start_error(settings(vec![identity])),
        Error::MissingRsaSignatureLen(SigningAlg::Ps256)
    ));
}

/// Drives a session to its first identity `Sign` request and returns the
/// session with that request's id.
fn session_at_identity_signature() -> (BuilderSession, contentauth_c2pa_builder::RequestId) {
    let mut host = Host::new(IdentityBehaviour::Honest);
    let mut session = BuilderSession::new(settings(vec![x509()]));

    loop {
        assert_eq!(session.advance().unwrap(), BuilderStep::AwaitHost);

        for request in session.outstanding_requests().to_vec() {
            if matches!(
                request.kind,
                BuilderRequest::Sign {
                    purpose: SignPurpose::Identity { .. },
                    ..
                }
            ) {
                return (session, request.id);
            }
            let reply = host.reply_to(&request.kind);
            session.fulfill(request.id, reply).unwrap();
        }
    }
}

#[test]
fn a_failed_identity_signature_fails_the_build() {
    let (mut session, id) = session_at_identity_signature();

    session
        .fulfill(
            id,
            BuilderHostReply::Failed(HostError::new("identity key unavailable")),
        )
        .unwrap();

    assert!(matches!(
        session.advance().unwrap_err(),
        Error::HostFailure { .. }
    ));
}

#[test]
fn an_identity_signature_of_the_wrong_length_fails_the_build() {
    let (mut session, id) = session_at_identity_signature();

    session
        .fulfill(id, BuilderHostReply::Signature(vec![0; 63]))
        .unwrap();

    assert!(matches!(
        session.advance().unwrap_err(),
        Error::SignatureLengthMismatch {
            expected: 64,
            actual: 63
        }
    ));
}

#[test]
fn an_identity_request_stays_outstanding_until_answered() {
    let (mut session, _id) = session_at_identity_signature();

    assert_eq!(session.advance().unwrap(), BuilderStep::AwaitHost);
    assert_eq!(session.outstanding_requests().len(), 1);
}
