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

//! CAWG identity assertions: reading them, and verifying the credential
//! each one carries.
//!
//! An identity assertion (`cawg.identity`, or `cawg.identity__1` and so on
//! when a manifest carries several) is a named actor's signed statement
//! that they stand behind particular assertions in a manifest. Its CBOR
//! has a `signer_payload` — the assertions it vouches for, as hashed URIs,
//! a `sig_type` naming the kind of credential, and optionally `role`s —
//! plus a `signature` over that payload whose meaning the `sig_type`
//! decides, and zero-filled `pad1`/`pad2`.
//!
//! # Two layers, and where the third credential type goes
//!
//! Everything *not* specific to a credential type lives here: decoding the
//! assertion, checking its padding, and checking that what it references
//! is really in the claim, unaltered, with a hard binding among it. What
//! the `signature` *is* is dispatched on `sig_type` in one place,
//! `check_assertion`:
//!
//! * `cawg.x509.cose` — the `x509` module, implemented.
//! * `cawg.identity_claims_aggregation` — recognised and reported as not
//!   checked ([`IdentityCredential::IdentityClaimsAggregation`]). It is a
//!   W3C verifiable credential whose issuer is a DID, so verifying it needs
//!   the network; when it lands it will bring its own request variants
//!   rather than change anything here.
//! * anything else — reported as unknown, which the specification makes a
//!   failure of that assertion alone.
//!
//! A new credential type is one module like `x509`, one arm of that
//! `match`, and one [`IdentityCredential`] variant.
//!
//! # Scope of a failure
//!
//! Every finding here concerns one identity assertion, and a failure never
//! lowers the store's [`ValidationState`](crate::ValidationState): a bad
//! identity claim says that named actor is not to be believed, not that
//! the content credential is. See
//! [`ValidationStatus::affects_validation_state`].

mod cbor;
pub(crate) mod x509;

use std::collections::HashSet;

use c2pa_cbor::Value;
use jumbf::parser::SuperBox;

use crate::{
    chain::PendingChain,
    claim::{self, Claim, HashedUri},
    manifest_store::{child_superboxes, content, CBOR},
    validation::{assertion_path, status_code, ValidationStatus},
};

/// Label of the first identity assertion in a manifest; later ones are
/// `cawg.identity__1`, `cawg.identity__2`, ….
pub const LABEL: &str = "cawg.identity";

/// `sig_type` of an X.509 credential signed as a `COSE_Sign1`.
pub const SIG_TYPE_X509_COSE: &str = "cawg.x509.cose";

/// `sig_type` of an identity claims aggregation credential.
pub const SIG_TYPE_IDENTITY_CLAIMS_AGGREGATION: &str = "cawg.identity_claims_aggregation";

/// Returns true if `label` names an identity assertion.
pub fn is_identity_label(label: &str) -> bool {
    label == LABEL || label.starts_with("cawg.identity__")
}

/// One identity assertion read out of a manifest.
///
/// Describes what the assertion *claims*. Whether the claim holds is in
/// the report's statuses, each of which names this assertion by
/// [`Self::url`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct IdentityAssertion {
    /// The assertion's label within its manifest, such as
    /// `cawg.identity`.
    pub label: String,

    /// The JUMBF URI the assertion's validation statuses carry.
    pub url: String,

    /// The `sig_type`, verbatim.
    pub sig_type: String,

    /// What kind of credential `sig_type` names.
    pub credential: IdentityCredential,

    /// The `role`s the named actor claims, if any.
    pub roles: Vec<String>,

    /// The assertions this one vouches for.
    pub referenced_assertions: Vec<HashedUri>,
}

/// The kind of credential an identity assertion carries.
///
/// Decided by `sig_type`; see the [module documentation](self) for how a
/// new kind is added.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IdentityCredential {
    /// `cawg.x509.cose`: an X.509 certificate chain and a `COSE_Sign1`.
    X509Cose {
        /// The subject of the signer's certificate (in RFC 4514 form), if
        /// the signature verified; `None` otherwise, since nothing says
        /// the certificate is the one that signed.
        signer: Option<String>,
    },

    /// `cawg.identity_claims_aggregation`: recognised, but this crate
    /// cannot yet verify it.
    IdentityClaimsAggregation,

    /// A `sig_type` this crate does not recognise.
    Unknown,
}

/// Everything the manifest reader learns from a manifest's identity
/// assertions.
#[derive(Debug, Default)]
pub(crate) struct Findings {
    /// The assertions that could be read, in store order.
    pub(crate) assertions: Vec<IdentityAssertion>,
}

/// Reads and checks each identity assertion in a manifest's assertion
/// store, recording findings and queueing each verified X.509 chain for
/// the session to evaluate once it has a time.
pub(crate) fn check_manifest(
    manifest_label: &str,
    assertions: Option<&SuperBox<'_>>,
    claim: &Claim,
    statuses: &mut Vec<ValidationStatus>,
    chains: &mut Vec<PendingChain>,
) -> Findings {
    let mut findings = Findings::default();

    let Some(assertions) = assertions else {
        return findings;
    };

    for assertion in child_superboxes(assertions) {
        let Some(label) = assertion.desc.label.filter(|l| is_identity_label(l)) else {
            continue;
        };

        let url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}");

        let Some(cbor) = content(assertion, CBOR) else {
            statuses.push(ValidationStatus::for_url(
                status_code::CAWG_IDENTITY_CBOR_INVALID,
                &url,
                "identity assertion has no CBOR content",
            ));
            continue;
        };

        if let Some(summary) =
            check_assertion(manifest_label, label, &url, cbor, claim, statuses, chains)
        {
            findings.assertions.push(summary);
        }
    }

    findings
}

/// The fields of an identity assertion that checking needs.
struct Decoded<'a> {
    /// The `signer_payload`'s bytes exactly as encoded, which is what the
    /// signature covers.
    signer_payload: &'a [u8],
    sig_type: String,
    roles: Vec<String>,
    referenced: Vec<HashedUri>,
    signature: Vec<u8>,
    padding_is_zero: bool,
}

/// Decodes an identity assertion's CBOR, or says why it cannot be.
fn decode(cbor: &[u8]) -> Result<Decoded<'_>, &'static str> {
    let value: Value = c2pa_cbor::from_slice(cbor).map_err(|_| "assertion is not valid CBOR")?;
    let map = value.as_map().ok_or("assertion is not a map")?;
    let field = |name: &str| {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(name))
            .map(|(_, v)| v)
    };

    let payload = field("signer_payload")
        .and_then(Value::as_map)
        .ok_or("signer_payload is missing or not a map")?;
    let payload_field = |name: &str| {
        payload
            .iter()
            .find(|(k, _)| k.as_str() == Some(name))
            .map(|(_, v)| v)
    };

    let sig_type = payload_field("sig_type")
        .and_then(Value::as_str)
        .ok_or("sig_type is missing or not text")?
        .to_string();

    let referenced = claim::hashed_uri_array(
        payload_field("referenced_assertions").ok_or("referenced_assertions is missing")?,
        "referenced_assertions",
    )
    .map_err(|_| "referenced_assertions is malformed")?;

    let roles = match payload_field("role") {
        None => Vec::new(),
        Some(roles) => roles
            .as_array()
            .ok_or("role is not an array")?
            .iter()
            .map(|r| {
                r.as_str()
                    .map(str::to_string)
                    .ok_or("role entry is not text")
            })
            .collect::<Result<_, _>>()?,
    };

    let Some(Value::Bytes(signature)) = field("signature") else {
        return Err("signature is missing or not a byte string");
    };
    let Some(Value::Bytes(pad1)) = field("pad1") else {
        return Err("pad1 is missing or not a byte string");
    };
    let pad2 = match field("pad2") {
        None => &[][..],
        Some(Value::Bytes(pad2)) => pad2.as_slice(),
        Some(_) => return Err("pad2 is not a byte string"),
    };

    Ok(Decoded {
        // `signer_payload` was just found by decoding, so locating its
        // bytes cannot fail for a definite-length encoding; one that uses
        // indefinite lengths is refused here as it is for a signature.
        signer_payload: cbor::map_value(cbor, "signer_payload")
            .ok_or("signer_payload uses an encoding this crate cannot locate")?,
        sig_type,
        roles,
        referenced,
        signature: signature.clone(),
        padding_is_zero: pad1.iter().chain(pad2).all(|b| *b == 0),
    })
}

/// Checks one identity assertion, returning its summary unless its CBOR
/// could not be read at all.
fn check_assertion(
    manifest_label: &str,
    label: &str,
    url: &str,
    cbor: &[u8],
    claim: &Claim,
    statuses: &mut Vec<ValidationStatus>,
    chains: &mut Vec<PendingChain>,
) -> Option<IdentityAssertion> {
    let decoded = match decode(cbor) {
        Ok(decoded) => decoded,
        Err(reason) => {
            statuses.push(ValidationStatus::for_url(
                status_code::CAWG_IDENTITY_CBOR_INVALID,
                url,
                reason,
            ));
            return None;
        }
    };

    let first_finding = statuses.len();

    if !decoded.padding_is_zero {
        statuses.push(ValidationStatus::for_url(
            status_code::CAWG_IDENTITY_PAD_INVALID,
            url,
            "pad1 or pad2 holds a byte other than zero",
        ));
    }

    check_references(&decoded.referenced, claim, url, statuses);

    let mut signer = None;
    let mut signature_verified = false;

    let credential = match decoded.sig_type.as_str() {
        SIG_TYPE_X509_COSE => {
            if let Some(verified) =
                x509::verify(url, decoded.signer_payload, &decoded.signature, statuses)
            {
                signature_verified = true;
                signer = verified.certificates.first().map(|c| c.subject.clone());
                chains.push(PendingChain {
                    manifest_label: manifest_label.to_string(),
                    url: url.to_string(),
                    certificates: verified.certificates,
                    timestamp: verified.timestamp,
                    rvals: Vec::new(),
                });
            }
            IdentityCredential::X509Cose { signer }
        }

        SIG_TYPE_IDENTITY_CLAIMS_AGGREGATION => {
            statuses.push(ValidationStatus::for_url(
                status_code::CAWG_IDENTITY_SIG_TYPE_UNSUPPORTED,
                url,
                "identity claims aggregation credentials are not verified by this crate",
            ));
            IdentityCredential::IdentityClaimsAggregation
        }

        other => {
            statuses.push(ValidationStatus::for_url(
                status_code::CAWG_IDENTITY_SIG_TYPE_UNKNOWN,
                url,
                format!("signature type {other:?} is not recognised"),
            ));
            IdentityCredential::Unknown
        }
    };

    if signature_verified
        && !statuses[first_finding..]
            .iter()
            .any(ValidationStatus::is_failure)
    {
        statuses.push(ValidationStatus::for_url(
            status_code::CAWG_IDENTITY_WELL_FORMED,
            url,
            "identity assertion is well formed and its signature verified",
        ));
    }

    Some(IdentityAssertion {
        label: label.to_string(),
        url: url.to_string(),
        sig_type: decoded.sig_type,
        credential,
        roles: decoded.roles,
        referenced_assertions: decoded.referenced,
    })
}

/// Checks that what an identity assertion vouches for is really what the
/// claim lists, that a hard binding is among it, and that nothing is named
/// twice.
fn check_references(
    referenced: &[HashedUri],
    claim: &Claim,
    url: &str,
    statuses: &mut Vec<ValidationStatus>,
) {
    let mut seen = HashSet::new();

    for reference in referenced {
        let path = assertion_path(&reference.url).unwrap_or(&reference.url);

        if !seen.insert(path) {
            statuses.push(ValidationStatus::for_url(
                status_code::CAWG_IDENTITY_ASSERTION_DUPLICATE,
                url,
                format!("{} is referenced more than once", reference.url),
            ));
        }

        // The claim's own hashes were verified against the assertions
        // themselves when the manifest was read, so agreeing with the
        // claim is agreeing with the bytes.
        let in_claim = claim
            .assertion_references()
            .find(|candidate| assertion_path(&candidate.url) == Some(path));

        match in_claim {
            None => statuses.push(ValidationStatus::for_url(
                status_code::CAWG_IDENTITY_ASSERTION_MISMATCH,
                url,
                format!("{} is not an assertion of this claim", reference.url),
            )),
            Some(candidate) if candidate.hash != reference.hash => {
                statuses.push(ValidationStatus::for_url(
                    status_code::CAWG_IDENTITY_ASSERTION_MISMATCH,
                    url,
                    format!("{} does not hash to what the claim records", reference.url),
                ))
            }
            Some(_) => {}
        }
    }

    if !referenced.iter().any(|r| is_hard_binding(&r.url)) {
        statuses.push(ValidationStatus::for_url(
            status_code::CAWG_IDENTITY_HARD_BINDING_MISSING,
            url,
            "identity assertion references no hard binding assertion",
        ));
    }
}

/// Returns true if `url` names a hard binding assertion: `c2pa.hash.data`,
/// `c2pa.hash.bmff` and its versions, `c2pa.hash.boxes`,
/// `c2pa.hash.collection.data` — all the `c2pa.hash.*` labels — whatever
/// its `__n` instance suffix.
fn is_hard_binding(url: &str) -> bool {
    url.rsplit('/')
        .next()
        .is_some_and(|label| label.starts_with("c2pa.hash."))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use c2pa_cbor::Value;

    use super::*;
    use crate::{
        manifest_store::{self, ParsedManifestStore},
        read::{ReadSession, ReadSettings, TrustList},
        request::{ReadHostReply, ReadRequest},
        test_support::{
            assertion_box, boxed, identity_box, identity_manifest, identity_manifest_from,
            manifest_store as store_of, superbox, type_uuid, IdentityParts, IDENTITY_ASSET,
            TEST_SIGNER_CERT,
        },
        validation::ValidationState,
        ReadReport, ReadStep, Session,
    };

    /// An instant inside the test signer's validity window.
    const NOW: i64 = 1_800_000_000;

    /// Reads a manifest store the way a host would, answering only the
    /// manifest store and the clock (`None` fails the clock request).
    fn read(manifest: Vec<u8>, settings: ReadSettings, now: Option<i64>) -> ReadReport {
        let bytes = store_of(&[manifest]);
        let mut session = ReadSession::new(settings);

        loop {
            if session.advance().unwrap() == ReadStep::Complete {
                return session.finish().unwrap();
            }

            let asks: Vec<_> = session
                .outstanding_requests()
                .iter()
                .map(|r| (r.id, r.kind.clone()))
                .collect();

            for (id, request) in asks {
                let reply = match (request, now) {
                    (ReadRequest::ManifestStore { .. }, _) => {
                        ReadHostReply::ManifestStore(Some(bytes.clone()))
                    }
                    (ReadRequest::AssetLength { .. }, _) => {
                        ReadHostReply::AssetLength(IDENTITY_ASSET.len() as u64)
                    }
                    (ReadRequest::AssetBytes { range, .. }, _) => ReadHostReply::AssetBytes(
                        IDENTITY_ASSET[range.start as usize..(range.start + range.len) as usize]
                            .to_vec(),
                    ),
                    (ReadRequest::CurrentDateTime, Some(now)) => {
                        ReadHostReply::CurrentDateTime(now)
                    }
                    (ReadRequest::CurrentDateTime, None) => {
                        ReadHostReply::Failed(crate::HostError::new("no clock"))
                    }
                    (other, _) => panic!("unexpected request {other:?}"),
                };
                session.fulfill(id, reply).unwrap();
            }
        }
    }

    fn identity_anchored() -> ReadSettings {
        ReadSettings {
            identity_trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
            ..ReadSettings::default()
        }
    }

    fn parse_one(manifest: Vec<u8>) -> ParsedManifestStore {
        manifest_store::parse(&store_of(&[manifest])).unwrap()
    }

    fn codes(report: &ReadReport) -> Vec<&str> {
        report
            .statuses
            .iter()
            .filter(|s| s.is_identity_finding())
            .map(|s| s.code.as_str())
            .collect()
    }

    fn identity_codes(parsed: &ParsedManifestStore) -> Vec<&str> {
        parsed
            .statuses
            .iter()
            .filter(|s| s.is_identity_finding())
            .map(|s| s.code.as_str())
            .collect()
    }

    // ---- reading ---------------------------------------------------------

    #[test]
    fn a_well_formed_assertion_is_read_and_verified() {
        let parsed = parse_one(identity_manifest(|p| p.roles = vec!["creator".into()]));

        assert_eq!(
            identity_codes(&parsed),
            ["cawg.x509.signature.validated", "cawg.identity.well-formed"]
        );
        assert!(parsed.statuses.iter().all(|s| !s.is_failure()));

        let identity = &parsed.manifests[0].identity_assertions[0];
        assert_eq!(identity.label, "cawg.identity");
        assert_eq!(
            identity.url,
            "self#jumbf=/c2pa/urn:uuid:identity/c2pa.assertions/cawg.identity"
        );
        assert_eq!(identity.sig_type, SIG_TYPE_X509_COSE);
        assert_eq!(identity.roles, ["creator"]);
        assert_eq!(identity.referenced_assertions.len(), 2);
        assert!(matches!(
            &identity.credential,
            IdentityCredential::X509Cose { signer: Some(_) }
        ));

        // The verified chain is queued for the session to judge.
        assert_eq!(parsed.identity_chains.len(), 1);
        assert_eq!(parsed.identity_chains[0].url, identity.url);
    }

    #[test]
    fn a_manifest_without_identity_assertions_has_none_and_queues_nothing() {
        let parsed = parse_one(crate::test_support::manifest(
            "urn:uuid:plain",
            "p.jpg",
            &[],
        ));

        assert!(parsed.manifests[0].identity_assertions.is_empty());
        assert!(parsed.identity_chains.is_empty());
    }

    #[test]
    fn identity_labels_include_numbered_instances_only() {
        assert!(is_identity_label("cawg.identity"));
        assert!(is_identity_label("cawg.identity__1"));
        assert!(!is_identity_label("cawg.identity.other"));
        assert!(!is_identity_label("cawg.identit"));
        assert!(!is_identity_label("c2pa.actions"));
    }

    #[test]
    fn several_identity_assertions_are_all_read() {
        let parts = IdentityParts::default();
        let manifest = identity_manifest_from(
            &parts,
            vec![
                identity_box("cawg.identity", &parts),
                identity_box("cawg.identity__1", &parts),
            ],
        );

        let parsed = parse_one(manifest);
        let labels: Vec<_> = parsed.manifests[0]
            .identity_assertions
            .iter()
            .map(|i| i.label.as_str())
            .collect();

        assert_eq!(labels, ["cawg.identity", "cawg.identity__1"]);
        assert_eq!(parsed.identity_chains.len(), 2);
    }

    #[test]
    fn a_manifest_with_no_assertion_store_is_not_an_error() {
        let findings = check_manifest(
            "urn:uuid:x",
            None,
            &Claim::default(),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(findings.assertions.is_empty());
    }

    // ---- cbor ------------------------------------------------------------

    fn cbor_invalid_reason(adjust: impl FnOnce(&mut IdentityParts)) -> String {
        let parsed = parse_one(identity_manifest(adjust));

        assert!(parsed.manifests[0].identity_assertions.is_empty());
        assert!(parsed.identity_chains.is_empty());

        let finding = parsed
            .statuses
            .iter()
            .find(|s| s.code == status_code::CAWG_IDENTITY_CBOR_INVALID)
            .unwrap();
        assert!(finding.is_failure());
        finding.explanation.clone().unwrap()
    }

    #[test]
    fn assertions_that_are_not_the_schema_are_cbor_invalid() {
        let raw = |bytes: &[u8]| {
            let bytes = bytes.to_vec();
            move |p: &mut IdentityParts| p.raw_cbor = Some(bytes)
        };

        assert_eq!(
            cbor_invalid_reason(raw(&[0xff, 0xff])),
            "assertion is not valid CBOR"
        );
        assert_eq!(cbor_invalid_reason(raw(&[0x01])), "assertion is not a map");
        assert_eq!(
            cbor_invalid_reason(raw(&[0xa0])),
            "signer_payload is missing or not a map"
        );
    }

    #[test]
    fn each_required_field_is_checked() {
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_payload = Some(|m| {
                m.remove(&Value::Text("sig_type".into()));
            })),
            "sig_type is missing or not text"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_payload = Some(|m| {
                m.remove(&Value::Text("referenced_assertions".into()));
            })),
            "referenced_assertions is missing"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_payload = Some(|m| {
                m.insert(
                    Value::Text("referenced_assertions".into()),
                    Value::Text("no".into()),
                );
            })),
            "referenced_assertions is malformed"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_payload = Some(|m| {
                m.insert(Value::Text("role".into()), Value::Text("creator".into()));
            })),
            "role is not an array"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_payload = Some(|m| {
                m.insert(
                    Value::Text("role".into()),
                    Value::Array(vec![Value::Integer(1)]),
                );
            })),
            "role entry is not text"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_assertion = Some(|m| {
                m.remove(&Value::Text("signature".into()));
            })),
            "signature is missing or not a byte string"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_assertion = Some(|m| {
                m.remove(&Value::Text("pad1".into()));
            })),
            "pad1 is missing or not a byte string"
        );
        assert_eq!(
            cbor_invalid_reason(|p| p.edit_assertion = Some(|m| {
                m.insert(Value::Text("pad2".into()), Value::Integer(0));
            })),
            "pad2 is not a byte string"
        );
    }

    #[test]
    fn a_payload_encoded_with_indefinite_lengths_is_read_from_its_own_bytes() {
        // `signer_payload` as an indefinite-length map: valid CBOR whose
        // signed bytes are the ones as written, which is why they are
        // located rather than re-encoded. The signature here is empty, so
        // it is the signature, not the encoding, that is refused.
        let mut raw = vec![0xa3];
        raw.extend_from_slice(&[0x6e]);
        raw.extend_from_slice(b"signer_payload");
        raw.extend_from_slice(&[0xbf, 0x68]);
        raw.extend_from_slice(b"sig_type");
        raw.extend_from_slice(&[0x6e]);
        raw.extend_from_slice(b"cawg.x509.cose");
        raw.extend_from_slice(&[0x75]);
        raw.extend_from_slice(b"referenced_assertions");
        raw.extend_from_slice(&[0x80, 0xff]);
        raw.extend_from_slice(&[0x69]);
        raw.extend_from_slice(b"signature");
        raw.extend_from_slice(&[0x40]);
        raw.extend_from_slice(&[0x64]);
        raw.extend_from_slice(b"pad1");
        raw.extend_from_slice(&[0x40]);

        let parsed = parse_one(identity_manifest(|p| p.raw_cbor = Some(raw)));

        assert_eq!(
            identity_codes(&parsed),
            [
                "cawg.identity.hard_binding_missing",
                "cawg.x509.credential.invalid"
            ]
        );
        assert_eq!(parsed.manifests[0].identity_assertions.len(), 1);
    }

    #[test]
    fn a_payload_in_another_key_order_is_verified_as_signed() {
        // c2pa-rs's order puts `role` last; a sorted encoding puts it
        // before `sig_type`. Either must verify, which only holds if the
        // signed bytes are the ones in the assertion.
        let parsed = parse_one(identity_manifest(|p| {
            p.roles = vec!["creator".into()];
            p.sign_instead = None;
        }));
        assert!(parsed.statuses.iter().all(|s| !s.is_failure()));
    }

    #[test]
    fn an_identity_assertion_box_with_no_cbor_is_cbor_invalid() {
        let parts = IdentityParts::default();
        let empty = superbox(type_uuid(*b"cbor"), "cawg.identity", &[]);
        let parsed = parse_one(identity_manifest_from(&parts, vec![empty]));

        assert_eq!(identity_codes(&parsed), ["cawg.identity.cbor.invalid"]);
        assert!(parsed.manifests[0].identity_assertions.is_empty());
    }

    // ---- references and padding -----------------------------------------

    fn failure_codes(adjust: impl FnOnce(&mut IdentityParts)) -> Vec<String> {
        parse_one(identity_manifest(adjust))
            .statuses
            .iter()
            .filter(|s| s.is_identity_finding() && s.is_failure())
            .map(|s| s.code.clone())
            .collect()
    }

    #[test]
    fn nonzero_padding_is_flagged_in_either_field() {
        assert_eq!(
            failure_codes(|p| p.pad1 = vec![0, 1]),
            ["cawg.identity.pad.invalid"]
        );
        assert_eq!(
            failure_codes(|p| p.pad2 = Some(vec![0, 0, 2])),
            ["cawg.identity.pad.invalid"]
        );
        assert!(failure_codes(|p| {
            p.pad1 = vec![0; 8];
            p.pad2 = Some(vec![0; 3]);
        })
        .is_empty());
    }

    #[test]
    fn a_reference_whose_hash_differs_from_the_claims_is_a_mismatch() {
        assert_eq!(
            failure_codes(|p| p.referenced[0].1 = vec![0; 32]),
            ["cawg.identity.assertion.mismatch"]
        );
    }

    #[test]
    fn a_reference_to_an_assertion_the_claim_does_not_list_is_a_mismatch() {
        assert_eq!(
            failure_codes(|p| p.omit_from_claim = vec!["a.test".to_string()]),
            ["cawg.identity.assertion.mismatch"]
        );
        assert_eq!(
            failure_codes(|p| p.referenced.push(("nowhere".to_string(), vec![1]))),
            ["cawg.identity.assertion.mismatch"]
        );
    }

    #[test]
    fn an_assertion_may_be_referenced_by_its_absolute_uri() {
        // The claim names `self#jumbf=c2pa.assertions/a.test`; the identity
        // assertion may name the same box absolutely.
        let codes = failure_codes(|p| {
            p.edit_payload = Some(|m| {
                let Some(Value::Array(refs)) =
                    m.get_mut(&Value::Text("referenced_assertions".into()))
                else {
                    panic!("no references")
                };
                if let Value::Map(first) = &mut refs[0] {
                    first.insert(
                        Value::Text("url".into()),
                        Value::Text(
                            "self#jumbf=/c2pa/urn:uuid:identity/c2pa.assertions/a.test".into(),
                        ),
                    );
                }
            });
        });
        assert!(codes.is_empty(), "{codes:?}");
    }

    #[test]
    fn referencing_no_hard_binding_is_flagged_for_every_hard_binding_label() {
        assert_eq!(
            failure_codes(|p| p.referenced.truncate(1)),
            ["cawg.identity.hard_binding_missing"]
        );

        for label in [
            "c2pa.hash.bmff.v2",
            "c2pa.hash.boxes",
            "c2pa.hash.collection.data",
        ] {
            let mut parts = IdentityParts::default();
            parts.referenced.truncate(1);
            parts.omit_from_claim.push("c2pa.hash.data".into());
            parts.referenced.push((label.to_string(), vec![1]));

            // Naming a hard binding of some kind satisfies that check (the
            // claim does not list it, which is a separate finding).
            let codes: Vec<_> = parse_one(identity_manifest_from(
                &parts,
                vec![identity_box("cawg.identity", &parts)],
            ))
            .statuses
            .iter()
            .filter(|s| s.code == status_code::CAWG_IDENTITY_HARD_BINDING_MISSING)
            .map(|s| s.code.clone())
            .collect();
            assert!(codes.is_empty(), "{label}");
        }
    }

    #[test]
    fn referencing_an_assertion_twice_is_flagged() {
        assert_eq!(
            failure_codes(|p| {
                let first = p.referenced[0].clone();
                p.referenced.push(first);
            }),
            ["cawg.identity.assertion.duplicate"]
        );
    }

    // ---- credential types -------------------------------------------------

    #[test]
    fn an_unknown_sig_type_is_a_failure_of_that_assertion_alone() {
        let parsed = parse_one(identity_manifest(|p| p.sig_type = "example.vendor".into()));

        assert_eq!(identity_codes(&parsed), ["cawg.identity.sig_type.unknown"]);
        assert!(parsed.statuses.iter().any(ValidationStatus::is_failure));
        assert!(parsed.identity_chains.is_empty());

        let identity = &parsed.manifests[0].identity_assertions[0];
        assert_eq!(identity.credential, IdentityCredential::Unknown);
        assert_eq!(identity.sig_type, "example.vendor");
    }

    #[test]
    fn an_identity_claims_aggregation_credential_is_recognised_but_not_checked() {
        let parsed = parse_one(identity_manifest(|p| {
            p.sig_type = SIG_TYPE_IDENTITY_CLAIMS_AGGREGATION.into()
        }));

        assert_eq!(
            identity_codes(&parsed),
            ["cawg.identity.sig_type.unsupported"]
        );
        // Not checked is neither a pass nor a failure.
        assert!(parsed.statuses.iter().all(|s| !s.is_failure()));
        assert!(parsed.statuses.iter().all(|s| !s.is_unchecked()));
        assert_eq!(
            parsed.manifests[0].identity_assertions[0].credential,
            IdentityCredential::IdentityClaimsAggregation
        );
    }

    // ---- the x509 signature ------------------------------------------------

    #[test]
    fn a_signature_over_other_bytes_is_a_mismatch() {
        let parsed = parse_one(identity_manifest(|p| {
            p.sign_instead = Some(b"not the signer payload".to_vec())
        }));

        assert_eq!(identity_codes(&parsed), ["cawg.x509.signature.mismatch"]);
        assert!(parsed.statuses.iter().any(ValidationStatus::is_failure));

        // Nothing says that certificate signed this, so it is not named
        // and its chain is not judged.
        assert!(matches!(
            parsed.manifests[0].identity_assertions[0].credential,
            IdentityCredential::X509Cose { signer: None }
        ));
        assert!(parsed.identity_chains.is_empty());
    }

    #[test]
    fn an_unreadable_signature_is_an_invalid_credential() {
        let parsed = parse_one(identity_manifest(|p| {
            p.signature_override = Some(vec![0xff])
        }));

        assert_eq!(identity_codes(&parsed), ["cawg.x509.credential.invalid"]);
        assert!(parsed.statuses.iter().any(ValidationStatus::is_failure));
    }

    #[test]
    fn a_timestamp_header_that_is_malformed_is_reported_without_spoiling_the_signature() {
        let parsed = parse_one(identity_manifest(|p| {
            p.unprotected = Value::Map(BTreeMap::from([(
                Value::Text("sigTst2".into()),
                Value::Integer(1),
            )]))
        }));

        let codes: Vec<_> = parsed.statuses.iter().map(|s| s.code.as_str()).collect();
        assert!(codes.contains(&"timeStamp.malformed"), "{codes:?}");
        assert!(codes.contains(&"cawg.x509.signature.validated"));
        assert_eq!(parsed.identity_chains.len(), 1);
    }

    // ---- trust -------------------------------------------------------------

    #[test]
    fn a_timestamp_that_does_not_hold_up_leaves_the_chain_judged_at_the_hosts_time() {
        // A well-shaped `sigTst2` header whose token is not a timestamp:
        // recorded as malformed, and not taken as the time of signing.
        let report = read(
            identity_manifest(|p| {
                p.unprotected = Value::Map(BTreeMap::from([(
                    Value::Text("sigTst2".into()),
                    Value::Map(BTreeMap::from([(
                        Value::Text("tstTokens".into()),
                        Value::Array(vec![Value::Map(BTreeMap::from([(
                            Value::Text("val".into()),
                            Value::Bytes(vec![1, 2, 3]),
                        )]))]),
                    )])),
                )]))
            }),
            identity_anchored(),
            Some(NOW),
        );

        let all: Vec<_> = report.statuses.iter().map(|s| s.code.as_str()).collect();
        assert!(all.contains(&"timeStamp.malformed"), "{all:?}");
        assert!(all.contains(&"cawg.x509.credential.trusted"), "{all:?}");
    }

    #[test]
    fn a_signer_on_the_identity_trust_list_is_trusted() {
        let report = read(identity_manifest(|_| {}), identity_anchored(), Some(NOW));

        assert!(codes(&report).contains(&"cawg.x509.credential.trusted"));
        assert!(!codes(&report).contains(&"cawg.x509.credential.untrusted"));
    }

    #[test]
    fn identity_trust_is_independent_of_the_claims() {
        // The identity signer is an anchor; the claim signer (the same
        // certificate) is not: the manifest is merely valid, the actor
        // trusted.
        let report = read(identity_manifest(|_| {}), identity_anchored(), Some(NOW));
        assert_eq!(report.validation_state, Some(ValidationState::Valid));
        assert!(codes(&report).contains(&"cawg.x509.credential.trusted"));

        // And the reverse: a claim anchor does not make an identity
        // trusted.
        let report = read(
            identity_manifest(|_| {}),
            ReadSettings {
                trust_anchors: vec![TEST_SIGNER_CERT.to_vec()],
                ..ReadSettings::default()
            },
            Some(NOW),
        );
        assert_eq!(report.validation_state, Some(ValidationState::Trusted));
        assert!(codes(&report).contains(&"cawg.x509.credential.untrusted"));
        assert!(report
            .statuses
            .iter()
            .filter(|s| s.is_identity_finding())
            .all(|s| !s.is_failure()));
    }

    #[test]
    fn no_identity_anchors_means_untrusted_but_otherwise_fine() {
        let report = read(
            identity_manifest(|_| {}),
            ReadSettings::default(),
            Some(NOW),
        );

        assert_eq!(
            codes(&report),
            [
                "cawg.x509.signature.validated",
                "cawg.identity.well-formed",
                "cawg.x509.credential.untrusted"
            ]
        );
        assert_eq!(report.validation_state, Some(ValidationState::Valid));
    }

    #[test]
    fn a_named_identity_list_is_reported_on_the_trusted_status() {
        let report = read(
            identity_manifest(|_| {}),
            ReadSettings {
                identity_trust_lists: vec![TrustList {
                    uri: "https://example.com/cawg.pem".to_string(),
                    anchors: vec![TEST_SIGNER_CERT.to_vec()],
                }],
                ..ReadSettings::default()
            },
            Some(NOW),
        );

        let trusted = report
            .statuses
            .iter()
            .find(|s| s.code == "cawg.x509.credential.trusted")
            .unwrap();
        assert_eq!(
            trusted.trust_list_uri.as_deref(),
            Some("https://example.com/cawg.pem")
        );
    }

    #[test]
    fn an_identity_signer_outside_its_validity_window_is_a_failure_of_the_assertion_only() {
        let report = read(
            identity_manifest(|_| {}),
            identity_anchored(),
            Some(i64::MAX / 4),
        );

        assert!(codes(&report).contains(&"cawg.x509.signature.outside_validity"));
        assert!(report
            .statuses
            .iter()
            .any(|s| s.code == "cawg.x509.signature.outside_validity" && s.is_failure()));

        // The claim signer's own window failure is the claim's, and does
        // invalidate: the identity one must not be what decides it.
        let identity_only: Vec<_> = report
            .statuses
            .iter()
            .filter(|s| s.is_identity_finding() && s.is_failure())
            .collect();
        assert!(identity_only.iter().all(|s| !s.affects_validation_state()));
    }

    #[test]
    fn a_failing_identity_assertion_does_not_invalidate_the_store() {
        let report = read(
            identity_manifest(|p| p.sign_instead = Some(b"other".to_vec())),
            identity_anchored(),
            Some(NOW),
        );

        assert!(report.statuses.iter().any(|s| s.is_failure()));
        assert_eq!(report.validation_state, Some(ValidationState::Valid));
    }

    #[test]
    fn a_host_with_no_clock_leaves_the_identity_chain_unevaluated_but_not_the_store_incomplete() {
        let report = read(identity_manifest(|_| {}), identity_anchored(), None);

        let untrusted = report
            .statuses
            .iter()
            .find(|s| s.code == "cawg.x509.credential.untrusted")
            .unwrap();
        assert!(untrusted
            .explanation
            .as_deref()
            .unwrap()
            .contains("no current time"));
        assert!(!untrusted.is_failure());
    }

    #[test]
    fn an_identity_anchor_that_is_not_a_certificate_is_refused_up_front() {
        let mut session = ReadSession::new(ReadSettings {
            identity_trust_anchors: vec![vec![1, 2, 3]],
            ..ReadSettings::default()
        });

        let err = session.advance().unwrap_err();
        assert!(matches!(
            err,
            crate::Error::MalformedTrustAnchor {
                kind: crate::error::AnchorKind::Identity,
                index: 0,
                ..
            }
        ));
        assert!(err.to_string().contains("identity trust anchor 0"));
    }

    #[test]
    fn a_hard_binding_helper_box_is_still_a_valid_assertion_box() {
        // Guards the test support itself: the boxes it builds parse.
        let a = assertion_box("a.test");
        assert_eq!(&a[4..8], b"jumb");
        assert_eq!(boxed(b"cbor", &[1]).len(), 9);
    }
}
