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

//! OCSP (RFC 6960): building the request for one certificate's revocation
//! status, and interpreting whatever comes back.
//!
//! # Why this module is a seam
//!
//! The same reasoning as [`crate::cert`] and [`crate::cose`]: only this
//! module names an `x509_ocsp` type. [`PendingOcspCheck`] and
//! [`OcspOutcome`] cross the seam in plain types, and
//! [`crate::chain::ocsp_checks`] — the only caller — never sees an
//! `x509_ocsp::CertId` or `x509_ocsp::BasicOcspResponse` directly.
//!
//! # Where the request comes from, and where the answer goes
//!
//! The host is never asked to speak OCSP itself. This module builds the
//! DER-encoded `OCSPRequest` and hands it to the session as an opaque
//! payload ([`ReadRequest::Ocsp`](crate::ReadRequest::Ocsp)); the host's
//! only job is an HTTP POST of those exact bytes to the responder URL and
//! reporting back whatever bytes it received, unread. Whether the answer
//! came from a live OCSP responder or was stapled into the manifest ahead
//! of time by whoever built it makes no difference here — both arrive as
//! the same DER blob, and this module is the only thing that knows the
//! difference between a POST body and a header value even exists.
//!
//! # Fail-open, by construction
//!
//! [`evaluate`] never returns anything stronger than [`OcspOutcome::Revoked`]
//! requires: a response has to name the right [`x509_ocsp::CertId`], be
//! signed by an authority this module can tie back to the certificate's own
//! issuer, and say `revoked` outright. Anything short of that —
//! unreachable, malformed, wrongly signed, naming the wrong certificate,
//! stale, or genuinely `unknown` — comes back as [`OcspOutcome::Inconclusive`],
//! which [`crate::chain::ocsp_checks`]'s caller treats exactly like no
//! check having run at all. The C2PA specification makes OCSP checking
//! optional in the first place, and offline verification — reading a
//! manifest years later, with no responder left to ask — is a design goal
//! of the format; a verifier that invalidated a manifest because it
//! *could not learn* a certificate's status would defeat that goal for
//! every asset it could not reach the network for.
//!
//! # What is deliberately not supported
//!
//! * **`ResponderID` by key hash.** RFC 6960 fixes that comparison at a
//!   SHA-1 hash of the responder's raw public key, regardless of the hash
//!   algorithm anything else in the exchange uses. Adding a SHA-1
//!   dependency for the sake of one `ResponderID` shape — when `byName`,
//!   the far more common choice, already reaches the same authorities —
//!   is not worth it yet; a response identifying its responder by key is
//!   read as [`OcspOutcome::Inconclusive`] rather than guessed at.
//! * **CRLs.** The C2PA specification permits OCSP only, so there is
//!   nothing this module would do with one.

use contentauth_c2pa_primitives::HashAlgorithm;
use der::{
    asn1::{Null, OctetString},
    oid::ObjectIdentifier,
    Decode, Encode,
};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus,
    Request as SingleRequest, ResponderId, TbsRequest, Version,
};

use crate::{
    cert::{self, Certificate},
    chain,
};

/// SHA-256 (`2.16.840.1.101.3.4.2.1`), used for `CertID`'s hash algorithm.
///
/// RFC 6960 lets a requester pick any hash algorithm the responder
/// recognizes; SHA-1 remains the most widely supported choice among
/// deployed responders, but this crate's own profile already forbids SHA-1
/// for content hashing (see [`contentauth_c2pa_primitives::HashAlgorithm`]),
/// and a prototype exploring this plumbing is a reasonable place to prefer
/// the modern algorithm over maximum interoperability with legacy
/// responders.
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// One certificate's revocation check, still outstanding.
///
/// Built by [`crate::chain::ocsp_checks`] for a subject/issuer pair in an
/// already-validated path; carried by [`crate::read::ReadSession`] from the
/// moment the host request is issued until a reply — or none — arrives.
#[derive(Clone, Debug)]
pub(crate) struct PendingOcspCheck {
    /// Where to send [`Self::request_der`], taken from the subject
    /// certificate's Authority Information Access extension.
    pub(crate) responder_url: String,

    /// The DER-encoded `OCSPRequest` this check sends. Built once, here,
    /// so the host never has to know anything about OCSP's ASN.1 beyond
    /// "these are the bytes to POST".
    pub(crate) request_der: Vec<u8>,

    /// The subject certificate's issuer — needed to tell whether whoever
    /// signed the response is allowed to answer for it.
    issuer: Certificate,

    /// The `CertID` this check asked about, kept to match a response's
    /// `SingleResponse` back to this subject certificate without
    /// re-deriving it (and without trusting the response to echo it
    /// faithfully in some other form).
    cert_id: CertId,
}

/// What one OCSP check established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OcspOutcome {
    /// A response naming this certificate, signed by an authority tied to
    /// its issuer, said the certificate was not revoked.
    ///
    /// This adds nothing beyond what path validation already found: an
    /// OCSP check can only take trust away, never grant it.
    NotRevoked,

    /// A response naming this certificate, signed by an authority tied to
    /// its issuer, said the certificate was revoked.
    Revoked,

    /// Nothing usable was established one way or the other. See the
    /// module docs for the fail-open reasoning this covers.
    Inconclusive,
}

/// Builds the OCSP check for one link of a certificate path, if the
/// subject certificate names a responder to ask.
///
/// Returns `None` when `subject` carries no OCSP responder URL, or (only
/// in a defensive, expected-unreachable case) if the request could not be
/// DER-encoded — never a status finding of its own, since not every
/// certificate is expected to carry the extension in the first place.
pub(crate) fn build_check(subject: &Certificate, issuer: &Certificate) -> Option<PendingOcspCheck> {
    let responder_url = subject.ocsp_responder_url.clone()?;
    let cert_id = build_cert_id(subject, issuer).ok()?;

    let request = OcspRequest {
        tbs_request: TbsRequest {
            version: Version::V1,
            requestor_name: None,
            request_list: vec![SingleRequest {
                req_cert: cert_id.clone(),
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };

    let request_der = request.to_der().ok()?;

    Some(PendingOcspCheck {
        responder_url,
        request_der,
        issuer: issuer.clone(),
        cert_id,
    })
}

/// Builds the `CertID` (RFC 6960 §4.1.1) naming `subject` under `issuer`.
fn build_cert_id(subject: &Certificate, issuer: &Certificate) -> Result<CertId, &'static str> {
    let algorithm = HashAlgorithm::Sha256;

    Ok(CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: SHA256_OID,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(algorithm.digest(&issuer.subject_der))
            .map_err(|_| "issuer name hash could not be encoded")?,
        issuer_key_hash: OctetString::new(algorithm.digest(&issuer.public_key_bitstring))
            .map_err(|_| "issuer key hash could not be encoded")?,
        serial_number: x509_cert::serial_number::SerialNumber::new(&subject.serial_number)
            .map_err(|_| "serial number could not be encoded")?,
    })
}

/// Interprets a host's answer to [`PendingOcspCheck`], as a
/// [`crate::ReadRequest::Ocsp`](crate::ReadRequest::Ocsp)/[`crate::ReadHostReply::Ocsp`](crate::ReadHostReply::Ocsp)
/// round trip.
///
/// `now` is the instant the certificate chain itself was judged against —
/// the same one [`crate::chain::validate`] used, whether that came from the
/// host's clock or a trusted timestamp. A response is only trusted to speak
/// to that instant if it actually covered it; see the module docs for why
/// anything less than a clean answer is [`OcspOutcome::Inconclusive`] rather
/// than a rejection.
pub(crate) fn evaluate(check: &PendingOcspCheck, response_der: &[u8], now: i64) -> OcspOutcome {
    evaluate_checked(check, response_der, now).unwrap_or(OcspOutcome::Inconclusive)
}

/// The fallible core of [`evaluate`], written so every "cannot tell"
/// exit reads as one `?` or `None` rather than a repeated
/// [`OcspOutcome::Inconclusive`] at each of them.
fn evaluate_checked(
    check: &PendingOcspCheck,
    response_der: &[u8],
    now: i64,
) -> Option<OcspOutcome> {
    let response = OcspResponse::from_der(response_der).ok()?;

    if response.response_status != OcspResponseStatus::Successful {
        return None;
    }

    let bytes = response.response_bytes?;
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).ok()?;

    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|candidate| candidate.cert_id == check.cert_id)?;

    let signer = responder_certificate(check, &basic)?;
    verify_response_signature(&basic, &signer).ok()?;

    let this_update = generalized_time_seconds(&single.this_update);
    if now < this_update {
        // A response that only starts speaking for a later instant than
        // the one this check cares about says nothing about it yet.
        return None;
    }
    if let Some(next_update) = &single.next_update {
        if now > generalized_time_seconds(next_update) {
            // Stale: the responder itself says a fresher answer should
            // have replaced this one by `now`.
            return None;
        }
    }

    match single.cert_status {
        CertStatus::Good(_) => Some(OcspOutcome::NotRevoked),
        CertStatus::Revoked(_) => Some(OcspOutcome::Revoked),
        CertStatus::Unknown(_) => None,
    }
}

/// Finds the certificate whose key actually signed `basic`, among those
/// this module is willing to trust to answer for [`PendingOcspCheck::issuer`].
///
/// Two shapes are accepted: the issuer answered directly (`responderID`
/// names the issuer itself), or a delegated responder certificate the
/// issuer issued for exactly this purpose did — the same
/// `id-kp-OCSPSigning` profile [`crate::chain::validate`] already holds an
/// end-entity certificate to. See the module docs for the one
/// `responderID` shape this does not resolve.
fn responder_certificate(
    check: &PendingOcspCheck,
    basic: &BasicOcspResponse,
) -> Option<Certificate> {
    let ResponderId::ByName(name) = &basic.tbs_response_data.responder_id else {
        return None;
    };

    let name_der = name.to_der().ok()?;

    if name_der == check.issuer.subject_der {
        return Some(check.issuer.clone());
    }

    for candidate in basic.certs.as_ref()?.iter() {
        let Ok(der) = candidate.to_der() else {
            continue;
        };
        let Ok(candidate) = cert::decode(&der) else {
            continue;
        };

        if candidate.subject_der != name_der {
            continue;
        }

        let names_ocsp_signing = candidate
            .extended_key_usage
            .as_deref()
            .is_some_and(|purposes| purposes.iter().any(|oid| oid == chain::OCSP_SIGNING));

        if names_ocsp_signing && chain::verify(&candidate, &check.issuer).is_ok() {
            return Some(candidate);
        }
    }

    None
}

/// Verifies a `BasicOcspResponse`'s signature over its own `tbsResponseData`.
fn verify_response_signature(
    basic: &BasicOcspResponse,
    signer: &Certificate,
) -> Result<(), &'static str> {
    use c2pa_raw_crypto::{validator_for_sig_and_hash_algs, Oid};

    let hash = cert::signature_hash(&basic.signature_algorithm)
        .ok()
        .flatten();

    let validator = validator_for_sig_and_hash_algs(
        &Oid::new(basic.signature_algorithm.oid.as_bytes()),
        &Oid::new(hash.as_deref().unwrap_or(&[])),
    )
    .ok_or("the OCSP response is signed with an algorithm this core cannot verify")?;

    let tbs_der = basic
        .tbs_response_data
        .to_der()
        .map_err(|_| "the OCSP response's signed data could not be re-encoded")?;

    validator
        .validate(basic.signature.raw_bytes(), &tbs_der, &signer.public_key)
        .map_err(|_| "the OCSP response's signature does not verify")
}

/// Converts an OCSP `GeneralizedTime` field to seconds since the Unix
/// epoch.
fn generalized_time_seconds(time: &x509_ocsp::OcspGeneralizedTime) -> i64 {
    // `as` is lossless for every representable time: GeneralizedTime tops
    // out at year 9999.
    time.0.to_unix_duration().as_secs() as i64
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use core::time::Duration;

    use der::asn1::{BitString, GeneralizedTime};
    use x509_ocsp::{OcspGeneralizedTime, ResponseData, RevokedInfo, SingleResponse};

    use super::*;
    use crate::test_support::{FIXTURE_LEAF_CERT, TEST_SIGNER_CERT, TEST_SIGNER_KEY};

    /// `ecdsa-with-SHA256`, the CMS/X.509 signature algorithm that matches
    /// [`TEST_SIGNER_KEY`] — the same OID `timestamp.rs`'s own tests sign
    /// with, for the same key.
    const ECDSA_WITH_SHA256_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// [`TEST_SIGNER_CERT`], decoded. Self-signed, so it doubles as its own
    /// OCSP responder in these tests — the simplest shape
    /// [`responder_certificate`] resolves: the issuer answered directly,
    /// with no delegated responder certificate involved.
    fn issuer() -> Certificate {
        cert::decode(TEST_SIGNER_CERT).expect("the test signer decodes")
    }

    /// A certificate to ask about. Borrowed from an unrelated fixture
    /// purely for a [`Certificate::serial_number`] to build a `CertID`
    /// from — [`evaluate`] never checks that `subject` was actually issued
    /// by `issuer`, which is `crate::chain::validate`'s job, not this
    /// module's.
    fn subject() -> Certificate {
        cert::decode(FIXTURE_LEAF_CERT).expect("the fixture leaf decodes")
    }

    fn check() -> PendingOcspCheck {
        let issuer = issuer();
        PendingOcspCheck {
            responder_url: "http://ocsp.example/".to_string(),
            request_der: vec![],
            cert_id: build_cert_id(&subject(), &issuer).expect("builds"),
            issuer,
        }
    }

    fn generalized_time(unix_seconds: i64) -> OcspGeneralizedTime {
        OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(unix_seconds as u64))
                .expect("encodes"),
        )
    }

    /// Builds and signs (for real, with [`TEST_SIGNER_KEY`]) a
    /// `BasicOcspResponse` for `check`'s own `CertID`, wrapped as a
    /// complete, DER-encoded `OCSPResponse`.
    ///
    /// `corrupt_signature` flips a bit of the signature after signing —
    /// the same "otherwise well-formed, but the cryptography refuses it"
    /// shape this crate's other signature tests use — to exercise the
    /// authentication check independently of every other one.
    fn signed_response(
        check: &PendingOcspCheck,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
        corrupt_signature: bool,
    ) -> Vec<u8> {
        let single = SingleResponse {
            cert_id: check.cert_id.clone(),
            cert_status: status,
            this_update: generalized_time(this_update),
            next_update: next_update.map(generalized_time),
            single_extensions: None,
        };

        let responder_subject = x509_cert::Certificate::from_der(TEST_SIGNER_CERT)
            .expect("decodes")
            .tbs_certificate
            .subject;

        let tbs = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByName(responder_subject),
            produced_at: generalized_time(this_update),
            responses: vec![single],
            response_extensions: None,
        };

        let signer = c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .expect("the test key is valid");

        let mut signature = signer.sign(&tbs.to_der().expect("encodes")).expect("signs");

        if corrupt_signature {
            let last = signature.len() - 1;
            signature[last] ^= 0xff;
        }

        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature).expect("encodes"),
            certs: None,
        };

        OcspResponse::successful(basic)
            .expect("encodes")
            .to_der()
            .expect("encodes")
    }

    #[test]
    fn build_check_requires_a_responder_url() {
        let mut subject = subject();
        subject.ocsp_responder_url = None;
        assert!(build_check(&subject, &issuer()).is_none());
    }

    #[test]
    fn build_check_names_the_right_certificate() {
        let mut subject = subject();
        subject.ocsp_responder_url = Some("http://ocsp.example/".to_string());

        let check = build_check(&subject, &issuer()).expect("names a responder");
        assert_eq!(check.responder_url, "http://ocsp.example/");

        // The request this crate builds names exactly the `CertID` this
        // module would independently build for the same pair.
        let request = OcspRequest::from_der(&check.request_der).expect("round-trips");
        assert_eq!(
            request.tbs_request.request_list[0].req_cert,
            build_cert_id(&subject, &issuer()).expect("builds")
        );
    }

    #[test]
    fn a_good_status_from_the_issuer_itself_is_not_revoked() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, Some(2_000), false);

        assert_eq!(evaluate(&check, &response, 1_500), OcspOutcome::NotRevoked);
    }

    #[test]
    fn a_revoked_status_is_reported() {
        let check = check();
        let info = RevokedInfo {
            revocation_time: generalized_time(900),
            revocation_reason: None,
        };
        let response =
            signed_response(&check, CertStatus::revoked(info), 1_000, Some(2_000), false);

        assert_eq!(evaluate(&check, &response, 1_500), OcspOutcome::Revoked);
    }

    #[test]
    fn an_unknown_status_is_inconclusive() {
        let check = check();
        let response = signed_response(&check, CertStatus::unknown(), 1_000, Some(2_000), false);

        assert_eq!(
            evaluate(&check, &response, 1_500),
            OcspOutcome::Inconclusive
        );
    }

    #[test]
    fn a_response_naming_a_different_cert_id_is_inconclusive() {
        let check = check();
        let mut other = check.clone();
        other.cert_id.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[9, 9, 9]).expect("encodes");

        let response = signed_response(&other, CertStatus::good(), 1_000, Some(2_000), false);

        // `other`'s response answers a `CertID` that is not `check`'s own.
        assert_eq!(
            evaluate(&check, &response, 1_500),
            OcspOutcome::Inconclusive
        );
    }

    #[test]
    fn a_forged_signature_is_inconclusive() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, Some(2_000), true);

        assert_eq!(
            evaluate(&check, &response, 1_500),
            OcspOutcome::Inconclusive
        );
    }

    #[test]
    fn a_response_from_before_this_update_is_inconclusive() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 5_000, None, false);

        // `now` is before `thisUpdate`: the response does not yet speak to
        // the instant this check cares about.
        assert_eq!(
            evaluate(&check, &response, 1_000),
            OcspOutcome::Inconclusive
        );
    }

    #[test]
    fn a_stale_response_is_inconclusive() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, Some(1_100), false);

        assert_eq!(
            evaluate(&check, &response, 5_000),
            OcspOutcome::Inconclusive
        );
    }

    #[test]
    fn a_response_with_no_next_update_never_goes_stale() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, None, false);

        assert_eq!(
            evaluate(&check, &response, 50_000_000),
            OcspOutcome::NotRevoked
        );
    }

    #[test]
    fn garbage_bytes_are_inconclusive() {
        let check = check();
        assert_eq!(
            evaluate(&check, &[0xff, 0xff], 1_500),
            OcspOutcome::Inconclusive
        );
    }

    #[test]
    fn a_response_status_other_than_successful_is_inconclusive() {
        let check = check();
        let response = OcspResponse::try_later().to_der().expect("encodes");

        assert_eq!(
            evaluate(&check, &response, 1_500),
            OcspOutcome::Inconclusive
        );
    }
}
