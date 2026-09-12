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
//! status, and interpreting whatever comes back, per the C2PA
//! specification's §15.9 ("Validate the Credential Revocation
//! Information").
//!
//! # Why this module is a seam
//!
//! The same reasoning as [`crate::cert`] and [`crate::cose`]: only this
//! module names an `x509_ocsp` type. [`PendingOcspCheck`],
//! [`StapledOutcome`] and [`OnlineOutcome`] cross the seam in plain types,
//! and [`crate::chain::ocsp_checks`] and [`crate::read::ReadSession`] —
//! the only callers — never see an `x509_ocsp::CertId` or
//! `x509_ocsp::BasicOcspResponse` directly.
//!
//! # Two evaluations, not one
//!
//! §15.9 asks two different questions of an OCSP response, with different
//! rules for each, and this module keeps them as two entry points rather
//! than one:
//!
//! * [`evaluate_stapled`] (§15.9.1) — a response already sitting in the
//!   C2PA Manifest Store, either "stapled" into the claim signature's own
//!   `rVals` COSE header or carried in another manifest's certificate
//!   status assertion. This can only ever answer for the *signing* instant:
//!   it requires a trusted RFC 3161 timestamp, and has no fallback to the
//!   current time.
//! * [`evaluate_online`] (§15.9.2) — a response the host fetched live from
//!   the responder named in the certificate's own Authority Information
//!   Access extension. This one *can* fall back to the current time when
//!   the claim signature carries no trusted timestamp, since a response
//!   fetched right now speaks best to what is true right now.
//!
//! Both share [`accept`], which is the RFC 6960 §3.2 acceptance test
//! common to either question: does this response actually name the
//! certificate this check is about, and is it signed by someone entitled
//! to answer for it?
//!
//! # Where the request comes from, and where the answer goes
//!
//! The host is never asked to speak OCSP itself for an *online* check.
//! This module builds the DER-encoded `OCSPRequest` and hands it to the
//! session as an opaque payload ([`ReadRequest::Ocsp`](crate::ReadRequest::Ocsp));
//! the host's only job is an HTTP POST of those exact bytes to the
//! responder URL and reporting back whatever bytes it received, unread.
//!
//! # Fail-open about *not answering*, fail-closed about *not vouching*
//!
//! A response this module could not even authenticate for the right
//! certificate — unreachable, malformed, wrongly signed, naming the wrong
//! certificate — is never treated as a rejection: it comes back as
//! [`StapledOutcome::Inconclusive`] or [`OnlineOutcome::Inconclusive`],
//! which [`crate::read::ReadSession`] treats as "nothing learned," the
//! same as the responder never having answered at all. The C2PA
//! specification makes OCSP checking optional in the first place
//! (§15.9.2's own note: querying a responder can reveal an asset's
//! identity to an observer), and offline verification is a design goal of
//! the format; a verifier that invalidated a manifest because it *could
//! not learn* a certificate's status would defeat that goal for every
//! asset it could not reach a network for.
//!
//! But a response this module *did* authenticate, and that still failed
//! to establish [`OnlineOutcome::NotRevoked`] — a `good` status for an
//! instant the response does not actually cover, say — is a different
//! matter for an *online* check: §15.9.2 is explicit that this reads as
//! [`OnlineOutcome::Revoked`], not merely inconclusive. Once a responder
//! has actually answered, the specification is no longer willing to give
//! the certificate the benefit of the doubt. [`evaluate_stapled`] has no
//! equivalent fail-closed fallback — §15.9.1 defines no "otherwise" for a
//! response already sitting in the store, so anything it does not
//! affirmatively establish is [`StapledOutcome::Inconclusive`], falling
//! through to an online check instead.
//!
//! # What is deliberately not supported
//!
//! * **`ResponderID` by key hash.** RFC 6960 fixes that comparison at a
//!   SHA-1 hash of the responder's raw public key, regardless of the hash
//!   algorithm anything else in the exchange uses. Adding a SHA-1
//!   dependency for the sake of one `ResponderID` shape — when `byName`,
//!   the far more common choice, already reaches the same authorities —
//!   is not worth it yet; a response identifying its responder by key is
//!   treated as unauthenticated rather than guessed at.
//! * **An independently trusted OCSP responder list.** RFC 6960 §4.2.2.2
//!   also authorizes a responder the *client* explicitly trusts, on its
//!   own account, regardless of who issued its certificate. This crate has
//!   no such list to configure; only a responder that is the certificate's
//!   own issuer, or a delegate that issuer certified for exactly this
//!   purpose, is recognized.
//! * **Certificate status assertions in other manifests** (§15.9's own
//!   third bullet — a subsequent claim generator recording OCSP responses
//!   for an earlier manifest's signer). Reading assertion values by type is
//!   [`crate::manifest_store`]'s job, and it does not decode this one yet.
//! * **CRLs.** The C2PA specification permits OCSP only, so there is
//!   nothing this module would do with one.

use contentauth_c2pa_primitives::HashAlgorithm;
use der::{
    asn1::{Null, OctetString},
    oid::ObjectIdentifier,
    Decode, Encode,
};
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus,
    Request as SingleRequest, ResponderId, SingleResponse, TbsRequest, Version,
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
/// moment it is created (and any stapled responses are tried against it)
/// until an online reply — or none — arrives.
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

/// What [`evaluate_stapled`] (C2PA spec §15.9.1) established about a
/// response already present in the C2PA Manifest Store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StapledOutcome {
    /// The response met every §15.9.1 condition with `certStatus` good (or
    /// revoked for the disambiguated `removeFromCRL` reason, which §15.9.1
    /// also requires be read as not revoked): the certificate was not
    /// revoked at the time of signing.
    NotRevoked,

    /// The response met every §15.9.1 condition except that `certStatus`
    /// was revoked (for a reason other than `removeFromCRL`): the
    /// certificate was revoked.
    Revoked,

    /// Nothing was established either way — no trusted timestamp to judge
    /// the response against, no response naming this `CertID`, an
    /// unauthenticated signer, a response that does not yet or no longer
    /// cover the signing instant, or `certStatus` `unknown`. The C2PA
    /// specification treats this the same as no revocation information
    /// having been found in the store at all: validation falls through to
    /// [`evaluate_online`].
    Inconclusive,
}

/// What [`evaluate_online`] (C2PA spec §15.9.2) established about a
/// response freshly fetched from an OCSP responder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OnlineOutcome {
    /// The certificate was not revoked at the time of signing (or, having
    /// no signing time to judge, is not revoked now).
    NotRevoked,

    /// The certificate was revoked at the relevant instant — or, per
    /// §15.9.2's own "Otherwise" fallback, the response was authenticated
    /// but did not establish [`Self::NotRevoked`] any other way (its
    /// `certStatus` was neither a covered `good` nor a rescued `revoked`).
    /// Unlike everywhere else this module is fail-open, §15.9.2 is
    /// deliberately fail-*closed* about a response it actually received
    /// and could authenticate but that did not hold up.
    Revoked,

    /// The response was authenticated, but did not establish
    /// [`Self::NotRevoked`], and its `certStatus` was `unknown`.
    Unknown,

    /// The response could not be authenticated for this `CertID` at all —
    /// unreachable, malformed, wrongly signed, or naming the wrong
    /// certificate. This is the only outcome
    /// [`crate::read::ReadSession`] treats as fail-open (equivalent to the
    /// responder never having answered); see [`Self::Revoked`] for why an
    /// authenticated-but-unsatisfying response is not read the same way.
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

/// A response accepted per RFC 6960 §3.2's requirements 1 through 4 for
/// `check`'s own `CertID`: it is signed by an authority entitled to answer
/// for the certificate, and the signature verifies. What is left is purely
/// a question of *when* and *what it said* — [`evaluate_stapled`] and
/// [`evaluate_online`] each answer that differently.
struct Accepted {
    this_update: i64,
    next_update: Option<i64>,
    produced_at: i64,
    status: Status,
}

/// The three ways RFC 6960's `CertStatus` can come out, holding just
/// enough about a `revoked` answer for the C2PA specification's
/// `removeFromCRL` disambiguation and its "revoked after signing" rescue.
#[derive(Clone, Copy)]
enum Status {
    Good,
    Revoked {
        revocation_time: i64,
        reason: Option<CrlReason>,
    },
    Unknown,
}

/// Decodes `response_der`, finds the `SingleResponse` answering `check`'s
/// own `CertID`, and accepts it only if its signer is authorized to answer
/// for [`PendingOcspCheck::issuer`].
///
/// This is RFC 6960 §3.2's requirements 1 (signer authorized), 2 (signature
/// verifies) and, implicitly, "the response actually names this
/// certificate" — requirements 3 and 4 (`thisUpdate`/`nextUpdate`
/// freshness) are for the caller to judge against whichever instant its
/// own question is about.
fn accept(check: &PendingOcspCheck, response_der: &[u8]) -> Option<Accepted> {
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

    Some(Accepted {
        this_update: generalized_time_seconds(&single.this_update),
        next_update: single.next_update.as_ref().map(generalized_time_seconds),
        produced_at: generalized_time_seconds(&basic.tbs_response_data.produced_at),
        status: status_of(single),
    })
}

/// Reads a `SingleResponse`'s `certStatus` into [`Status`].
fn status_of(single: &SingleResponse) -> Status {
    match &single.cert_status {
        CertStatus::Good(_) => Status::Good,
        CertStatus::Unknown(_) => Status::Unknown,
        CertStatus::Revoked(info) => Status::Revoked {
            revocation_time: generalized_time_seconds(&info.revocation_time),
            reason: info.revocation_reason,
        },
    }
}

/// True if `reason` is the `removeFromCRL` `CRLReason` C2PA spec §15.9.1
/// and §15.9.2 both call out: a certificate that a delta-CRL scheme once
/// listed as revoked and has since removed, which both sections require
/// reading as *not* revoked rather than as an actual revocation.
fn is_remove_from_crl(reason: Option<CrlReason>) -> bool {
    reason == Some(CrlReason::RemoveFromCRL)
}

/// Evaluates one response already present in the C2PA Manifest Store —
/// stapled into the claim signature's `rVals` header, or (not yet
/// implemented; see the module docs) a certificate status assertion in
/// another manifest — against C2PA spec §15.9.1.
///
/// `attested` is the claim signature's trusted RFC 3161 timestamp instant,
/// if it has one that chains to a configured timestamp anchor; `now` is
/// the host's current time, if known. Both are required here: §15.9.1 has
/// no fallback for either — a store response can only speak to the
/// signing instant when that instant is actually known (`attested`), and
/// "the current time is no earlier than `thisUpdate`" is a check against
/// real time (`now`), not a substitute for it.
pub(crate) fn evaluate_stapled(
    check: &PendingOcspCheck,
    response_der: &[u8],
    now: Option<i64>,
    attested: Option<i64>,
) -> StapledOutcome {
    evaluate_stapled_checked(check, response_der, now, attested)
        .unwrap_or(StapledOutcome::Inconclusive)
}

fn evaluate_stapled_checked(
    check: &PendingOcspCheck,
    response_der: &[u8],
    now: Option<i64>,
    attested: Option<i64>,
) -> Option<StapledOutcome> {
    let accepted = accept(check, response_der)?;
    let now = now?;
    let attested = attested?;

    if now < accepted.this_update {
        return None;
    }

    // Both intervals are open at each end, matching the spec's own
    // "(thisUpdate,nextUpdate)"/"(thisUpdate,producedAt + 24 hours)"
    // notation literally — the same convention `evaluate_online`'s
    // `in_validity_window` uses.
    let covers_signing = attested < accepted.this_update
        || match accepted.next_update {
            Some(next_update) => attested > accepted.this_update && attested < next_update,
            None => attested > accepted.this_update && attested < accepted.produced_at + ONE_DAY,
        };

    if !covers_signing {
        return None;
    }

    Some(match accepted.status {
        Status::Good => StapledOutcome::NotRevoked,
        Status::Revoked { reason, .. } if is_remove_from_crl(reason) => StapledOutcome::NotRevoked,
        Status::Revoked { .. } => StapledOutcome::Revoked,
        Status::Unknown => StapledOutcome::Inconclusive,
    })
}

/// Evaluates a response freshly fetched from an OCSP responder against
/// C2PA spec §15.9.2.
///
/// `attested` and `now` are as in [`evaluate_stapled`], except that here
/// `now` stands in for `attested` when the claim signature carries no
/// trusted timestamp — a live response is judged against the instant nearest
/// to when it was actually fetched. If neither is available, nothing can
/// be established.
pub(crate) fn evaluate_online(
    check: &PendingOcspCheck,
    response_der: &[u8],
    now: Option<i64>,
    attested: Option<i64>,
) -> OnlineOutcome {
    evaluate_online_checked(check, response_der, now, attested)
        .unwrap_or(OnlineOutcome::Inconclusive)
}

fn evaluate_online_checked(
    check: &PendingOcspCheck,
    response_der: &[u8],
    now: Option<i64>,
    attested: Option<i64>,
) -> Option<OnlineOutcome> {
    let accepted = accept(check, response_der)?;

    let in_validity_window = |instant: i64| {
        accepted
            .next_update
            .is_some_and(|next_update| instant > accepted.this_update && instant < next_update)
    };

    let judged_at = attested.or(now);
    let time_condition = judged_at.is_some_and(in_validity_window);

    let status_condition = match accepted.status {
        Status::Good => true,
        Status::Revoked { reason, .. } => is_remove_from_crl(reason),
        Status::Unknown => false,
    };

    if time_condition && status_condition {
        return Some(OnlineOutcome::NotRevoked);
    }

    // The "revoked, but only after it signed" rescue: a non-removeFromCRL
    // revocation still leaves the certificate good for a signature made
    // before the revocation took effect.
    if let Status::Revoked {
        revocation_time,
        reason,
    } = accepted.status
    {
        if !is_remove_from_crl(reason) {
            if let Some(attested) = attested {
                if in_validity_window(attested) && revocation_time > attested {
                    return Some(OnlineOutcome::NotRevoked);
                }
            }
        }
    }

    Some(match accepted.status {
        Status::Unknown => OnlineOutcome::Unknown,
        _ => OnlineOutcome::Revoked,
    })
}

/// Seconds in a day, for §15.9.1's `producedAt + 24 hours` fallback
/// window when a stapled response carries no `nextUpdate`.
const ONE_DAY: i64 = 24 * 60 * 60;

/// Finds the certificate whose key actually signed `basic`, among those
/// this module is willing to trust to answer for [`PendingOcspCheck::issuer`].
///
/// Two shapes are accepted (RFC 6960 §4.2.2.2): the issuer answered
/// directly (`responderID` names the issuer itself), or a delegated
/// responder certificate the issuer issued for exactly this purpose did —
/// the same `id-kp-OCSPSigning` profile [`crate::chain::validate`] already
/// holds an end-entity certificate to. See the module docs for the
/// `responderID`-by-key-hash shape this does not resolve, and for the
/// independently-client-trusted-responder shape RFC 6960 also allows.
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
    /// from — this module's own evaluation logic never checks that
    /// `subject` was actually issued by `issuer`, which is
    /// `crate::chain::validate`'s job, not this module's.
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
        produced_at: i64,
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
            produced_at: generalized_time(produced_at),
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

    /// As [`signed_response`], with `producedAt` fixed to `this_update` —
    /// the shape most of these tests want, since only the §15.9.1
    /// no-`nextUpdate` fallback cares about the gap between the two.
    fn response(
        check: &PendingOcspCheck,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
    ) -> Vec<u8> {
        signed_response(check, status, this_update, next_update, this_update, false)
    }

    fn revoked(revocation_time: i64, reason: Option<CrlReason>) -> CertStatus {
        CertStatus::revoked(RevokedInfo {
            revocation_time: generalized_time(revocation_time),
            revocation_reason: reason,
        })
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

    // -- evaluate_online (C2PA spec §15.9.2) --------------------------

    #[test]
    fn online_good_status_with_an_attested_timestamp_is_not_revoked() {
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::NotRevoked
        );
    }

    #[test]
    fn online_good_status_falls_back_to_now_without_a_timestamp() {
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, Some(1_500), None),
            OnlineOutcome::NotRevoked
        );

        // With neither a timestamp nor a current time, the response's
        // "good" answer covers no instant this check can name — see
        // `online_an_authenticated_response_outside_its_window_is_revoked_not_inconclusive`
        // for why that reads as `Revoked` rather than `Inconclusive`.
        assert_eq!(
            evaluate_online(&check, &response, None, None),
            OnlineOutcome::Revoked
        );
    }

    #[test]
    fn online_requires_a_next_update_even_with_an_attested_time() {
        // Unlike the stapled path, the online path has no `producedAt`
        // fallback for a missing `nextUpdate`.
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, None);

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Revoked
        );
    }

    #[test]
    fn online_an_authenticated_response_outside_its_window_is_revoked_not_inconclusive() {
        // C2PA spec §15.9.2 is fail-*closed* about a response it actually
        // received and authenticated: "Otherwise... the certificate shall
        // be considered revoked" is the fallback once neither the main
        // condition nor the revoked-after-signing rescue established
        // `notRevoked` — even though the response itself says `good`, just
        // not for an instant this check can vouch for.
        // `Inconclusive` is reserved for a response this module could not
        // authenticate for the certificate at all (see
        // `online_garbage_bytes_are_inconclusive`), which
        // `crate::read::ReadSession` treats the same as the responder
        // never having answered.
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        // The attested time is long past `nextUpdate`.
        assert_eq!(
            evaluate_online(&check, &response, None, Some(5_000)),
            OnlineOutcome::Revoked
        );
    }

    #[test]
    fn online_revoked_is_reported() {
        let check = check();
        let response = response(&check, revoked(900, None), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Revoked
        );
    }

    #[test]
    fn online_revoked_with_remove_from_crl_is_not_revoked() {
        let check = check();
        let response = response(
            &check,
            revoked(900, Some(CrlReason::RemoveFromCRL)),
            1_000,
            Some(2_000),
        );

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::NotRevoked
        );
    }

    #[test]
    fn online_revoked_after_the_attested_signing_time_is_not_revoked() {
        // Revoked at 1_800, but the claim signature was attested at 1_500
        // — before the revocation took effect.
        let check = check();
        let response = response(&check, revoked(1_800, None), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::NotRevoked
        );
    }

    #[test]
    fn online_revoked_before_the_attested_signing_time_is_revoked() {
        // Revoked at 1_200, before the claim was attested at 1_500 — so it
        // really was already revoked by the time of signing.
        let check = check();
        let response = response(&check, revoked(1_200, None), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Revoked
        );
    }

    #[test]
    fn online_unknown_status_is_reported_as_unknown() {
        let check = check();
        let response = response(&check, CertStatus::unknown(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Unknown
        );
    }

    #[test]
    fn online_a_response_naming_a_different_cert_id_is_inconclusive() {
        let check = check();
        let mut other = check.clone();
        other.cert_id.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[9, 9, 9]).expect("encodes");
        let response = response(&other, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    #[test]
    fn online_a_forged_signature_is_inconclusive() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, Some(2_000), 1_000, true);

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    #[test]
    fn online_garbage_bytes_are_inconclusive() {
        let check = check();
        assert_eq!(
            evaluate_online(&check, &[0xff, 0xff], None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    #[test]
    fn online_a_response_status_other_than_successful_is_inconclusive() {
        let check = check();
        let response = OcspResponse::try_later().to_der().expect("encodes");

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    // -- evaluate_stapled (C2PA spec §15.9.1) -------------------------

    #[test]
    fn stapled_requires_an_attested_timestamp() {
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        // A current time alone is not enough: without a trusted
        // timestamp, a stapled response cannot speak to "at the time of
        // signing" at all.
        assert_eq!(
            evaluate_stapled(&check, &response, Some(1_500), None),
            StapledOutcome::Inconclusive
        );
    }

    #[test]
    fn stapled_requires_a_current_time() {
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, None, Some(1_500)),
            StapledOutcome::Inconclusive
        );
    }

    #[test]
    fn stapled_good_status_covering_the_attested_time_is_not_revoked() {
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(1_500)),
            StapledOutcome::NotRevoked
        );
    }

    #[test]
    fn stapled_the_validity_window_is_open_at_both_ends() {
        // "(thisUpdate,nextUpdate)" per the spec's own notation: an
        // attested time exactly on either boundary does not count as
        // covered, matching `evaluate_online`'s identical convention.
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(1_000)),
            StapledOutcome::Inconclusive,
            "exactly at thisUpdate"
        );
        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(2_000)),
            StapledOutcome::Inconclusive,
            "exactly at nextUpdate"
        );
    }

    #[test]
    fn stapled_an_attested_time_before_this_update_is_covered() {
        // §15.9.1 explicitly allows the attested time to precede
        // `thisUpdate` — the response still speaks for the certificate at
        // signing time in that case.
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(500)),
            StapledOutcome::NotRevoked
        );
    }

    #[test]
    fn stapled_the_current_time_may_not_precede_this_update() {
        let check = check();
        let response = response(&check, CertStatus::good(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, Some(999), Some(1_500)),
            StapledOutcome::Inconclusive
        );
    }

    #[test]
    fn stapled_without_next_update_falls_back_to_produced_at_plus_one_day() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, None, 1_000, false);

        // Inside the 24-hour window past `producedAt`.
        assert_eq!(
            evaluate_stapled(&check, &response, Some(50_000), Some(1_000 + ONE_DAY - 1)),
            StapledOutcome::NotRevoked
        );

        // Past it: no longer covered.
        assert_eq!(
            evaluate_stapled(&check, &response, Some(50_000), Some(1_000 + ONE_DAY + 1)),
            StapledOutcome::Inconclusive
        );
    }

    #[test]
    fn stapled_revoked_is_reported() {
        let check = check();
        let response = response(&check, revoked(900, None), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(1_500)),
            StapledOutcome::Revoked
        );
    }

    #[test]
    fn stapled_revoked_with_remove_from_crl_is_not_revoked() {
        let check = check();
        let response = response(
            &check,
            revoked(900, Some(CrlReason::RemoveFromCRL)),
            1_000,
            Some(2_000),
        );

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(1_500)),
            StapledOutcome::NotRevoked
        );
    }

    #[test]
    fn stapled_unknown_status_is_inconclusive() {
        // §15.9.1 defines no outcome for `unknown` — only good or revoked
        // settle the question, so this falls through as if nothing had
        // been found in the store.
        let check = check();
        let response = response(&check, CertStatus::unknown(), 1_000, Some(2_000));

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(1_500)),
            StapledOutcome::Inconclusive
        );
    }

    #[test]
    fn stapled_a_forged_signature_is_inconclusive() {
        let check = check();
        let response = signed_response(&check, CertStatus::good(), 1_000, Some(2_000), 1_000, true);

        assert_eq!(
            evaluate_stapled(&check, &response, Some(2_500), Some(1_500)),
            StapledOutcome::Inconclusive
        );
    }
}
