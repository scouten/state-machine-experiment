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
use der::{asn1::OctetString, Decode, Encode};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus,
    Request as SingleRequest, ResponderId, SingleResponse, TbsRequest, Version,
};

use crate::{
    cert::{self, Certificate},
    chain,
};

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
    ///
    /// `None` when the subject carries no AIA extension: this check can
    /// still match a stapled response already sitting in the manifest
    /// store by [`Self::cert_id`] — that costs no request of any kind —
    /// but there is nowhere to send an online one.
    pub(crate) responder_url: Option<String>,

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

/// Builds the OCSP check for one link of a certificate path.
///
/// Succeeds regardless of whether `subject` names an online responder:
/// matching a stapled response already in the manifest store needs only
/// the `CertID`, not anywhere to send a request, so gating this on the AIA
/// extension would silently drop a staple for a certificate that happens
/// not to carry one. [`PendingOcspCheck::responder_url`] is `None` in that
/// case, and it is only the online query — not this function — that has
/// nothing to do about it.
///
/// Returns `None` only in a defensive, expected-unreachable case: the
/// `CertID` or request could not be DER-encoded. Never a status finding of
/// its own.
pub(crate) fn build_check(subject: &Certificate, issuer: &Certificate) -> Option<PendingOcspCheck> {
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
        responder_url: subject.ocsp_responder_url.clone(),
        request_der,
        issuer: issuer.clone(),
        cert_id,
    })
}

/// Builds the `CertID` (RFC 6960 §4.1.1) naming `subject` under `issuer`.
fn build_cert_id(subject: &Certificate, issuer: &Certificate) -> Result<CertId, &'static str> {
    let algorithm = HashAlgorithm::Sha256;

    Ok(CertId {
        hash_algorithm: cert::sha256_algorithm_identifier(),
        issuer_name_hash: OctetString::new(algorithm.digest(&issuer.subject_der))
            .map_err(|_| "issuer name hash could not be encoded")?,
        issuer_key_hash: OctetString::new(algorithm.digest(&issuer.public_key_bitstring))
            .map_err(|_| "issuer key hash could not be encoded")?,
        serial_number: cert::encode_serial_number(&subject.serial_number)?,
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
///
/// `is_remove_from_crl` is already resolved to a plain `bool` by
/// [`status_of`], via [`cert::is_remove_from_crl`], rather than carrying
/// the raw `CRLReason` here: this module never needs to name that
/// `x509_cert` type of its own — see this module's own doc comment.
#[derive(Clone, Copy)]
enum Status {
    Good,
    Revoked {
        revocation_time: i64,
        is_remove_from_crl: bool,
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
fn accept(
    check: &PendingOcspCheck,
    response_der: &[u8],
    online_now: Option<i64>,
) -> Option<Accepted> {
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

    let produced_at = generalized_time_seconds(&basic.tbs_response_data.produced_at);
    let signer = responder_certificate(check, &basic, produced_at, online_now)?;
    verify_response_signature(&basic, &signer).ok()?;

    Some(Accepted {
        this_update: generalized_time_seconds(&single.this_update),
        next_update: single.next_update.as_ref().map(generalized_time_seconds),
        produced_at,
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
            is_remove_from_crl: cert::is_remove_from_crl(info.revocation_reason),
        },
    }
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
    let accepted = accept(check, response_der, None)?;
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
        Status::Revoked {
            is_remove_from_crl: true,
            ..
        } => StapledOutcome::NotRevoked,
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
    let accepted = accept(check, response_der, now)?;

    let in_validity_window = |instant: i64| {
        accepted
            .next_update
            .is_some_and(|next_update| instant > accepted.this_update && instant < next_update)
    };

    let judged_at = attested.or(now);
    let time_condition = judged_at.is_some_and(in_validity_window);

    let status_condition = match accepted.status {
        Status::Good => true,
        Status::Revoked {
            is_remove_from_crl, ..
        } => is_remove_from_crl,
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
        is_remove_from_crl,
    } = accepted.status
    {
        if !is_remove_from_crl {
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

/// Evaluates a response freshly fetched for a *CA* certificate above the
/// claim signer: is that CA revoked?
///
/// §15.9 says only that a CA "revoked at the time indicated in a trusted
/// time-stamp, or at the current time if no trusted time-stamp is present"
/// rejects the claim signature as `signingCredential.untrusted`. It
/// defines no "not revoked" or "inaccessible" status for a CA, so unlike
/// [`evaluate_online`] this answers only that one question — and, with no
/// fail-closed fallback of its own, treats everything it cannot affirm as
/// not revoked: an unauthenticated response, a `good` or `unknown` status,
/// or a `removeFromCRL` revocation. A CA's response is authenticated with
/// the same §3.2 acceptance test as the signer's.
pub(crate) fn evaluate_ca_online(
    check: &PendingOcspCheck,
    response_der: &[u8],
    now: Option<i64>,
    attested: Option<i64>,
) -> bool {
    let Some(accepted) = accept(check, response_der, now) else {
        return false;
    };

    match accepted.status {
        Status::Revoked {
            revocation_time,
            is_remove_from_crl: false,
        } => attested
            .or(now)
            .is_some_and(|judged_at| revocation_time <= judged_at),
        _ => false,
    }
}

/// Seconds in a day, for §15.9.1's `producedAt + 24 hours` fallback
/// window when a stapled response carries no `nextUpdate`.
const ONE_DAY: i64 = 24 * 60 * 60;

/// Finds the certificate whose key actually signed `basic`, among those
/// this module is willing to trust to answer for [`PendingOcspCheck::issuer`].
///
/// `responderID` (RFC 6960 §4.2.1) names who signed by one of two shapes,
/// resolved identically apart from how a candidate is matched: `byName`
/// against a certificate's subject, `byKey` against the SHA-1 hash RFC
/// 6960 fixes that shape to, regardless of the hash algorithm anything
/// else in the exchange uses. Either way (RFC 6960 §4.2.2.2), the match
/// can be the issuer itself, or a delegated responder certificate the
/// issuer issued for exactly this purpose — the same `id-kp-OCSPSigning`
/// profile [`crate::chain::validate`] already holds an end-entity
/// certificate to, checked at `produced_at` (the instant the response
/// itself claims to have been signed) exactly the way any other signing
/// certificate's validity window is checked at its own signing instant
/// elsewhere in this crate — an expired or not-yet-valid delegate is not
/// entitled to answer for anyone. See the module docs for the
/// independently-client-trusted-responder shape RFC 6960 also allows,
/// which this does not resolve.
fn responder_certificate(
    check: &PendingOcspCheck,
    basic: &BasicOcspResponse,
    produced_at: i64,
    online_now: Option<i64>,
) -> Option<Certificate> {
    match &basic.tbs_response_data.responder_id {
        ResponderId::ByName(name) => {
            let name_der = name.to_der().ok()?;

            if name_der == check.issuer.subject_der {
                return Some(check.issuer.clone());
            }

            find_delegate(check, basic, produced_at, online_now, |candidate| {
                candidate.subject_der == name_der
            })
        }

        ResponderId::ByKey(key_hash) => {
            let key_hash = key_hash.as_bytes();

            if sha1_digest(&check.issuer.public_key_bitstring).as_slice() == key_hash {
                return Some(check.issuer.clone());
            }

            find_delegate(check, basic, produced_at, online_now, |candidate| {
                sha1_digest(&candidate.public_key_bitstring).as_slice() == key_hash
            })
        }
    }
}

/// Finds a delegated OCSP responder certificate among `basic.certs` that:
/// `matches_id` picks out (by whichever `ResponderID` shape
/// [`responder_certificate`] is resolving), is certified by
/// [`PendingOcspCheck::issuer`] for exactly the `id-kp-OCSPSigning`
/// purpose, was valid at `produced_at`, and whose own issuer signature
/// verifies.
fn find_delegate(
    check: &PendingOcspCheck,
    basic: &BasicOcspResponse,
    produced_at: i64,
    online_now: Option<i64>,
    matches_id: impl Fn(&Certificate) -> bool,
) -> Option<Certificate> {
    for candidate in basic.certs.as_ref()?.iter() {
        let Ok(der) = candidate.to_der() else {
            continue;
        };
        let Ok(candidate) = cert::decode(&der) else {
            continue;
        };

        if !matches_id(&candidate) {
            continue;
        }

        let names_ocsp_signing = candidate
            .extended_key_usage
            .as_deref()
            .is_some_and(|purposes| purposes.iter().any(|oid| oid == chain::OCSP_SIGNING));

        // A live response's responder must also be authorized *now*
        // (RFC 6960 §4.2.2.2: "currently valid"), not merely at whatever
        // instant the response claims to have been produced — a responder
        // key that has since expired must not be able to backdate
        // `producedAt` into its own validity window. A response already
        // sitting in the manifest store is old by construction, so only
        // `produced_at` applies to it (`online_now` is `None`).
        let inside_validity = [Some(produced_at), online_now]
            .into_iter()
            .flatten()
            .all(|instant| instant >= candidate.not_before && instant <= candidate.not_after);

        if names_ocsp_signing && inside_validity && chain::verify(&candidate, &check.issuer).is_ok()
        {
            return Some(candidate);
        }
    }

    None
}

/// SHA-1 digest of `bytes`, for `ResponderID`'s `byKey` shape (RFC 6960
/// §4.2.1) — the one place this crate computes a SHA-1 hash, since RFC
/// 6960 fixes that comparison to it regardless of any other algorithm's
/// availability or preference.
fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().into()
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

/// A check and a validly signed response to it saying the certificate was
/// revoked at `revocation_time` (the response itself covers 1_000..2_000),
/// for tests elsewhere in this crate that need a real revocation to
/// evaluate rather than a hand-built outcome.
#[cfg(test)]
pub(crate) fn revoked_fixture(revocation_time: i64) -> (PendingOcspCheck, Vec<u8>) {
    let check = tests::check();
    let response = tests::response(
        &check,
        tests::revoked(revocation_time, None),
        1_000,
        Some(2_000),
    );
    (check, response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use core::time::Duration;

    use der::{
        asn1::{BitString, GeneralizedTime, OctetString},
        oid::ObjectIdentifier,
    };
    use x509_cert::{
        ext::pkix::CrlReason,
        time::{Time, Validity},
    };
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

    pub(super) fn check() -> PendingOcspCheck {
        let issuer = issuer();
        PendingOcspCheck {
            responder_url: Some("http://ocsp.example/".to_string()),
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
    pub(super) fn response(
        check: &PendingOcspCheck,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
    ) -> Vec<u8> {
        signed_response(check, status, this_update, next_update, this_update, false)
    }

    pub(super) fn revoked(revocation_time: i64, reason: Option<CrlReason>) -> CertStatus {
        CertStatus::revoked(RevokedInfo {
            revocation_time: generalized_time(revocation_time),
            revocation_reason: reason,
        })
    }

    /// Builds a real, cryptographically valid delegated OCSP responder
    /// certificate: subject `CN=Delegate`, signed by [`TEST_SIGNER_KEY`]
    /// (so it verifies against `issuer()`'s public key, exactly as
    /// [`chain::verify`] would check any other certificate), reusing
    /// [`TEST_SIGNER_CERT`]'s own `SubjectPublicKeyInfo` (so a response
    /// signed with that same key also verifies against *this*
    /// certificate's declared public key), asserting the
    /// `id-kp-OCSPSigning` EKU, and valid over `[not_before, not_after]`.
    fn delegated_responder_cert(not_before: i64, not_after: i64) -> Vec<u8> {
        let issuer_cert = x509_cert::Certificate::from_der(TEST_SIGNER_CERT).expect("decodes");

        let eku = x509_cert::ext::pkix::ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
            chain::OCSP_SIGNING,
        )]);
        // `id-ce-extKeyUsage` (RFC 5280 §4.2.1.12) — the Extended Key Usage
        // *extension's own* OID, distinct from `chain::OCSP_SIGNING`, which
        // is one of the *purposes* it can list.
        let extension = x509_cert::ext::Extension {
            extn_id: ObjectIdentifier::new_unwrap("2.5.29.37"),
            critical: false,
            extn_value: OctetString::new(eku.to_der().expect("encodes")).expect("encodes"),
        };

        let tbs = x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&[7]).expect("encodes"),
            signature: issuer_cert.tbs_certificate.signature.clone(),
            issuer: issuer_cert.tbs_certificate.subject.clone(),
            validity: Validity {
                not_before: Time::GeneralTime(generalized_time(not_before).0),
                not_after: Time::GeneralTime(generalized_time(not_after).0),
            },
            subject: "CN=Delegate".parse().expect("parses"),
            subject_public_key_info: issuer_cert.tbs_certificate.subject_public_key_info.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![extension]),
        };

        let signer = c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .expect("the test key is valid");
        let signature = signer.sign(&tbs.to_der().expect("encodes")).expect("signs");

        let certificate = x509_cert::Certificate {
            tbs_certificate: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature).expect("encodes"),
        };

        certificate.to_der().expect("encodes")
    }

    /// As [`signed_response`], but names `delegate` (rather than the
    /// issuer itself) as the responder, with `delegate`'s DER embedded in
    /// the response's own `certs` field — exercising the delegated-
    /// responder path in `responder_certificate` rather than the
    /// issuer-answered-directly one every other test here uses.
    fn signed_response_via_delegate(
        check: &PendingOcspCheck,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
        produced_at: i64,
        delegate_der: &[u8],
    ) -> Vec<u8> {
        let single = SingleResponse {
            cert_id: check.cert_id.clone(),
            cert_status: status,
            this_update: generalized_time(this_update),
            next_update: next_update.map(generalized_time),
            single_extensions: None,
        };

        let delegate = x509_cert::Certificate::from_der(delegate_der).expect("decodes");

        let tbs = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByName(delegate.tbs_certificate.subject.clone()),
            produced_at: generalized_time(produced_at),
            responses: vec![single],
            response_extensions: None,
        };

        let signer = c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .expect("the test key is valid");
        let signature = signer.sign(&tbs.to_der().expect("encodes")).expect("signs");

        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature).expect("encodes"),
            certs: Some(vec![delegate]),
        };

        OcspResponse::successful(basic)
            .expect("encodes")
            .to_der()
            .expect("encodes")
    }

    /// As [`signed_response`], but names the responder by `ResponderID`'s
    /// `byKey` shape (a SHA-1 hash of `key_hash_of`'s public key) instead
    /// of `byName`, with `certs` embedded in the response verbatim —
    /// exercising the `ResponderId::ByKey` arm of `responder_certificate`.
    fn signed_response_by_key(
        check: &PendingOcspCheck,
        status: CertStatus,
        this_update: i64,
        next_update: Option<i64>,
        produced_at: i64,
        key_hash: &[u8],
        certs: Option<Vec<x509_cert::Certificate>>,
    ) -> Vec<u8> {
        let single = SingleResponse {
            cert_id: check.cert_id.clone(),
            cert_status: status,
            this_update: generalized_time(this_update),
            next_update: next_update.map(generalized_time),
            single_extensions: None,
        };

        let tbs = ResponseData {
            version: Version::V1,
            responder_id: ResponderId::ByKey(OctetString::new(key_hash.to_vec()).expect("encodes")),
            produced_at: generalized_time(produced_at),
            responses: vec![single],
            response_extensions: None,
        };

        let signer = c2pa_raw_crypto::signer_from_private_key(
            TEST_SIGNER_KEY,
            c2pa_raw_crypto::SigningAlg::Es256,
        )
        .expect("the test key is valid");
        let signature = signer.sign(&tbs.to_der().expect("encodes")).expect("signs");

        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature).expect("encodes"),
            certs,
        };

        OcspResponse::successful(basic)
            .expect("encodes")
            .to_der()
            .expect("encodes")
    }

    #[test]
    fn online_accepts_a_response_from_the_issuer_identified_by_key_hash() {
        let check = check();
        let key_hash = sha1_digest(&issuer().public_key_bitstring);
        let response = signed_response_by_key(
            &check,
            CertStatus::good(),
            1_000,
            Some(2_000),
            1_000,
            &key_hash,
            None,
        );

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::NotRevoked
        );
    }

    #[test]
    fn online_a_response_naming_a_wrong_key_hash_is_inconclusive() {
        // A delegate certificate is included too, so this also proves a
        // non-matching key hash is rejected rather than accepted by
        // accident when candidates are actually present to check.
        let check = check();
        let delegate = delegated_responder_cert(0, 1_000_000_000);
        let wrong_hash = [0u8; 20];
        let response = signed_response_by_key(
            &check,
            CertStatus::good(),
            1_000,
            Some(2_000),
            1_000,
            &wrong_hash,
            Some(vec![
                x509_cert::Certificate::from_der(&delegate).expect("decodes")
            ]),
        );

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    #[test]
    fn online_accepts_a_response_from_a_delegated_responder_inside_its_validity_window() {
        let check = check();
        let delegate = delegated_responder_cert(0, 1_000_000_000);
        let response = signed_response_via_delegate(
            &check,
            CertStatus::good(),
            1_000,
            Some(2_000),
            1_000,
            &delegate,
        );

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::NotRevoked
        );
    }

    #[test]
    fn online_rejects_a_delegated_responder_whose_certificate_had_already_expired() {
        // The delegate's validity window ends well before the response's
        // own `producedAt`, so it was not entitled to answer at all —
        // an expired delegated credential must not be able to authenticate
        // a response just because its issuer signature still verifies.
        let check = check();
        let delegate = delegated_responder_cert(0, 500);
        let response = signed_response_via_delegate(
            &check,
            CertStatus::good(),
            1_000,
            Some(2_000),
            1_000,
            &delegate,
        );

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    #[test]
    fn online_rejects_a_delegate_that_has_expired_by_now_even_if_produced_at_is_backdated() {
        // The delegate was valid when the response *claims* to have been
        // produced (1_000), but expired at 1_500 — long before "now"
        // (5_000). A live response must be authorized at the current
        // time, not merely at whatever instant it says it was signed.
        let check = check();
        let delegate = delegated_responder_cert(0, 1_500);
        let response = signed_response_via_delegate(
            &check,
            CertStatus::good(),
            1_000,
            Some(6_000),
            1_000,
            &delegate,
        );

        assert_eq!(
            evaluate_online(&check, &response, Some(5_000), Some(1_200)),
            OnlineOutcome::Inconclusive
        );

        // The same response is fine while the delegate is still current.
        assert_eq!(
            evaluate_online(&check, &response, Some(1_400), Some(1_200)),
            OnlineOutcome::NotRevoked
        );
    }

    #[test]
    fn a_stapled_response_is_judged_at_produced_at_only_not_at_now() {
        // A response sitting in the manifest store is old by construction:
        // its responder's certificate may well have expired since, which
        // says nothing about whether it was entitled to answer then.
        let check = check();
        let delegate = delegated_responder_cert(0, 1_500);
        let response = signed_response_via_delegate(
            &check,
            CertStatus::good(),
            1_000,
            Some(2_000),
            1_000,
            &delegate,
        );

        assert_eq!(
            evaluate_stapled(&check, &response, Some(5_000), Some(1_200)),
            StapledOutcome::NotRevoked
        );
    }

    #[test]
    fn ca_online_revoked_before_the_attested_time_is_revoked() {
        let check = check();
        let response = response(&check, revoked(1_200, None), 1_000, Some(2_000));

        assert!(evaluate_ca_online(&check, &response, None, Some(1_500)));
    }

    #[test]
    fn ca_online_revoked_without_an_attested_time_is_judged_at_now() {
        let check = check();
        let response = response(&check, revoked(1_200, None), 1_000, Some(2_000));

        assert!(evaluate_ca_online(&check, &response, Some(1_500), None));
        assert!(!evaluate_ca_online(&check, &response, Some(1_100), None));
        assert!(!evaluate_ca_online(&check, &response, None, None));
    }

    #[test]
    fn ca_online_revoked_after_the_attested_time_is_not_revoked() {
        let check = check();
        let response = response(&check, revoked(1_800, None), 1_000, Some(2_000));

        assert!(!evaluate_ca_online(
            &check,
            &response,
            Some(5_000),
            Some(1_500)
        ));
    }

    #[test]
    fn ca_online_only_a_real_revocation_counts() {
        let check = check();

        for status in [
            CertStatus::good(),
            CertStatus::unknown(),
            revoked(900, Some(CrlReason::RemoveFromCRL)),
        ] {
            let response = response(&check, status, 1_000, Some(2_000));
            assert!(!evaluate_ca_online(
                &check,
                &response,
                Some(1_500),
                Some(1_500)
            ));
        }
    }

    #[test]
    fn ca_online_an_unauthenticated_response_is_never_a_revocation() {
        // Unlike the signer's check there is no fail-closed fallback: a
        // response that cannot be authenticated says nothing about the CA.
        let check = check();
        let wrong_hash = [0u8; 20];
        let forged = signed_response_by_key(
            &check,
            revoked(900, None),
            1_000,
            Some(2_000),
            1_000,
            &wrong_hash,
            None,
        );

        assert!(!evaluate_ca_online(
            &check,
            &forged,
            Some(1_500),
            Some(1_500)
        ));
        assert!(!evaluate_ca_online(
            &check,
            &[0xff, 0xff],
            Some(1_500),
            Some(1_500)
        ));
    }

    #[test]
    fn online_rejects_a_delegated_responder_whose_certificate_was_not_yet_valid() {
        let check = check();
        let delegate = delegated_responder_cert(2_000, 1_000_000_000);
        let response = signed_response_via_delegate(
            &check,
            CertStatus::good(),
            1_000,
            Some(2_000),
            1_000,
            &delegate,
        );

        assert_eq!(
            evaluate_online(&check, &response, None, Some(1_500)),
            OnlineOutcome::Inconclusive
        );
    }

    #[test]
    fn build_check_succeeds_without_a_responder_url() {
        // A certificate with no AIA extension still gets a check: it can be
        // matched against a stapled response by `CertID` even though there
        // is nowhere to send an online request.
        let mut subject = subject();
        subject.ocsp_responder_url = None;

        let check = build_check(&subject, &issuer()).expect("still builds a check");
        assert_eq!(check.responder_url, None);
    }

    #[test]
    fn build_check_names_the_right_certificate() {
        let mut subject = subject();
        subject.ocsp_responder_url = Some("http://ocsp.example/".to_string());

        let check = build_check(&subject, &issuer()).expect("names a responder");
        assert_eq!(check.responder_url.as_deref(), Some("http://ocsp.example/"));

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
