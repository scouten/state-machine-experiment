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

//! The `cawg.x509.cose` credential type.
//!
//! The assertion's `signature` is a `COSE_Sign1` whose payload is the
//! `signer_payload`, detached — the same construction as a C2PA claim
//! signature, down to the `x5chain` header and the optional RFC 3161
//! timestamp — so it is verified by the same code as one, reported under
//! CAWG's own status codes (see [`crate::validation::SignatureCodes`]). The
//! certificate chain it carries is then judged like a claim signer's,
//! against the identity trust anchors rather than the claim ones (see
//! [`crate::read::ReadSettings::identity_trust_anchors`]).

use crate::validation::{
    check_cose_signature, ValidationStatus, VerifiedSignature, CAWG_X509_SIGNATURE_CODES,
};

/// Verifies the `COSE_Sign1` in `signature` over `signer_payload` — the
/// payload's bytes exactly as the assertion encoded them.
///
/// Returns what the session needs to judge the signer's chain once it has
/// a time, only for a signature that verified.
pub(super) fn verify(
    url: &str,
    signer_payload: &[u8],
    signature: &[u8],
    statuses: &mut Vec<ValidationStatus>,
) -> Option<VerifiedSignature> {
    check_cose_signature(
        url,
        signer_payload,
        signature,
        &CAWG_X509_SIGNATURE_CODES,
        statuses,
    )
}
