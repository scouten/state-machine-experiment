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

//! CAWG identity assertions: [`IdentitySettings`], and the encoding of the
//! assertion each one becomes.
//!
//! An identity assertion is a named actor's signed statement that they
//! stand behind particular assertions in the manifest — including its hard
//! binding — and so cannot be written until the hard binding's hash is
//! known. The session therefore reserves it in the placeholder manifest
//! like the claim signature (zero-filled at its exact final length), and
//! once the asset has been hashed asks the host to sign it, under a
//! [`SignPurpose::Identity`] so a host holding several keys can tell
//! whose key is wanted, before the claim — which lists the assertion's own
//! hash — is signed.
//!
//! # Credential types
//!
//! [`IdentityCredential`] is the seam. Today it has one variant, the X.509
//! credential (`cawg.x509.cose`); another type is a new variant, which
//! decides the `sig_type`, how long the reserved signature is, and what
//! the host is asked to sign. Everything else — referencing assertions,
//! padding, placement — is common to all of them.
//!
//! [`SignPurpose::Identity`]: crate::SignPurpose::Identity

use contentauth_c2pa_primitives::SigningAlg;
use serde::Serialize;
use serde_bytes::Bytes;

use crate::{cose, error::Error};

/// Label of the first identity assertion; later ones are
/// `cawg.identity__1`, `cawg.identity__2`, ….
pub const LABEL: &str = "cawg.identity";

/// `sig_type` of an X.509 credential signed as a `COSE_Sign1`.
const SIG_TYPE_X509_COSE: &str = "cawg.x509.cose";

/// One CAWG identity assertion to add to the manifest.
///
/// The named actor the assertion speaks for is whoever holds the
/// credential's key; this crate neither knows nor checks who that is, and
/// the host vouches for the certificates it supplies, exactly as for the
/// claim signature.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IdentitySettings {
    /// How the named actor is proven.
    pub credential: IdentityCredential,

    /// The roles the named actor claims for themselves (CAWG's `role`).
    /// Empty to claim none.
    pub roles: Vec<String>,

    /// The labels of the [`BuilderSettings::assertions`] the actor vouches
    /// for, or `None` for all of them.
    ///
    /// The hard binding is always vouched for as well — the specification
    /// requires it, and it is what ties the actor's statement to this
    /// asset — and so is never named here. Identity assertions never
    /// vouch for one another.
    ///
    /// [`BuilderSettings::assertions`]: crate::BuilderSettings::assertions
    pub referenced_assertions: Option<Vec<String>>,
}

impl IdentitySettings {
    /// An identity assertion backed by an X.509 credential, vouching for
    /// every assertion, claiming no role.
    pub fn x509(signing_alg: SigningAlg, certificates: Vec<Vec<u8>>) -> Self {
        Self {
            credential: IdentityCredential::X509Cose {
                signing_alg,
                certificates,
                rsa_signature_len: None,
            },
            roles: Vec::new(),
            referenced_assertions: None,
        }
    }
}

/// The kind of credential an identity assertion is signed with.
///
/// Adding a kind is a new variant here: it decides the `sig_type`, how long
/// the reserved signature is, and what the host is asked to sign.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum IdentityCredential {
    /// `cawg.x509.cose`: a `COSE_Sign1` signed with the key of an X.509
    /// certificate, whose chain travels in its `x5chain` header.
    X509Cose {
        /// The algorithm to sign with.
        signing_alg: SigningAlg,

        /// DER-encoded certificate chain, signer first. Passed through
        /// opaquely, as [`BuilderSettings::certificates`] is.
        ///
        /// [`BuilderSettings::certificates`]: crate::BuilderSettings::certificates
        certificates: Vec<Vec<u8>>,

        /// The exact signature length, required if and only if
        /// `signing_alg` is RSASSA-PSS; see
        /// [`BuilderSettings::rsa_signature_len`].
        ///
        /// [`BuilderSettings::rsa_signature_len`]: crate::BuilderSettings::rsa_signature_len
        rsa_signature_len: Option<usize>,
    },
}

/// What a credential contributes to building its assertion, resolved once
/// at the start of the workflow.
#[derive(Clone, Debug)]
pub(crate) struct CredentialPlan {
    /// The `sig_type` the assertion declares.
    pub(crate) sig_type: &'static str,

    /// The algorithm the host signs with.
    pub(crate) alg: SigningAlg,

    /// The protected header of the `COSE_Sign1`, which the signature
    /// covers.
    pub(crate) protected_header: Vec<u8>,

    /// The exact length of the signature the host returns.
    pub(crate) signature_len: usize,
}

impl IdentityCredential {
    /// Validates the credential's settings and resolves what building
    /// with it needs.
    pub(crate) fn plan(&self) -> Result<CredentialPlan, Error> {
        match self {
            Self::X509Cose {
                signing_alg,
                certificates,
                rsa_signature_len,
            } => {
                if certificates.is_empty() {
                    return Err(Error::NoCertificates);
                }

                Ok(CredentialPlan {
                    sig_type: SIG_TYPE_X509_COSE,
                    alg: *signing_alg,
                    protected_header: cose::protected_header(*signing_alg, certificates)?,
                    signature_len: cose::signature_len(*signing_alg, *rsa_signature_len)?,
                })
            }
        }
    }

    /// The `signature` field's bytes, given the host's raw signature.
    pub(crate) fn signature_field(
        &self,
        plan: &CredentialPlan,
        signature: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::X509Cose { .. } => {
                cose::build_cose_sign1(&plan.protected_header, empty_map(), signature)
            }
        }
    }

    /// The bytes the host is asked to sign for a given signer payload.
    pub(crate) fn to_be_signed(&self, plan: &CredentialPlan, signer_payload: &[u8]) -> Vec<u8> {
        match self {
            Self::X509Cose { .. } => {
                cose::claim_to_be_signed(&plan.protected_header, signer_payload)
            }
        }
    }
}

/// An empty CBOR map, the `COSE_Sign1` unprotected header of an identity
/// signature (which carries no timestamp).
fn empty_map() -> c2pa_cbor::Value {
    c2pa_cbor::Value::Map(std::collections::BTreeMap::new())
}

/// The label of the `index`th identity assertion in a manifest.
pub(crate) fn label_for(index: usize) -> String {
    match index {
        0 => LABEL.to_string(),
        n => format!("{LABEL}__{n}"),
    }
}

/// A hashed reference to an assertion, as the `signer_payload` lists it.
#[derive(Serialize)]
struct HashedUri<'a> {
    url: &'a str,
    #[serde(with = "serde_bytes")]
    hash: &'a [u8],
}

/// The `signer_payload`. Field order is the order c2pa-rs declares and so
/// serialises them in (`referenced_assertions`, `sig_type`, `role`) — a
/// sorted map would put `role` first, and a verifier that re-derives the
/// bytes from the decoded payload, as c2pa-rs does, would then see a
/// signature over bytes it does not reproduce. The reader in this
/// workspace verifies the bytes as written and does not depend on this.
#[derive(Serialize)]
struct SignerPayload<'a> {
    referenced_assertions: Vec<HashedUri<'a>>,
    sig_type: &'a str,
    #[serde(rename = "role", skip_serializing_if = "<[String]>::is_empty")]
    roles: &'a [String],
}

/// The identity assertion: the `signer_payload`, the `signature`, and an
/// empty `pad1` (required by the specification; this assertion's length is
/// fixed by the signature's, so there is nothing to pad).
///
/// The payload is serialised in place from the same struct the signed
/// bytes came from, so it reproduces them exactly: a nested value is
/// encoded as it would be alone.
#[derive(Serialize)]
struct IdentityAssertion<'a> {
    signer_payload: SignerPayload<'a>,
    #[serde(with = "serde_bytes")]
    signature: &'a [u8],
    pad1: &'a Bytes,
}

/// Encodes a `signer_payload`: the assertions vouched for (each a URI and
/// its hash), the `sig_type`, and the roles if any.
pub(crate) fn signer_payload(
    referenced: &[(String, Vec<u8>)],
    sig_type: &str,
    roles: &[String],
) -> Result<Vec<u8>, Error> {
    Ok(c2pa_cbor::to_vec(&payload(referenced, sig_type, roles))?)
}

fn payload<'a>(
    referenced: &'a [(String, Vec<u8>)],
    sig_type: &'a str,
    roles: &'a [String],
) -> SignerPayload<'a> {
    SignerPayload {
        referenced_assertions: referenced
            .iter()
            .map(|(url, hash)| HashedUri { url, hash })
            .collect(),
        sig_type,
        roles,
    }
}

/// Encodes the identity assertion: the same payload [`signer_payload`]
/// encodes, and the `signature` field.
pub(crate) fn assertion_cbor(
    referenced: &[(String, Vec<u8>)],
    sig_type: &str,
    roles: &[String],
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    Ok(c2pa_cbor::to_vec(&IdentityAssertion {
        signer_payload: payload(referenced, sig_type, roles),
        signature,
        pad1: Bytes::new(&[]),
    })?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa_cbor::Value;

    use super::*;

    #[test]
    fn labels_count_up_from_the_bare_label() {
        assert_eq!(label_for(0), "cawg.identity");
        assert_eq!(label_for(1), "cawg.identity__1");
        assert_eq!(label_for(12), "cawg.identity__12");
    }

    #[test]
    fn the_signer_payload_decodes_as_the_schema_says() {
        let referenced = vec![
            ("self#jumbf=c2pa.assertions/a".to_string(), vec![1, 2, 3]),
            (
                "self#jumbf=c2pa.assertions/c2pa.hash.data".to_string(),
                vec![4],
            ),
        ];
        let roles = vec!["creator".to_string(), "editor".to_string()];

        let bytes = signer_payload(&referenced, SIG_TYPE_X509_COSE, &roles).unwrap();
        let value: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = value.as_map().unwrap();

        assert_eq!(
            map.get(&Value::Text("sig_type".into())),
            Some(&Value::Text("cawg.x509.cose".into()))
        );
        assert_eq!(
            map.get(&Value::Text("role".into())),
            Some(&Value::Array(vec![
                Value::Text("creator".into()),
                Value::Text("editor".into())
            ]))
        );

        let refs = map
            .get(&Value::Text("referenced_assertions".into()))
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(refs.len(), 2);
        let first = refs[0].as_map().unwrap();
        assert_eq!(
            first.get(&Value::Text("hash".into())),
            Some(&Value::Bytes(vec![1, 2, 3]))
        );
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn no_roles_means_no_role_field() {
        let bytes = signer_payload(&[], SIG_TYPE_X509_COSE, &[]).unwrap();
        let value: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = value.as_map().unwrap();

        assert_eq!(map.len(), 2);
        assert!(!map.contains_key(&Value::Text("role".into())));
    }

    #[test]
    fn the_payload_is_in_c2pa_rs_field_order_not_sorted() {
        // `role` is declared last, so it is written last; a sorted map
        // would put it between the other two.
        let roles = vec!["creator".to_string()];
        let bytes = signer_payload(&[], SIG_TYPE_X509_COSE, &roles).unwrap();

        let position = |needle: &[u8]| bytes.windows(needle.len()).position(|w| w == needle);
        let refs = position(b"referenced_assertions").unwrap();
        let sig_type = position(b"sig_type").unwrap();
        let role = position(b"role").unwrap();
        assert!(refs < sig_type && sig_type < role);
    }

    #[test]
    fn the_assertion_embeds_exactly_the_bytes_that_were_signed() {
        let referenced = vec![("self#jumbf=c2pa.assertions/a".to_string(), vec![1, 2, 3])];
        let roles = vec!["creator".to_string(), "editor".to_string()];

        let payload = signer_payload(&referenced, SIG_TYPE_X509_COSE, &roles).unwrap();
        let bytes = assertion_cbor(&referenced, SIG_TYPE_X509_COSE, &roles, &[7; 5]).unwrap();

        assert!(bytes
            .windows(payload.len())
            .any(|w| w == payload.as_slice()));

        let value: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(
            map.get(&Value::Text("signature".into())),
            Some(&Value::Bytes(vec![7; 5]))
        );
        assert_eq!(
            map.get(&Value::Text("pad1".into())),
            Some(&Value::Bytes(vec![]))
        );
    }

    #[test]
    fn an_x509_credential_needs_a_certificate() {
        let settings = IdentitySettings::x509(SigningAlg::Es256, vec![]);
        assert!(matches!(
            settings.credential.plan(),
            Err(Error::NoCertificates)
        ));
    }

    #[test]
    fn an_rsa_credential_needs_its_signature_length() {
        let settings = IdentitySettings::x509(SigningAlg::Ps256, vec![vec![1]]);
        assert!(matches!(
            settings.credential.plan(),
            Err(Error::MissingRsaSignatureLen(SigningAlg::Ps256))
        ));
    }

    #[test]
    fn an_x509_plan_resolves_what_the_build_needs() {
        let settings = IdentitySettings::x509(SigningAlg::Es256, vec![vec![1, 2, 3]]);
        let plan = settings.credential.plan().unwrap();

        assert_eq!(plan.sig_type, "cawg.x509.cose");
        assert_eq!(plan.alg, SigningAlg::Es256);
        assert_eq!(plan.signature_len, 64);

        let payload = signer_payload(&[], plan.sig_type, &[]).unwrap();
        let to_be_signed = settings.credential.to_be_signed(&plan, &payload);
        assert!(to_be_signed
            .windows(payload.len())
            .any(|w| w == payload.as_slice()));

        let field = settings
            .credential
            .signature_field(&plan, &[9; 64])
            .unwrap();
        let cose: Value = c2pa_cbor::from_slice(&field).unwrap();
        assert!(matches!(cose, Value::Tag(18, _)));
    }
}
