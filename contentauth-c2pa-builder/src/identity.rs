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

use contentauth_c2pa_primitives::{
    cbor::{byte_string, head},
    SigningAlg,
};

use crate::{cose, error::Error};

/// Label of the first identity assertion; later ones are
/// `cawg.identity__1`, `cawg.identity__2`, ….
pub const LABEL: &str = "cawg.identity";

/// `sig_type` of an X.509 credential signed as a `COSE_Sign1`.
const SIG_TYPE_X509_COSE: &str = "cawg.x509.cose";

/// CBOR major type 3: text string.
const MAJOR_TEXT: u8 = 3;

/// CBOR major type 4: array.
const MAJOR_ARRAY: u8 = 4;

/// CBOR major type 5: map.
const MAJOR_MAP: u8 = 5;

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

/// Writes a CBOR text string.
fn text(out: &mut Vec<u8>, text: &str) {
    head(out, MAJOR_TEXT, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

/// The label of the `index`th identity assertion in a manifest.
pub(crate) fn label_for(index: usize) -> String {
    match index {
        0 => LABEL.to_string(),
        n => format!("{LABEL}__{n}"),
    }
}

/// Encodes a `signer_payload`: the assertions vouched for (each a URI and
/// its hash), the `sig_type`, and the roles if any.
///
/// Written by hand, in the field order c2pa-rs serialises it in
/// (`referenced_assertions`, `sig_type`, `role`) and with the hashed URIs
/// naming no algorithm of their own, so the bytes are identical to the
/// ones a c2pa-rs verifier re-derives from the decoded payload. The
/// reader in this workspace verifies against the bytes as written, so
/// does not depend on this; another one may.
pub(crate) fn signer_payload(
    referenced: &[(String, Vec<u8>)],
    sig_type: &str,
    roles: &[String],
) -> Vec<u8> {
    let mut out = Vec::new();

    head(&mut out, MAJOR_MAP, if roles.is_empty() { 2 } else { 3 });

    text(&mut out, "referenced_assertions");
    head(&mut out, MAJOR_ARRAY, referenced.len() as u64);
    for (url, hash) in referenced {
        head(&mut out, MAJOR_MAP, 2);
        text(&mut out, "url");
        text(&mut out, url);
        text(&mut out, "hash");
        byte_string(&mut out, hash);
    }

    text(&mut out, "sig_type");
    text(&mut out, sig_type);

    if !roles.is_empty() {
        text(&mut out, "role");
        head(&mut out, MAJOR_ARRAY, roles.len() as u64);
        for role in roles {
            text(&mut out, role);
        }
    }

    out
}

/// Encodes the identity assertion itself: the `signer_payload` verbatim,
/// the `signature`, and an empty `pad1` (present because the
/// specification requires it; the length of this assertion is fixed by the
/// signature's, so there is nothing to pad).
pub(crate) fn assertion_cbor(signer_payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    head(&mut out, MAJOR_MAP, 3);
    text(&mut out, "signer_payload");
    out.extend_from_slice(signer_payload);
    text(&mut out, "signature");
    byte_string(&mut out, signature);
    text(&mut out, "pad1");
    byte_string(&mut out, &[]);

    out
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

        let bytes = signer_payload(&referenced, SIG_TYPE_X509_COSE, &roles);
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
        let bytes = signer_payload(&[], SIG_TYPE_X509_COSE, &[]);
        let value: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        let map = value.as_map().unwrap();

        assert_eq!(map.len(), 2);
        assert!(!map.contains_key(&Value::Text("role".into())));
    }

    #[test]
    fn the_assertion_embeds_the_payload_verbatim() {
        let payload = signer_payload(&[], SIG_TYPE_X509_COSE, &[]);
        let bytes = assertion_cbor(&payload, &[7; 5]);

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
        assert!(bytes
            .windows(payload.len())
            .any(|w| w == payload.as_slice()));
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

        let payload = signer_payload(&[], plan.sig_type, &[]);
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
