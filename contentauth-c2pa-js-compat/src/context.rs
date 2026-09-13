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

//! [`Context`]: the settings a read runs under, parsed from the
//! `contextJson` string c2pa-wasm's `fromBlob` takes.
//!
//! c2pa-wasm passes that string to c2pa-rs's `Context::with_settings`,
//! which parses it as c2pa-rs's own settings document — a large, nested
//! JSON schema of which this crate recognizes the slice its read-only,
//! single-asset use case can act on:
//!
//! ```json
//! {
//!   "trust": {
//!     "trust_anchors": "-----BEGIN CERTIFICATE-----\n...",
//!     "user_anchors": "-----BEGIN CERTIFICATE-----\n..."
//!   },
//!   "verify": {
//!     "ocsp_fetch": false,
//!     "remote_manifest_fetch": true
//!   }
//! }
//! ```
//!
//! Both anchor lists are PEM bundles, as they are in c2pa-rs, and both
//! feed the same trust evaluation there; here they are decoded to DER and
//! concatenated into [`ReadSettings::trust_anchors`] and, since c2pa-rs
//! judges timestamp authorities against the same trust store,
//! [`ReadSettings::timestamp_trust_anchors`] too. Any other key is
//! ignored, so a full c2pa-rs settings document loads without complaint
//! — the alternative, rejecting a setting this crate has no counterpart
//! for, would make the same client code fail here and succeed against
//! c2pa-wasm, which is the opposite of what a compatibility layer is for.
//! A key this crate *does* recognize but cannot parse (a malformed
//! certificate, a non-boolean `ocsp_fetch`) is a
//! [`C2paError::BadParam`], as it would be in c2pa-rs.
//!
//! One deliberate divergence: c2pa-rs's `ocsp_fetch` defaults to `false`,
//! while this workspace's engine defaults online OCSP checking to *on*
//! (see [`ReadSettings::check_ocsp`] for why). A `contextJson` that says
//! `"ocsp_fetch": false` gets c2pa-rs's behavior; one that says nothing
//! gets this workspace's — which, on a [`Platform`](crate::Platform) that
//! declines OCSP, reads exactly as though it were off.

use base64::Engine as _;
use contentauth_c2pa_file_reader::ReadSettings;
use serde::Deserialize;

use crate::error::C2paError;

/// The settings a [`crate::Reader`] reads under.
///
/// Built from c2pa-wasm's `contextJson` by [`Self::from_json`], or
/// directly from a [`ReadSettings`] by [`Self::from_settings`] for a
/// caller that would rather not go through JSON at all.
#[derive(Clone, Debug, Default)]
pub struct Context {
    settings: ReadSettings,
}

impl Context {
    /// Parses c2pa-rs settings JSON, as described in the module docs.
    pub fn from_json(json: &str) -> Result<Self, C2paError> {
        let doc: SettingsJson = serde_json::from_str(json)
            .map_err(|err| C2paError::BadParam(format!("settings JSON: {err}")))?;

        let mut anchors = Vec::new();
        for (key, pem) in [
            ("trust.trust_anchors", doc.trust.trust_anchors),
            ("trust.user_anchors", doc.trust.user_anchors),
        ] {
            if let Some(pem) = pem {
                anchors.extend(
                    pem_certificates(&pem).map_err(|err| {
                        C2paError::BadParam(format!("settings JSON: {key}: {err}"))
                    })?,
                );
            }
        }

        // Every field is named here on purpose: a setting the engine grows
        // is one this parser should be made to decide about, not one that
        // silently keeps its default.
        let defaults = ReadSettings::default();
        let settings = ReadSettings {
            trust_anchors: anchors.clone(),
            timestamp_trust_anchors: anchors,
            check_ocsp: doc.verify.ocsp_fetch.unwrap_or(defaults.check_ocsp),
            fetch_remote_manifests: doc
                .verify
                .remote_manifest_fetch
                .unwrap_or(defaults.fetch_remote_manifests),
        };

        Ok(Self { settings })
    }

    /// Wraps settings already in this workspace's own vocabulary.
    pub fn from_settings(settings: ReadSettings) -> Self {
        Self { settings }
    }

    /// The settings this context reads under.
    pub fn settings(&self) -> &ReadSettings {
        &self.settings
    }

    /// Consumes this context, returning its settings.
    pub fn into_settings(self) -> ReadSettings {
        self.settings
    }
}

/// The slice of c2pa-rs's settings document this crate recognizes. Every
/// field is optional and every unknown key is ignored — see the module
/// docs for why.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SettingsJson {
    trust: TrustJson,
    verify: VerifyJson,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct TrustJson {
    trust_anchors: Option<String>,
    user_anchors: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct VerifyJson {
    ocsp_fetch: Option<bool>,
    remote_manifest_fetch: Option<bool>,
}

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Decodes every `CERTIFICATE` block in a PEM bundle to DER, in order.
///
/// Only the certificate armor is recognized; a bundle with no certificate
/// block at all — including one that is not PEM in the first place — is an
/// error rather than an empty list, since an anchor list a caller went to
/// the trouble of supplying and that then trusts nobody is a mistake worth
/// surfacing. An empty or whitespace-only string, by contrast, is an
/// explicitly empty list.
fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut certificates = Vec::new();
    let mut rest = pem;

    while let Some(begin) = rest.find(PEM_BEGIN) {
        let after_begin = &rest[begin + PEM_BEGIN.len()..];
        let end = after_begin
            .find(PEM_END)
            .ok_or_else(|| "unterminated CERTIFICATE block".to_string())?;

        let body: String = after_begin[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|err| format!("CERTIFICATE block is not valid base64: {err}"))?;
        if der.is_empty() {
            return Err("CERTIFICATE block is empty".to_string());
        }

        certificates.push(der);
        rest = &after_begin[end + PEM_END.len()..];
    }

    if certificates.is_empty() && !pem.trim().is_empty() {
        return Err("no CERTIFICATE block found".to_string());
    }

    Ok(certificates)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];

    fn pem_of(der: &[u8]) -> String {
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        format!("{PEM_BEGIN}\n{body}\n{PEM_END}\n")
    }

    #[test]
    fn a_context_from_no_json_at_all_has_default_settings() {
        let context = Context::default();
        assert!(context.settings().trust_anchors.is_empty());
        assert_eq!(
            context.settings().check_ocsp,
            ReadSettings::default().check_ocsp
        );
    }

    #[test]
    fn an_empty_document_has_default_settings() {
        let context = Context::from_json("{}").expect("parses");
        assert!(context.settings().trust_anchors.is_empty());
        assert!(context.settings().timestamp_trust_anchors.is_empty());
        assert_eq!(
            context.settings().check_ocsp,
            ReadSettings::default().check_ocsp
        );
    }

    #[test]
    fn trust_anchors_and_user_anchors_are_decoded_from_pem_into_both_anchor_lists() {
        let other = [0x30u8, 0x03, 0x02, 0x01, 0x02];
        let json = serde_json::json!({
            "trust": {
                "trust_anchors": pem_of(DER),
                "user_anchors": pem_of(&other),
            }
        })
        .to_string();

        let context = Context::from_json(&json).expect("parses");
        assert_eq!(
            context.settings().trust_anchors,
            vec![DER.to_vec(), other.to_vec()]
        );
        assert_eq!(
            context.settings().timestamp_trust_anchors,
            vec![DER.to_vec(), other.to_vec()]
        );
    }

    #[test]
    fn a_pem_bundle_yields_every_certificate_in_order() {
        let other = [0x30u8, 0x03, 0x02, 0x01, 0x02];
        let bundle = format!("{}{}", pem_of(DER), pem_of(&other));
        assert_eq!(
            pem_certificates(&bundle).expect("decodes"),
            vec![DER.to_vec(), other.to_vec()]
        );
    }

    #[test]
    fn pem_with_windows_line_endings_and_surrounding_text_still_decodes() {
        let body = base64::engine::general_purpose::STANDARD.encode(DER);
        let pem = format!("subject=CN=x\r\n{PEM_BEGIN}\r\n{body}\r\n{PEM_END}\r\ntrailer\r\n");
        assert_eq!(pem_certificates(&pem).expect("decodes"), vec![DER.to_vec()]);
    }

    #[test]
    fn an_empty_anchor_string_is_an_empty_list() {
        assert_eq!(
            pem_certificates("").expect("decodes"),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            pem_certificates("  \n").expect("decodes"),
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn anchors_that_are_not_pem_are_a_bad_param() {
        let json =
            serde_json::json!({ "trust": { "trust_anchors": "not a certificate" } }).to_string();
        let err = Context::from_json(&json).expect_err("rejects");
        assert!(matches!(err, C2paError::BadParam(_)), "{err:?}");
    }

    #[test]
    fn an_unterminated_or_undecodable_or_empty_block_is_an_error() {
        assert!(pem_certificates(&format!("{PEM_BEGIN}\nAAAA\n")).is_err());
        assert!(pem_certificates(&format!("{PEM_BEGIN}\n!!!!\n{PEM_END}\n")).is_err());
        assert!(pem_certificates(&format!("{PEM_BEGIN}\n{PEM_END}\n")).is_err());
    }

    #[test]
    fn verify_flags_override_the_defaults() {
        let context = Context::from_json(
            r#"{ "verify": { "ocsp_fetch": false, "remote_manifest_fetch": false } }"#,
        )
        .expect("parses");
        assert!(!context.settings().check_ocsp);
        assert!(!context.settings().fetch_remote_manifests);

        let context =
            Context::from_json(r#"{ "verify": { "ocsp_fetch": true } }"#).expect("parses");
        assert!(context.settings().check_ocsp);
    }

    #[test]
    fn a_verify_flag_of_the_wrong_type_is_a_bad_param() {
        let err =
            Context::from_json(r#"{ "verify": { "ocsp_fetch": "yes" } }"#).expect_err("rejects");
        assert!(matches!(err, C2paError::BadParam(_)), "{err:?}");
    }

    #[test]
    fn keys_this_crate_has_no_counterpart_for_are_ignored() {
        let json = r#"{
            "version": 1,
            "trust": { "trust_config": "1.3.6.1.5.5.7.3.36", "allowed_list": null },
            "verify": { "verify_after_reading": true, "strict_v1_validation": false },
            "builder": { "thumbnail": { "enabled": true } }
        }"#;
        assert!(Context::from_json(json).is_ok());
    }

    #[test]
    fn something_that_is_not_json_is_a_bad_param() {
        let err = Context::from_json("not json").expect_err("rejects");
        assert!(matches!(err, C2paError::BadParam(_)), "{err:?}");
    }

    #[test]
    fn from_settings_and_into_settings_round_trip() {
        let settings = ReadSettings {
            trust_anchors: vec![DER.to_vec()],
            ..ReadSettings::default()
        };
        let context = Context::from_settings(settings.clone());
        assert_eq!(
            context.into_settings().trust_anchors,
            settings.trust_anchors
        );
    }
}
