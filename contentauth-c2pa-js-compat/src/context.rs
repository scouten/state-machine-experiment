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
//!     "anchors": [
//!       { "trust_anchors": "-----BEGIN CERTIFICATE-----\n...", "trust_kind": "manifest" },
//!       { "trust_anchors": "-----BEGIN CERTIFICATE-----\n...", "trust_kind": "tsa" }
//!     ]
//!   },
//!   "verify": {
//!     "ocsp_fetch": false
//!   }
//! }
//! ```
//!
//! `trust.anchors` is the shape c2pa-rs 0.91 introduced: a list of trust
//! lists, each a PEM bundle tagged with a `trust_kind` of `manifest`
//! (signing certificates), `tsa` (timestamp authorities) or `cawg`.
//! They are decoded to DER and routed by kind — `manifest` into
//! [`ReadSettings::trust_anchors`], `tsa` into
//! [`ReadSettings::timestamp_trust_anchors`], as c2pa-rs keeps those two
//! trust stores separate. A list that carries a `trust_uri` instead
//! becomes a named [`TrustList`] ([`ReadSettings::trust_lists`] /
//! [`ReadSettings::timestamp_trust_lists`]), so the URI is reported as
//! `trust_list_uri` on the trusted statuses, as c2pa-rs does. `cawg`
//! lists are accepted and ignored, there being no CAWG identity
//! validation in this workspace. The other per-list fields
//! (`trust_config`, `allowed_list`, `trusted_ica_issuers`) are likewise
//! accepted and ignored.
//!
//! The older `trust.trust_anchors` and `trust.user_anchors` strings, which
//! c2pa-rs 0.91 deprecated (and plans to remove in 0.92), are still
//! understood, exactly as c2pa-rs still does: it folds each into
//! `anchors` as a `manifest` list, so they feed
//! [`ReadSettings::trust_anchors`] only. `ocsp_fetch` maps to
//! [`ReadSettings::check_ocsp`], and — this being a compatibility layer —
//! takes c2pa-rs's own default of `false` when absent, not this
//! workspace's engine default of `true`: the same `contextJson` (or none
//! at all) must mean the same thing here as it does to c2pa-wasm, and an
//! online [`Platform`](crate::Platform) must not start making
//! certificate-directed network requests a caller never opted into. A
//! caller who wants the engine's own default reaches it explicitly, with
//! `"ocsp_fetch": true` or [`Context::from_settings`].
//!
//! Any other key is ignored, so a full c2pa-rs settings document loads
//! without complaint — the alternative, rejecting a setting this crate has
//! no counterpart for, would make the same client code fail here and
//! succeed against c2pa-wasm, which is the opposite of what a
//! compatibility layer is for. A key this crate *does* recognize but
//! cannot parse (a malformed certificate, a non-boolean `ocsp_fetch`) is a
//! [`C2paError::BadParam`], as it would be in c2pa-rs.
//!
//! One key deserves a specific warning rather than silence:
//! `verify.remote_manifest_fetch`. c2pa-rs defaults it to `true` and
//! follows an asset's reference to a remotely hosted manifest store when
//! it is set. Nothing in this workspace's engine can do that yet — its
//! request vocabulary has no remote-manifest request at all, and
//! [`ReadSettings::fetch_remote_manifests`] is documented as aspirational
//! — so the key is deliberately *not* mapped onto that field, and an
//! asset whose only manifest is remote reads as
//! [`C2paError::JumbfNotFound`] here whatever the setting says. Rejecting
//! the key would refuse every stock c2pa-rs settings document, since
//! `true` is the default; ignoring it is the honest option until the
//! engine grows the request.

use base64::Engine as _;
use contentauth_c2pa_file_reader::{ReadSettings, TrustList};
use serde::Deserialize;

use crate::error::C2paError;

/// The settings a [`crate::Reader`] reads under.
///
/// Built from c2pa-wasm's `contextJson` by [`Self::from_json`], or
/// directly from a [`ReadSettings`] by [`Self::from_settings`] for a
/// caller that would rather not go through JSON at all.
#[derive(Clone, Debug)]
pub struct Context {
    settings: ReadSettings,
}

/// The settings an absent `contextJson` means: what c2pa-wasm reads under
/// when handed none, which is c2pa-rs's defaults — no trust anchors, and
/// no online OCSP. Identical to [`Context::from_json`]`("{}")`.
impl Default for Context {
    fn default() -> Self {
        Self {
            settings: ReadSettings {
                check_ocsp: false,
                ..ReadSettings::default()
            },
        }
    }
}

impl Context {
    /// Parses c2pa-rs settings JSON, as described in the module docs.
    pub fn from_json(json: &str) -> Result<Self, C2paError> {
        let doc: SettingsJson = serde_json::from_str(json)
            .map_err(|err| C2paError::BadParam(format!("settings JSON: {err}")))?;

        let mut signing_anchors = Vec::new();
        let mut timestamp_anchors = Vec::new();
        let mut signing_lists = Vec::new();
        let mut timestamp_lists = Vec::new();

        let bad =
            |key: &str, err: String| C2paError::BadParam(format!("settings JSON: {key}: {err}"));

        for (key, pem) in [
            ("trust.trust_anchors", doc.trust.trust_anchors),
            ("trust.user_anchors", doc.trust.user_anchors),
        ] {
            if let Some(pem) = pem {
                signing_anchors.extend(pem_certificates(&pem).map_err(|err| bad(key, err))?);
            }
        }

        for (index, list) in doc.trust.anchors.into_iter().flatten().enumerate() {
            let key = format!("trust.anchors[{index}].trust_anchors");
            let certificates =
                pem_certificates(&list.trust_anchors).map_err(|err| bad(&key, err))?;
            let (anonymous, named) = match list.trust_kind {
                TrustListKind::Manifest => (&mut signing_anchors, &mut signing_lists),
                TrustListKind::Tsa => (&mut timestamp_anchors, &mut timestamp_lists),
                TrustListKind::Cawg => continue,
            };
            match list.trust_uri {
                Some(uri) => named.push(TrustList {
                    uri,
                    anchors: certificates,
                }),
                None => anonymous.extend(certificates),
            }
        }

        // Every field is named here on purpose: a setting the engine grows
        // is one this parser should be made to decide about, not one that
        // silently keeps its default. `fetch_remote_manifests` is decided
        // *not* to follow `verify.remote_manifest_fetch` — see the module
        // docs — and stays at the engine's default until the engine can
        // actually act on it.
        let defaults = Self::default().settings;
        let settings = ReadSettings {
            trust_anchors: signing_anchors,
            timestamp_trust_anchors: timestamp_anchors,
            trust_lists: signing_lists,
            timestamp_trust_lists: timestamp_lists,
            check_ocsp: doc.verify.ocsp_fetch.unwrap_or(defaults.check_ocsp),
            fetch_remote_manifests: defaults.fetch_remote_manifests,
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
    anchors: Option<Vec<TrustAnchorJson>>,
    trust_anchors: Option<String>,
    user_anchors: Option<String>,
}

/// One entry of `trust.anchors`. `trust_kind` is required, as in c2pa-rs.
#[derive(Deserialize)]
struct TrustAnchorJson {
    trust_anchors: String,
    trust_kind: TrustListKind,
    trust_uri: Option<String>,
}

/// c2pa-rs's `TrustListKind`, serialized lowercase.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum TrustListKind {
    Manifest,
    Tsa,
    Cawg,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct VerifyJson {
    ocsp_fetch: Option<bool>,
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

    /// No `contextJson` at all means c2pa-rs's defaults — in particular
    /// no online OCSP, whatever this workspace's engine defaults to.
    #[test]
    fn a_context_from_no_json_at_all_has_c2pa_rs_defaults() {
        let context = Context::default();
        assert!(context.settings().trust_anchors.is_empty());
        assert!(context.settings().timestamp_trust_anchors.is_empty());
        assert!(!context.settings().check_ocsp);
    }

    /// The engine's own default is deliberately *not* what an absent
    /// setting means here; this pins that the two differ, so a change to
    /// the engine's default cannot make this test pass by accident.
    #[test]
    fn the_engines_own_ocsp_default_is_not_the_compat_default() {
        assert!(ReadSettings::default().check_ocsp);
        assert!(!Context::default().settings().check_ocsp);
    }

    #[test]
    fn an_empty_document_means_the_same_as_no_document() {
        let context = Context::from_json("{}").expect("parses");
        assert!(context.settings().trust_anchors.is_empty());
        assert!(context.settings().timestamp_trust_anchors.is_empty());
        assert!(!context.settings().check_ocsp);
        assert_eq!(
            context.settings().fetch_remote_manifests,
            Context::default().settings().fetch_remote_manifests
        );
    }

    /// The deprecated string fields are folded into c2pa-rs's `manifest`
    /// list, so they reach signing trust only.
    #[test]
    fn legacy_trust_anchors_and_user_anchors_feed_signing_trust_only() {
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
        assert!(context.settings().timestamp_trust_anchors.is_empty());
    }

    #[test]
    fn anchors_are_routed_by_trust_kind() {
        let tsa = [0x30u8, 0x03, 0x02, 0x01, 0x02];
        let cawg = [0x30u8, 0x03, 0x02, 0x01, 0x03];
        let json = serde_json::json!({
            "trust": {
                "anchors": [
                    { "trust_anchors": pem_of(DER), "trust_kind": "manifest" },
                    { "trust_anchors": pem_of(&tsa), "trust_kind": "tsa" },
                    { "trust_anchors": pem_of(&cawg), "trust_kind": "cawg",
                      "trusted_ica_issuers": ["did:web:example.com"] },
                ]
            }
        })
        .to_string();

        let context = Context::from_json(&json).expect("parses");
        assert_eq!(context.settings().trust_anchors, vec![DER.to_vec()]);
        assert_eq!(
            context.settings().timestamp_trust_anchors,
            vec![tsa.to_vec()]
        );
    }

    #[test]
    fn a_list_with_a_trust_uri_becomes_a_named_trust_list() {
        let tsa = [0x30u8, 0x03, 0x02, 0x01, 0x02];
        let json = serde_json::json!({
            "trust": {
                "anchors": [
                    { "trust_anchors": pem_of(DER), "trust_kind": "manifest",
                      "trust_uri": "https://example.com/signers" },
                    { "trust_anchors": pem_of(&tsa), "trust_kind": "tsa",
                      "trust_uri": "https://example.com/tsa" },
                ]
            }
        })
        .to_string();

        let context = Context::from_json(&json).expect("parses");
        let settings = context.settings();
        assert!(settings.trust_anchors.is_empty());
        assert!(settings.timestamp_trust_anchors.is_empty());
        assert_eq!(
            settings.trust_lists,
            vec![TrustList {
                uri: "https://example.com/signers".to_string(),
                anchors: vec![DER.to_vec()],
            }]
        );
        assert_eq!(
            settings.timestamp_trust_lists,
            vec![TrustList {
                uri: "https://example.com/tsa".to_string(),
                anchors: vec![tsa.to_vec()],
            }]
        );
    }

    #[test]
    fn an_anchor_list_without_a_trust_kind_or_with_an_unknown_one_is_a_bad_param() {
        for anchor in [
            serde_json::json!({ "trust_anchors": pem_of(DER) }),
            serde_json::json!({ "trust_anchors": pem_of(DER), "trust_kind": "bogus" }),
            serde_json::json!({ "trust_anchors": "not a certificate", "trust_kind": "manifest" }),
        ] {
            let json = serde_json::json!({ "trust": { "anchors": [anchor] } }).to_string();
            let err = Context::from_json(&json).expect_err("rejects");
            assert!(matches!(err, C2paError::BadParam(_)), "{err:?}");
        }
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
    fn ocsp_fetch_is_honored_in_both_directions() {
        let context =
            Context::from_json(r#"{ "verify": { "ocsp_fetch": false } }"#).expect("parses");
        assert!(!context.settings().check_ocsp);

        let context =
            Context::from_json(r#"{ "verify": { "ocsp_fetch": true } }"#).expect("parses");
        assert!(context.settings().check_ocsp);
    }

    /// `remote_manifest_fetch` is accepted (c2pa-rs defaults it to `true`,
    /// so a stock settings document carries it) but never reaches the
    /// engine, which cannot act on it — see the module docs.
    #[test]
    fn remote_manifest_fetch_is_accepted_but_does_not_reach_the_engine() {
        for value in ["true", "false"] {
            let json = format!(r#"{{ "verify": {{ "remote_manifest_fetch": {value} }} }}"#);
            let context = Context::from_json(&json).expect("parses");
            assert_eq!(
                context.settings().fetch_remote_manifests,
                Context::default().settings().fetch_remote_manifests,
                "{json}"
            );
        }
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
