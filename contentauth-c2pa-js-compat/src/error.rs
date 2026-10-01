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

//! Errors from [`crate::Reader`], shaped to reproduce c2pa-wasm's
//! error-string contract.
//!
//! c2pa-wasm cannot hand JavaScript a Rust error; what crosses the
//! boundary is a string, produced by `format!("{err:?}")` on its own
//! `WasmError` — an enum whose `C2pa` variant wraps c2pa-rs's `Error`. The
//! `Debug` output of that nesting is what c2pa-web's `reader.ts` actually
//! matches on: a `fromBlob` that rejects with exactly `C2pa(JumbfNotFound)`
//! becomes a `null` reader rather than a thrown error.
//!
//! Hence two levels here: [`Error`] stands in for `WasmError`, and
//! [`C2paError`] for the slice of c2pa-rs's `Error` this crate's use case
//! reaches, with the same variant names — so the derived `Debug` output,
//! and with it [`Error::js_message`], comes out the same.

/// Errors surfaced by [`crate::Reader`]; the counterpart of c2pa-wasm's
/// `WasmError`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An error from the read itself — the counterpart of `WasmError::C2pa`.
    #[error(transparent)]
    C2pa(#[from] C2paError),
}

impl Error {
    /// The string this error crosses into JavaScript as: `format!("{self:?}")`,
    /// exactly as c2pa-wasm's `From<WasmError> for JsString` produces it.
    ///
    /// Notably `"C2pa(JumbfNotFound)"` for a [`C2paError::JumbfNotFound`],
    /// which is the one string c2pa-web's `reader.ts` matches on.
    pub fn js_message(&self) -> String {
        format!("{self:?}")
    }
}

/// The slice of c2pa-rs's `Error` this crate's use case reaches, under the
/// same variant names.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum C2paError {
    /// No C2PA manifest store was found in the asset.
    ///
    /// c2pa-rs's `Error::JumbfNotFound`; the one error c2pa-web does not
    /// treat as an error — see the module docs.
    #[error("no JUMBF data found")]
    JumbfNotFound,

    /// `format` names a container format no `FormatHandler` in this build
    /// recognizes.
    ///
    /// c2pa-rs's `Error::UnsupportedType`, which it resolves from a registry
    /// of handlers keyed by MIME type; this crate has exactly one handler,
    /// so the check is a plain string match (see `src/format.rs`).
    #[error("type is unsupported")]
    UnsupportedType,

    /// `context_json` could not be understood as settings.
    ///
    /// c2pa-rs's `Error::BadParam`, which is what its `Settings` parser
    /// reports for JSON it cannot load.
    #[error("bad parameter: {0}")]
    BadParam(String),

    /// The read engine itself failed — a malformed manifest store,
    /// malformed container framing, or the host-protocol misuse this
    /// crate's own drive loop would be responsible for, not the caller.
    ///
    /// No single c2pa-rs counterpart: where c2pa-rs would report one of
    /// its many parse- and validation-time variants, this carries the
    /// engine's own typed error instead of flattening it into a string.
    #[error(transparent)]
    Read(#[from] contentauth_c2pa_file_reader::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumbf_not_found_crosses_into_js_as_the_string_c2pa_web_matches_on() {
        let err = Error::from(C2paError::JumbfNotFound);
        assert_eq!(err.js_message(), "C2pa(JumbfNotFound)");
    }

    #[test]
    fn other_errors_carry_their_detail_in_the_js_message() {
        let err = Error::from(C2paError::BadParam("nope".to_string()));
        assert_eq!(err.js_message(), "C2pa(BadParam(\"nope\"))");

        let err = Error::from(C2paError::UnsupportedType);
        assert_eq!(err.js_message(), "C2pa(UnsupportedType)");
    }

    #[test]
    fn display_follows_c2pa_rs_wording() {
        assert_eq!(
            Error::from(C2paError::JumbfNotFound).to_string(),
            "no JUMBF data found"
        );
        assert_eq!(
            Error::from(C2paError::UnsupportedType).to_string(),
            "type is unsupported"
        );
        assert_eq!(
            Error::from(C2paError::BadParam("x".to_string())).to_string(),
            "bad parameter: x"
        );
    }
}
