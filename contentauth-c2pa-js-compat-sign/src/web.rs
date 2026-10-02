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
//! The browser end of this crate: a `#[wasm_bindgen]`-exported
//! `WasmBuilder` whose signer is a plain JavaScript object.
//!
//! ```js
//! const builder = WasmBuilder.fromJson(definitionJson);
//! const { asset, manifest } = await builder.sign(
//!   {
//!     alg: "es256",
//!     certs: [certDerUint8Array],            // signer first
//!     sign: async (data) => new Uint8Array(  // data: Uint8Array
//!       await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data)),
//!   },
//!   "image/jpeg",
//!   blob,
//! );
//! ```
//!
//! WebCrypto's ECDSA output is already the fixed-width `r || s` COSE
//! wants, so a non-extractable `CryptoKey` works as-is: the key never
//! enters Wasm memory. Only compiled under the `web` feature for
//! `wasm32-unknown-unknown`; nothing here runs under `cargo test` (there
//! is no browser), and the logic it delegates to is all tested natively.

use contentauth_c2pa_primitives::{HostError, SigningAlg};
use js_sys::{Array, Function, JsString, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{builder::Builder, error::Error, signer::AsyncSigner};

impl From<Error> for JsString {
    fn from(err: Error) -> Self {
        JsString::from(err.js_message())
    }
}

/// A JavaScript signer object, read once into Rust-side fields.
struct JsSigner {
    alg: SigningAlg,
    certs: Vec<Vec<u8>>,
    sign: Function,
    this: JsValue,
}

impl JsSigner {
    fn from_js(signer: &JsValue) -> Result<Self, JsString> {
        let field = |name: &str| {
            Reflect::get(signer, &JsValue::from_str(name))
                .map_err(|_| JsString::from(format!("signer.{name} is not readable")))
        };

        let alg = field("alg")?
            .as_string()
            .and_then(|name| parse_alg(&name))
            .ok_or_else(|| JsString::from("signer.alg must be a supported algorithm name"))?;

        let certs = field("certs")?;
        if !Array::is_array(&certs) {
            return Err(JsString::from(
                "signer.certs must be an array of Uint8Array, signer's certificate first",
            ));
        }
        let certs = Array::from(&certs)
            .iter()
            .enumerate()
            .map(|(index, cert)| match cert.dyn_into::<Uint8Array>() {
                Ok(cert) if cert.length() > 0 => Ok(cert.to_vec()),
                _ => Err(JsString::from(format!(
                    "signer.certs[{index}] must be a non-empty Uint8Array"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(JsString::from("signer.certs must not be empty"));
        }

        let sign = field("sign")?
            .dyn_into::<Function>()
            .map_err(|_| JsString::from("signer.sign must be a function"))?;

        Ok(Self {
            alg,
            certs,
            sign,
            this: signer.clone(),
        })
    }
}

impl AsyncSigner for JsSigner {
    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Vec<Vec<u8>> {
        self.certs.clone()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError> {
        let returned = self
            .sign
            .call1(&self.this, &Uint8Array::from(data))
            .map_err(|err| HostError::new(format!("signer.sign threw: {}", describe(&err))))?;

        // `sign` may be async or return a plain value; `Promise.resolve`
        // accepts both.
        let signature = JsFuture::from(Promise::resolve(&returned))
            .await
            .map_err(|err| HostError::new(format!("signer.sign rejected: {}", describe(&err))))?;

        Ok(Uint8Array::new(&signature).to_vec())
    }
}

/// The lowercase algorithm names JavaScript callers use.
fn parse_alg(name: &str) -> Option<SigningAlg> {
    Some(match name.to_ascii_lowercase().as_str() {
        "es256" => SigningAlg::Es256,
        "es384" => SigningAlg::Es384,
        "es512" => SigningAlg::Es512,
        "ps256" => SigningAlg::Ps256,
        "ps384" => SigningAlg::Ps384,
        "ps512" => SigningAlg::Ps512,
        "ed25519" => SigningAlg::Ed25519,
        _ => return None,
    })
}

/// The builder, exported to JavaScript. Errors cross as strings, for the
/// same reason `contentauth-c2pa-js-compat`'s `WasmReader` gives.
#[wasm_bindgen]
pub struct WasmBuilder {
    inner: Builder,
}

#[wasm_bindgen]
impl WasmBuilder {
    /// Parses a manifest definition.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<WasmBuilder, JsString> {
        Ok(Self {
            inner: Builder::from_json(json)?,
        })
    }

    /// Signs `blob` (of `format`) with `signer`, resolving to
    /// `{ asset: Uint8Array, manifest: Uint8Array }`.
    pub async fn sign(
        &self,
        signer: JsValue,
        format: &str,
        blob: &web_sys::Blob,
    ) -> Result<JsValue, JsString> {
        let signer = JsSigner::from_js(&signer)?;
        let signed = self.inner.sign(&signer, format, blob).await?;

        let out = Object::new();
        for (name, bytes) in [("asset", &signed.asset), ("manifest", &signed.manifest)] {
            Reflect::set(
                &out,
                &JsValue::from_str(name),
                &Uint8Array::from(&bytes[..]),
            )
            .map_err(|_| JsString::from("could not build the result object"))?;
        }
        Ok(out.into())
    }
}

/// A best-effort rendering of a JavaScript exception value.
fn describe(err: &JsValue) -> String {
    err.as_string().unwrap_or_else(|| format!("{err:?}"))
}
