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

//! The browser end of this crate: [`Blob`] for `web_sys::Blob`, a
//! [`Platform`] that reads the JavaScript clock, and a
//! `#[wasm_bindgen]`-exported [`WasmReader`] whose JavaScript surface is
//! c2pa-wasm's own.
//!
//! Only compiled under the `web` feature, and only for
//! `wasm32-unknown-unknown`: this is the one module in this workspace that
//! names a wasm-bindgen type, and nothing below this crate ever does.
//!
//! # What this demonstrates
//!
//! c2pa-wasm's `BlobStream` turns a `Blob` into the synchronous
//! `Read + Seek` stream c2pa-rs demands, using `FileReaderSync` — which
//! only exists inside a Web Worker, so c2pa-web's whole reader runs in
//! one. The [`Blob`] implementation here answers each read with
//! `Blob.slice(start, end).arrayBuffer()` instead: a `Promise`, available
//! on the main thread and in a Worker alike, awaited from inside
//! [`crate::read_manifest`]'s loop. Every read of a large asset's hash
//! range is therefore a genuine yield to the event loop, rather than a
//! synchronous stall of the thread — the cooperative behavior the
//! sans-I/O engine makes possible and c2pa-rs's stream contract does not.
//!
//! Nothing in this module can run under `cargo test`, which has no
//! browser; it is held to `cargo check --target wasm32-unknown-unknown`
//! (which CI runs with `--all-features`) and to the shape of the code it
//! delegates to, all of which *is* tested natively.

use contentauth_c2pa_primitives::{ByteRange, HostError};
use js_sys::{JsString, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{blob::Blob, error::Error, platform::Platform, reader::Reader};

/// A JavaScript `Blob`, read through `Blob.slice(start, end).arrayBuffer()`.
impl Blob for web_sys::Blob {
    fn size(&self) -> u64 {
        // `Blob.size` is a JavaScript number: exact for any real asset
        // (2^53 bytes is eight petabytes), so the cast loses nothing.
        web_sys::Blob::size(self) as u64
    }

    async fn bytes(&self, range: ByteRange) -> Result<Vec<u8>, HostError> {
        let end = range
            .start
            .checked_add(range.len)
            .ok_or_else(|| HostError::new("byte range overflows"))?;

        let slice = self
            .slice_with_f64_and_f64(range.start as f64, end as f64)
            .map_err(|err| HostError::new(format!("Blob.slice failed: {}", describe(&err))))?;

        let buffer = JsFuture::from(slice.array_buffer()).await.map_err(|err| {
            HostError::new(format!("Blob.arrayBuffer failed: {}", describe(&err)))
        })?;

        // A slice past the end of a `Blob` is clamped rather than rejected
        // by JavaScript, so this can come back short; `read_manifest`
        // checks the length of every read regardless.
        Ok(Uint8Array::new(&buffer).to_vec())
    }
}

/// A [`Platform`] for the browser: `Date.now()` for the clock, and no OCSP.
///
/// OCSP is declined rather than attempted because a browser `fetch` of an
/// arbitrary responder URL — one embedded in the asset being read — is
/// both an SSRF surface this crate does not want to own by default and,
/// for most responders, blocked by CORS anyway. Declining is fail-open
/// (see [`Platform::ocsp`]), so a manifest reads exactly as it would with
/// online checking off, which is c2pa-rs's own default. A host that wants
/// live checks implements [`Platform`] over `fetch` itself and passes it
/// to [`Reader::from_blob`].
#[derive(Clone, Copy, Debug, Default)]
pub struct WebPlatform;

impl Platform for WebPlatform {
    async fn current_date_time(&self) -> Result<i64, HostError> {
        let millis = js_sys::Date::now();
        if !millis.is_finite() {
            return Err(HostError::new("Date.now() is not a finite number"));
        }
        // `Date.now()` is milliseconds since the epoch as an f64; whole
        // seconds fit an i64 with room to spare, and `as` saturates
        // rather than wraps for the values that would not.
        Ok((millis / 1000.0).floor() as i64)
    }

    async fn ocsp(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new("WebPlatform does not make OCSP requests"))
    }
}

/// The string [`Error`] crosses into JavaScript as — c2pa-wasm's own
/// `From<WasmError> for JsString`, which is the contract c2pa-web's
/// `reader.ts` matches `C2pa(JumbfNotFound)` against.
impl From<Error> for JsString {
    fn from(err: Error) -> Self {
        JsString::from(err.js_message())
    }
}

/// c2pa-wasm's `WasmReader`, exported to JavaScript under the same name
/// and the same method names.
///
/// A thin binding over [`Reader`]: `fromBlob` awaits
/// [`Reader::from_blob`] over the `web_sys::Blob` it is given and
/// [`WebPlatform`], and the accessors serialize [`Reader`]'s answers with
/// the same `serde_wasm_bindgen` configuration c2pa-wasm uses (maps as
/// objects, so `manifests` is a plain object keyed by label rather than a
/// `Map`).
///
/// Errors cross as strings, not `JsError`s, for the same reason c2pa-wasm
/// gives: wasm-bindgen mishandles `JsError` in a Firefox worker
/// (wasm-bindgen issue 4961).
#[wasm_bindgen]
pub struct WasmReader {
    inner: Reader,
    serializer: Serializer,
}

#[wasm_bindgen]
impl WasmReader {
    /// Attempts to create a new `WasmReader` from an asset format and a
    /// `Blob` of the asset's bytes, optionally with a context JSON string
    /// configuring the read — c2pa-wasm's `fromBlob`.
    #[wasm_bindgen(js_name = fromBlob)]
    pub async fn from_blob(
        format: &str,
        blob: &web_sys::Blob,
        context_json: Option<String>,
    ) -> Result<WasmReader, JsString> {
        let inner = Reader::from_blob(format, blob, context_json.as_deref(), &WebPlatform).await?;

        Ok(Self {
            inner,
            serializer: Serializer::new().serialize_maps_as_objects(true),
        })
    }

    /// Returns the label of the asset's active manifest.
    #[wasm_bindgen(js_name = activeLabel)]
    pub fn active_label(&self) -> Option<String> {
        self.inner.active_label()
    }

    /// Returns the asset's manifest store.
    #[wasm_bindgen(js_name = manifestStore)]
    pub fn manifest_store(&self) -> Result<JsValue, JsString> {
        self.inner
            .manifest_store()
            .serialize(&self.serializer)
            .map_err(serde_error)
    }

    /// Returns the asset's active manifest.
    #[wasm_bindgen(js_name = activeManifest)]
    pub fn active_manifest(&self) -> Result<JsValue, JsString> {
        self.inner
            .active_manifest()
            .serialize(&self.serializer)
            .map_err(serde_error)
    }

    /// Returns a JSON representation of the asset's manifest store.
    #[wasm_bindgen]
    pub fn json(&self) -> String {
        self.inner.json()
    }
}

/// c2pa-wasm's `WasmError::Serde` case, as the same kind of string.
fn serde_error(err: serde_wasm_bindgen::Error) -> JsString {
    JsString::from(format!("Serde({err:?})"))
}

/// A best-effort rendering of a JavaScript exception value.
fn describe(err: &JsValue) -> String {
    err.as_string().unwrap_or_else(|| format!("{err:?}"))
}
