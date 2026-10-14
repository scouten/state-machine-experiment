use contentauth_c2pa_js_compat::web::WasmReader;
use contentauth_c2pa_js_compat_sign::web::WasmBuilder;
use js_sys::JsString;
use wasm_bindgen::prelude::*;

/// A browser-owned reader backed by the shared state-machine host.
#[wasm_bindgen]
pub struct BrowserReader {
    inner: WasmReader,
}

#[wasm_bindgen]
impl BrowserReader {
    /// Reads a Blob through the async host, optionally using a caller-owned
    /// policy-bounded remote manifest and OCSP callbacks.
    #[wasm_bindgen(js_name = fromBlob)]
    pub async fn from_blob(
        format: &str,
        blob: &web_sys::Blob,
        context: Option<String>,
        detached_manifest: Option<js_sys::Uint8Array>,
        remote_manifest: Option<js_sys::Function>,
        ocsp: Option<js_sys::Function>,
    ) -> Result<BrowserReader, JsString> {
        Ok(Self {
            inner: WasmReader::from_blob(
                format,
                blob,
                context,
                detached_manifest,
                remote_manifest,
                ocsp,
            )
            .await?,
        })
    }

    /// Returns the active manifest's label.
    #[wasm_bindgen(js_name = activeLabel)]
    pub fn active_label(&self) -> Option<String> {
        self.inner.active_label()
    }

    /// Returns the current, intentionally partial manifest projection.
    #[wasm_bindgen(js_name = manifestStore)]
    pub fn manifest_store(&self) -> Result<JsValue, JsString> {
        self.inner.manifest_store()
    }

    /// Returns the active manifest.
    #[wasm_bindgen(js_name = activeManifest)]
    pub fn active_manifest(&self) -> Result<JsValue, JsString> {
        self.inner.active_manifest()
    }

    /// Returns the current manifest projection as JSON.
    pub fn json(&self) -> String {
        self.inner.json()
    }
}

/// A browser-owned builder backed by the existing baseline signing host.
#[wasm_bindgen]
pub struct BrowserBuilder {
    inner: WasmBuilder,
}

#[wasm_bindgen]
impl BrowserBuilder {
    /// Parses the baseline definition without accepting unsupported fields.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(definition: &str) -> Result<BrowserBuilder, JsString> {
        Ok(Self {
            inner: WasmBuilder::from_json(definition)?,
        })
    }

    /// Signs a Blob with a JavaScript-owned signing capability.
    pub async fn sign(
        &self,
        signer: JsValue,
        format: &str,
        blob: &web_sys::Blob,
    ) -> Result<JsValue, JsString> {
        self.inner.sign(signer, format, blob).await
    }

    /// Signs a Blob into a detached manifest store, leaving the asset
    /// unchanged.
    #[wasm_bindgen(js_name = signDetached)]
    pub async fn sign_detached(
        &self,
        signer: JsValue,
        blob: &web_sys::Blob,
    ) -> Result<JsValue, JsString> {
        self.inner.sign_detached(signer, blob).await
    }
}
