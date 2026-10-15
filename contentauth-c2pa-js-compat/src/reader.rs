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

//! [`Reader`]: the compatibility surface itself.

use contentauth_c2pa_reader::ReadReport;

use crate::{
    blob::Blob,
    context::Context,
    error::{C2paError, Error},
    format,
    manifest_store::{Manifest, ManifestStore},
    platform::Platform,
};

/// Reads and validates a C2PA manifest store from a [`Blob`].
///
/// The counterpart of c2pa-wasm's `WasmReader`, method for method:
/// [`Self::from_blob`] is its `fromBlob`, the rest its `activeLabel`,
/// `manifestStore`, `activeManifest`, and `json`. Like `WasmReader`, this
/// type is a snapshot: everything is read and validated in `from_blob`,
/// and the accessors merely report on the result — none of them awaits.
///
/// Backed by [`crate::read_manifest`], the async host that drives a
/// [`FileReadSession`](contentauth_c2pa_file_reader::FileReadSession)
/// with `.await`s at every request. The engine underneath is exactly the
/// one `contentauth-c2pa-rs-compat` drives synchronously; the difference
/// is entirely in this layer.
///
/// # Example
///
/// ```no_run
/// use contentauth_c2pa_js_compat::{OfflinePlatform, Reader};
///
/// # async fn example(jpeg: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
/// let reader = Reader::from_blob("image/jpeg", &jpeg, None, &OfflinePlatform).await?;
/// println!("{}", reader.json()?);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Reader {
    report: ReadReport,
}

impl Reader {
    /// The `format` strings this build can locate a manifest store within:
    /// a MIME type or a bare extension, matched without regard to case.
    ///
    /// c2pa-web gates `fromBlob` behind its own `isSupportedReaderFormat`
    /// list; this is the equivalent for this build.
    pub fn supported_formats() -> &'static [&'static str] {
        format::FORMATS
    }

    /// Locates, reads, and validates the manifest store embedded in
    /// `blob` — c2pa-wasm's `fromBlob(format, blob, contextJson)`, plus the
    /// one argument a sans-I/O engine needs that c2pa-rs gets from its
    /// platform implicitly (see [`Platform`]).
    ///
    /// `format` is the asset's MIME type or file extension; see
    /// [`Self::supported_formats`]. `context_json` is c2pa-rs settings JSON
    /// (see [`Context::from_json`] for the slice recognized); `None` reads
    /// with default settings, exactly as passing no `contextJson` does in
    /// c2pa-wasm. A caller with a [`Context`] already in hand — or with
    /// settings in this workspace's own vocabulary — uses
    /// [`Self::from_blob_with_context`] instead.
    ///
    /// Fails with [`C2paError::JumbfNotFound`] if the asset carries no
    /// manifest store, as c2pa-rs's `Reader` does; c2pa-web turns exactly
    /// that failure into a `null` reader (see [`Error::js_message`]). Fails
    /// with [`C2paError::UnsupportedType`] for a `format` no handler in
    /// this build recognizes, and [`C2paError::BadParam`] for
    /// `context_json` that cannot be understood.
    /// A missing or unsupported active claim hash algorithm is
    /// [`C2paError::UnknownAlgorithm`], matching c2pa-js rather than the
    /// underlying engine's SHA-256 default.
    ///
    /// The returned future suspends whenever `blob` or `platform` does —
    /// see [`crate::read_manifest`] for exactly when that is.
    pub async fn from_blob<B, P>(
        format: &str,
        blob: &B,
        context_json: Option<&str>,
        platform: &P,
    ) -> Result<Self, Error>
    where
        B: Blob + ?Sized,
        P: Platform + ?Sized,
    {
        let context = match context_json {
            Some(json) => Context::from_json(json)?,
            None => Context::default(),
        };
        Self::from_blob_with_context(format, blob, context, platform).await
    }

    /// As [`Self::from_blob`], with the settings already parsed (or built
    /// directly) into a [`Context`].
    pub async fn from_blob_with_context<B, P>(
        format: &str,
        blob: &B,
        context: Context,
        platform: &P,
    ) -> Result<Self, Error>
    where
        B: Blob + ?Sized,
        P: Platform + ?Sized,
    {
        Self::from_blob_with_context_and_detached_manifest(format, blob, context, None, platform)
            .await
    }

    /// As [`Self::from_blob`], using caller-supplied detached manifest-store
    /// bytes instead of locating a store in the asset.
    ///
    /// The asset is still read and validated against the supplied store. An
    /// invalid or unrelated store fails through the same reader validation
    /// path as an embedded store.
    pub async fn from_blob_with_detached_manifest<B, P>(
        format: &str,
        blob: &B,
        context_json: Option<&str>,
        manifest_store: Vec<u8>,
        platform: &P,
    ) -> Result<Self, Error>
    where
        B: Blob + ?Sized,
        P: Platform + ?Sized,
    {
        let context = match context_json {
            Some(json) => Context::from_json(json)?,
            None => Context::default(),
        };
        Self::from_blob_with_context_and_detached_manifest(
            format,
            blob,
            context,
            Some(manifest_store),
            platform,
        )
        .await
    }

    async fn from_blob_with_context_and_detached_manifest<B, P>(
        format: &str,
        blob: &B,
        context: Context,
        detached_manifest: Option<Vec<u8>>,
        platform: &P,
    ) -> Result<Self, Error>
    where
        B: Blob + ?Sized,
        P: Platform + ?Sized,
    {
        let handler = format::for_format(format)?;

        let report = crate::drive::read_manifest_with_detached_manifest(
            &handler,
            blob,
            platform,
            context.into_settings(),
            detached_manifest,
        )
        .await
        .map_err(C2paError::from)?;

        if !report.manifest_store_found {
            return Err(C2paError::JumbfNotFound.into());
        }

        if let Some(active) = report
            .manifests
            .iter()
            .find(|manifest| Some(&manifest.label) == report.active_manifest.as_ref())
        {
            // c2pa-js requires an explicit claim algorithm; the core engine
            // instead supports the specification's SHA-256 default.
            if active
                .claim
                .alg
                .as_deref()
                .and_then(contentauth_c2pa_reader::HashAlgorithm::from_c2pa_name)
                .is_none()
            {
                return Err(C2paError::UnknownAlgorithm.into());
            }
        }

        Ok(Self { report })
    }

    /// The active manifest's label, if the store contains any manifest —
    /// c2pa-wasm's `activeLabel()`.
    pub fn active_label(&self) -> Option<String> {
        self.report.active_manifest.clone()
    }

    /// The whole manifest store — c2pa-wasm's `manifestStore()`.
    ///
    /// Infallible where c2pa-wasm's is not: the only way its
    /// `manifestStore()` can fail is in converting the result to a
    /// JavaScript value, which is the binding's job here (see the `web`
    /// feature's `WasmReader`), not this type's.
    pub fn manifest_store(&self) -> ManifestStore {
        ManifestStore::from_report(&self.report)
    }

    /// The active manifest — the last one in the store — if the store
    /// contains any; c2pa-wasm's `activeManifest()`.
    ///
    /// Reads position directly rather than resolving
    /// [`Self::active_label`] through a lookup: the parser does not enforce
    /// unique labels, so a store with a duplicate would make a first-match
    /// search return an earlier manifest than the last (active) one the
    /// label is documented to mean.
    pub fn active_manifest(&self) -> Option<Manifest> {
        self.report.manifests.last().map(Manifest::from_inner)
    }

    /// Copies an embedded resource identified by its absolute self JUMBF URI.
    ///
    /// Unknown or ambiguous identifiers fail rather than selecting a resource
    /// by basename or fetching an external URL.
    pub fn resource_to_bytes(&self, uri: &str) -> Result<Vec<u8>, Error> {
        crate::resource_bytes(&self.report, uri).map(<[u8]>::to_vec)
    }

    /// The manifest store as a pretty-printed JSON string — c2pa-wasm's
    /// `json()`, which is c2pa-rs's `Reader::json`.
    ///
    /// Numeric-array object fields use the pinned SDK's base64 display format.
    /// Object accessors retain arrays. Serialization errors propagate rather
    /// than returning an empty success-shaped report.
    pub fn json(&self) -> Result<String, serde_json::Error> {
        self.manifest_store().json()
    }
}
