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
use contentauth_c2pa_file_builder::TimestampSettings;
use contentauth_c2pa_js_compat::{for_format, Blob};
use contentauth_c2pa_sign_baseline::Definition;

use crate::{drive::build, error::Error, signer::AsyncSigner};

/// A signed asset and the manifest store inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SignedAsset {
    /// The complete signed asset.
    pub asset: Vec<u8>,

    /// The manifest store alone, as embedded in `asset`.
    pub manifest: Vec<u8>,
}

/// Builds and signs a manifest per a JSON definition.
#[derive(Clone, Debug)]
pub struct Builder {
    definition: Definition,
}

impl Builder {
    /// Parses a manifest definition. See [`Definition`] for the supported
    /// subset of c2pa-rs's JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        Ok(Self {
            definition: Definition::from_json(json)?,
        })
    }

    /// Signs `source` (of MIME type or extension `format`), awaiting
    /// `source` for its bytes and `signer` for the signature.
    ///
    /// The returned future suspends exactly when `source` or `signer` does,
    /// and never otherwise: between two awaits the engine runs
    /// synchronously. Dropping it abandons the build; nothing has been
    /// published anywhere.
    pub async fn sign<B, S>(
        &self,
        signer: &S,
        format: &str,
        source: &B,
    ) -> Result<SignedAsset, Error>
    where
        B: Blob + ?Sized,
        S: AsyncSigner + ?Sized,
    {
        let handler = for_format(format).map_err(|_| Error::UnsupportedType)?;
        let tsa_url = self
            .definition
            .tsa_url
            .clone()
            .or_else(|| signer.time_authority_url());
        let mut settings =
            self.definition
                .clone()
                .into_settings("image/jpeg", signer.alg(), signer.certs())?;
        if tsa_url.is_some() && settings.timestamp.is_none() {
            settings.timestamp = Some(TimestampSettings::default());
        }
        build(handler, source, signer, settings, tsa_url.as_deref()).await
    }
}
