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
use std::{
    io::{Read, Seek, Write},
    path::Path,
};

use contentauth_c2pa_file_builder::{
    build_and_sign, build_and_sign_file, FileBuilderReport, HashAlgorithm, HostError,
    TimestampSettings,
};
use contentauth_c2pa_format_jpeg::JpegFormat;
use contentauth_c2pa_primitives::tsa::{timestamp_request, timestamp_token};
use contentauth_c2pa_sign_baseline::Definition;

use crate::{error::Error, signer::Signer};

/// Builds and signs a manifest per a JSON definition, shaped after
/// c2pa-rs's `Builder`.
#[derive(Clone, Debug)]
pub struct Builder {
    definition: Definition,
}

const JPEG: &str = "image/jpeg";

impl Builder {
    /// Parses a manifest definition. See [`Definition`] for the supported
    /// subset of c2pa-rs's JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        Ok(Self {
            definition: Definition::from_json(json)?,
        })
    }

    /// Signs `source` (of MIME type `format`), writing the signed asset
    /// to `dest` and returning the manifest store's bytes, as c2pa-rs's
    /// `Builder::sign` does.
    ///
    /// Pass a `dest` that starts empty: this never truncates it (see
    /// [`contentauth_c2pa_file_builder::build_and_sign`]).
    pub fn sign<S, D>(
        &self,
        signer: &dyn Signer,
        format: &str,
        source: S,
        dest: D,
    ) -> Result<Vec<u8>, Error>
    where
        S: Read + Seek,
        D: Read + Write + Seek,
    {
        let (settings, tsa_url) = self.settings(signer, format)?;
        let report = build_and_sign(
            JpegFormat,
            source,
            dest,
            settings,
            |_, data| signer.sign(data),
            Some(&mut |alg, digest| timestamp(signer, tsa_url.as_deref(), alg, digest)),
            None,
        )?;
        Ok(report.manifest)
    }

    /// Signs the file at `source`, publishing the result at `dest`
    /// atomically (a failed build leaves `dest` untouched), and returns
    /// the manifest store's bytes. The format comes from `source`'s
    /// extension.
    pub fn sign_file(
        &self,
        signer: &dyn Signer,
        source: impl AsRef<Path>,
        dest: impl AsRef<Path>,
    ) -> Result<Vec<u8>, Error> {
        let source = source.as_ref();
        let is_jpeg = source
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg"));
        if !is_jpeg {
            return Err(Error::UnsupportedPath {
                path: source.to_path_buf(),
            });
        }

        let (settings, tsa_url) = self.settings(signer, JPEG)?;
        let FileBuilderReport { manifest, .. } = build_and_sign_file(
            JpegFormat,
            source,
            dest,
            settings,
            |_, data| signer.sign(data),
            Some(&mut |alg, digest| timestamp(signer, tsa_url.as_deref(), alg, digest)),
            None,
        )?;
        Ok(manifest)
    }

    /// The engine's settings, and the time-stamp authority's URL if the
    /// definition or the signer names one (the definition wins).
    fn settings(
        &self,
        signer: &dyn Signer,
        format: &str,
    ) -> Result<
        (
            contentauth_c2pa_sign_baseline::BuilderSettings,
            Option<String>,
        ),
        Error,
    > {
        if !format.eq_ignore_ascii_case(JPEG) {
            return Err(Error::UnsupportedType(format.to_string()));
        }
        let tsa_url = self
            .definition
            .tsa_url
            .clone()
            .or_else(|| signer.time_authority_url());
        let mut settings = self
            .definition
            .clone()
            .into_settings(signer.alg(), signer.certs())?;
        if tsa_url.is_some() && settings.timestamp.is_none() {
            settings.timestamp = Some(TimestampSettings::default());
        }
        Ok((settings, tsa_url))
    }
}

/// Answers one timestamp request: encode the `TimeStampReq`, let the
/// signer send it, unwrap the token from the response.
fn timestamp(
    signer: &dyn Signer,
    tsa_url: Option<&str>,
    alg: HashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, HostError> {
    let url = tsa_url.ok_or_else(|| HostError::new("no time-stamp authority URL is configured"))?;
    let request = timestamp_request(digest, alg)?;
    let response = signer.send_timestamp_request(url, &request)?;
    timestamp_token(&response)
}
