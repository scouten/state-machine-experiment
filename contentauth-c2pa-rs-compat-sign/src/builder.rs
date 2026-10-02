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

use contentauth_c2pa_file_builder::{build_and_sign, build_and_sign_file, FileBuilderReport};
use contentauth_c2pa_format_jpeg::JpegFormat;
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
        let settings = self.settings(signer, format)?;
        let report = build_and_sign(JpegFormat, source, dest, settings, |_, data| {
            signer.sign(data)
        })?;
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

        let settings = self.settings(signer, JPEG)?;
        let FileBuilderReport { manifest, .. } =
            build_and_sign_file(JpegFormat, source, dest, settings, |_, data| {
                signer.sign(data)
            })?;
        Ok(manifest)
    }

    fn settings(
        &self,
        signer: &dyn Signer,
        format: &str,
    ) -> Result<contentauth_c2pa_sign_baseline::BuilderSettings, Error> {
        if !format.eq_ignore_ascii_case(JPEG) {
            return Err(Error::UnsupportedType(format.to_string()));
        }
        Ok(self
            .definition
            .clone()
            .into_settings(JPEG, signer.alg(), signer.certs())?)
    }
}
