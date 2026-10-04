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

//! A host's collection of formats, and how it picks among them.

use contentauth_c2pa_format::FormatHandler;

use crate::erased::AnyFormat;

/// The formats a host is prepared to handle, in the order it tries them.
///
/// A registry answers *which handler?*; it never reads an asset. Reading
/// the leading bytes of one — [`Self::window`] of them — is the host's job,
/// done however and whenever the host reads (a blocking `read`, an awaited
/// `Blob.slice`, a cache hit), and the bytes then go to [`Self::detect`].
/// A pure function of bytes in hand is also what keeps this the smallest
/// possible interface for another language to reproduce.
///
/// Policy is the host's too. A registry offers three independent ways to
/// find a format — [`Self::detect`] by content, [`Self::by_extension`],
/// [`Self::by_mime`] — and no opinion on how they combine. (Content is
/// evidence; a file name or a `Content-Type` is a claim. A host that
/// trusts its claims can skip reading at all.)
#[derive(Clone, Debug, Default)]
pub struct Registry {
    formats: Vec<AnyFormat>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry of the formats this workspace ships, as far as the
    /// crate's features enable them.
    pub fn standard() -> Self {
        #[allow(unused_mut)]
        let mut registry = Self::new();
        #[cfg(feature = "jpeg")]
        registry.register(contentauth_c2pa_format_jpeg::JpegFormat);
        #[cfg(feature = "tiff")]
        registry.register(contentauth_c2pa_format_tiff::TiffFormat);
        registry
    }

    /// Adds a Rust format. Earlier registrations are tried first.
    pub fn register<H>(&mut self, handler: H) -> &mut Self
    where
        H: FormatHandler + Send + Sync + 'static,
        H::Locate: 'static,
        H::PlanEmbed: 'static,
    {
        self.register_any(AnyFormat::new(handler))
    }

    /// Adds a format already wrapped as an [`AnyFormat`] — one built with
    /// [`AnyFormat::from_dyn`], say.
    pub fn register_any(&mut self, format: AnyFormat) -> &mut Self {
        self.formats.push(format);
        self
    }

    /// As [`Self::register_any`], for building a registry in one
    /// expression.
    pub fn with(mut self, format: AnyFormat) -> Self {
        self.register_any(format);
        self
    }

    /// The registered formats, in order.
    pub fn formats(&self) -> &[AnyFormat] {
        &self.formats
    }

    /// The file extensions of every registered format, in order.
    pub fn extensions(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.formats
            .iter()
            .flat_map(|f| f.descriptor().extensions.iter().copied())
    }

    /// The media types of every registered format, in order.
    pub fn mime_types(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.formats
            .iter()
            .flat_map(|f| f.descriptor().mime_types.iter().copied())
    }

    /// How many leading bytes of an asset [`Self::detect`] may look at.
    ///
    /// Read this many (or the whole asset, if it is shorter) and pass them
    /// to [`Self::detect`]: one read serves every registered format.
    pub fn window(&self) -> u64 {
        self.formats
            .iter()
            .map(|f| f.descriptor().window())
            .max()
            .unwrap_or(0)
    }

    /// The first format whose signature `header` — the asset's leading
    /// bytes — carries.
    pub fn detect(&self, header: &[u8]) -> Option<&AnyFormat> {
        self.formats.iter().find(|f| f.descriptor().matches(header))
    }

    /// The first format that serves `extension` (with or without a
    /// leading dot, any case).
    pub fn by_extension(&self, extension: &str) -> Option<&AnyFormat> {
        self.formats
            .iter()
            .find(|f| f.descriptor().serves_extension(extension))
    }

    /// The first format that serves the media type `mime` (any case, any
    /// `; parameters`).
    pub fn by_mime(&self, mime: &str) -> Option<&AnyFormat> {
        self.formats
            .iter()
            .find(|f| f.descriptor().serves_mime(mime))
    }
}
