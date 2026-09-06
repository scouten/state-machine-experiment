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

use std::path::Path;

use contentauth_c2pa_file_reader::ReadSettings;
use contentauth_c2pa_reader::ReadReport;

use crate::{
    error::Error,
    format,
    manifest::Manifest,
    validation::{ValidationState, ValidationStatus},
};

/// Reads and validates a C2PA manifest store from a file on disk.
///
/// The read-only, single-asset counterpart of `Reader` in c2pa-rs, backed
/// by [`contentauth_c2pa_file_reader::read_manifest_from_file`] rather than
/// c2pa-rs's own `Store`. Every method here is named and shaped after its
/// c2pa-rs counterpart; see each method's doc comment for where the
/// behavior necessarily differs, given this workspace's engine reads (and
/// validates) strictly more narrowly than c2pa-rs today — see
/// [`contentauth_c2pa_reader`]'s own README for the list.
///
/// # Example
///
/// ```no_run
/// use contentauth_c2pa_compat::Reader;
///
/// let reader = Reader::from_file("photo.jpg")?;
/// println!("{}", reader.json());
/// assert_eq!(
///     reader.validation_state(),
///     contentauth_c2pa_compat::ValidationState::Trusted
/// );
/// # Ok::<(), contentauth_c2pa_compat::Error>(())
/// ```
#[derive(Debug)]
pub struct Reader {
    report: ReadReport,
}

impl Reader {
    /// File extensions this build can locate a manifest store within.
    ///
    /// Named after c2pa-rs's `Reader::supported_mime_types`; extensions
    /// rather than MIME types because format selection here is a plain
    /// extension match today (see `src/format.rs`) rather than a registry
    /// keyed by content-sniffed MIME type.
    pub fn supported_extensions() -> &'static [&'static str] {
        format::EXTENSIONS
    }

    /// Opens `path`, locates its embedded C2PA manifest store, and
    /// validates it with default settings (no configured trust anchors, so
    /// no manifest can reach [`ValidationState::Trusted`]).
    ///
    /// Fails with [`Error::JumbfNotFound`] if the asset carries no manifest
    /// store — matching c2pa-rs's own `Reader::from_file`, which does the
    /// same absent a sidecar `.c2pa` file (this crate does not look for
    /// one). Fails with [`Error::UnsupportedType`] if `path`'s extension
    /// names a format no handler in this build recognizes; see
    /// [`Self::supported_extensions`].
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_file_with_settings(path, ReadSettings::default())
    }

    /// As [`Self::from_file`], with caller-supplied [`ReadSettings`] —
    /// concretely, trust anchors a manifest's signer must chain to in order
    /// to reach [`ValidationState::Trusted`] rather than merely
    /// [`ValidationState::Valid`].
    ///
    /// c2pa-rs configures trust process-globally (`Settings`/`TrustHandler`
    /// APIs); this crate takes it per read instead, in keeping with every
    /// other session in this workspace taking its configuration as an
    /// explicit argument rather than through global state.
    pub fn from_file_with_settings(
        path: impl AsRef<Path>,
        settings: ReadSettings,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        let handler = format::for_path(path)?;

        let report =
            contentauth_c2pa_file_reader::read_manifest_from_file(&handler, path, settings)?;

        if !report.manifest_store_found {
            return Err(Error::JumbfNotFound {
                path: path.to_path_buf(),
            });
        }

        Ok(Self { report })
    }

    /// Returns the overall validation outcome.
    pub fn validation_state(&self) -> ValidationState {
        self.report.validation_state.into()
    }

    /// Returns the individual validation status codes recorded while
    /// reading, or `None` if none were recorded.
    pub fn validation_status(&self) -> Option<Vec<ValidationStatus>> {
        if self.report.statuses.is_empty() {
            None
        } else {
            Some(
                self.report
                    .statuses
                    .iter()
                    .cloned()
                    .map(ValidationStatus::from)
                    .collect(),
            )
        }
    }

    /// Returns the active manifest — the last one in the store — if any.
    pub fn active_manifest(&self) -> Option<Manifest<'_>> {
        self.report.active().map(Manifest)
    }

    /// Returns the active manifest's label, if any.
    pub fn active_label(&self) -> Option<&str> {
        self.report.active_manifest.as_deref()
    }

    /// Returns the manifest with the given label, if the store contains
    /// one.
    pub fn get_manifest(&self, label: &str) -> Option<Manifest<'_>> {
        self.report
            .manifests
            .iter()
            .find(|manifest| manifest.label == label)
            .map(Manifest)
    }

    /// Iterates over every manifest in the store, in store order.
    pub fn iter_manifests(&self) -> impl Iterator<Item = Manifest<'_>> {
        self.report.manifests.iter().map(Manifest)
    }

    /// Returns the manifest store as a pretty-printed JSON string.
    ///
    /// Returns `"{}"` if serialization fails, matching c2pa-rs's own
    /// `Reader::json`; see [`Self::json_checked`] for the fallible form.
    /// See the `json` module for what this crate's JSON shape does and
    /// does not reproduce from c2pa-rs's own schema.
    pub fn json(&self) -> String {
        self.json_checked().unwrap_or_else(|_| "{}".to_string())
    }

    /// As [`Self::json`], propagating a serialization failure instead of
    /// papering over it.
    pub fn json_checked(&self) -> Result<String, Error> {
        let value = crate::json::value(&self.report)?;
        Ok(serde_json::to_string_pretty(&value)?)
    }
}
