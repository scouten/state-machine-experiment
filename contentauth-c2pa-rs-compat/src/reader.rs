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

use std::{path::Path, sync::Arc};

use contentauth_c2pa_reader::ReadReport;

use crate::{
    context::Context,
    error::Error,
    format,
    manifest::Manifest,
    validation::{ValidationState, ValidationStatus},
};

/// Reads and validates a C2PA manifest store from a file on disk.
///
/// The read-only, single-asset counterpart of `Reader` in c2pa-rs, backed
/// by a [`contentauth_c2pa_file_reader::FileReadSession`] — driven by
/// `src/host.rs`'s own `reqwest`-backed host, rather than
/// [`contentauth_c2pa_file_reader::read_manifest_from_file`], so that
/// [`ReadSettings::check_ocsp`](contentauth_c2pa_file_reader::ReadSettings::check_ocsp)
/// can make a real HTTP request — rather than c2pa-rs's own `Store`. Every
/// method here is named and shaped after its
/// c2pa-rs counterpart; see each method's doc comment for where the
/// behavior necessarily differs, given this workspace's engine reads (and
/// validates) strictly more narrowly than c2pa-rs today — see
/// [`contentauth_c2pa_reader`]'s own README for the list.
///
/// Built from a [`Context`], exactly as c2pa-rs's own `Reader` now prefers
/// ([`Self::from_file`] is a deprecated convenience over the same path, as
/// it is in c2pa-rs): create a `Context`, configure it once (trust
/// anchors, today), and hand it to [`Self::from_context`] rather than
/// passing configuration as a loose argument to each read.
///
/// # Example
///
/// ```no_run
/// use contentauth_c2pa_rs_compat::{Context, Reader, ValidationState};
///
/// let reader = Reader::from_context(Context::new()).with_file("photo.jpg")?;
/// println!("{}", reader.json());
/// assert_eq!(reader.validation_state(), ValidationState::Trusted);
/// # Ok::<(), contentauth_c2pa_rs_compat::Error>(())
/// ```
#[derive(Debug)]
pub struct Reader {
    context: Arc<Context>,

    /// `None` until [`Self::with_file`] succeeds — mirrors c2pa-rs's own
    /// `Reader`, which likewise exists (via [`Self::default`]) before any
    /// asset has been loaded into it. Every accessor below answers as
    /// though nothing was found, rather than panicking, in that state.
    report: Option<ReadReport>,
}

impl Default for Reader {
    fn default() -> Self {
        Self::from_context(Context::default())
    }
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

    /// Creates a `Reader` from the given [`Context`], with no asset loaded
    /// yet — call [`Self::with_file`] next.
    pub fn from_context(context: Context) -> Self {
        Self {
            context: Arc::new(context),
            report: None,
        }
    }

    /// As [`Self::from_context`], sharing a [`Context`] already held by an
    /// [`Arc`] — e.g. one also used to build other readers — rather than
    /// taking ownership of a new one.
    pub fn from_shared_context(context: &Arc<Context>) -> Self {
        Self {
            context: Arc::clone(context),
            report: None,
        }
    }

    /// Opens `path`, locates its embedded C2PA manifest store, and
    /// validates it per this reader's [`Context`].
    ///
    /// Fails with [`Error::JumbfNotFound`] if the asset carries no manifest
    /// store — matching c2pa-rs's own `Reader::with_file`, which does the
    /// same absent a sidecar `.c2pa` file (this crate does not look for
    /// one). Fails with [`Error::UnsupportedType`] if `path`'s extension
    /// names a format no handler in this build recognizes; see
    /// [`Self::supported_extensions`].
    ///
    /// Reading more than one file into the same `Reader` — c2pa-rs supports
    /// this, to merge manifests from more than one source — is not: a
    /// second call replaces whatever an earlier one loaded rather than
    /// merging with it, since this crate's use case is a single asset.
    pub fn with_file(mut self, path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let handler = format::for_path(path)?;
        let settings = self.context.settings().clone();

        let report = crate::host::read_and_validate(&handler, path, settings)?;

        if !report.manifest_store_found {
            return Err(Error::JumbfNotFound {
                path: path.to_path_buf(),
            });
        }

        self.report = Some(report);
        Ok(self)
    }

    /// Opens `path` and reads it with default settings (no configured
    /// trust anchors, so no manifest can reach [`ValidationState::Trusted`]).
    ///
    /// Equivalent to `Reader::default().with_file(path)`, exactly as
    /// c2pa-rs's own (deprecated) `Reader::from_file` is equivalent to
    /// `Reader::default().with_file(path)` there. Prefer
    /// [`Self::from_context`] to configure trust anchors first.
    #[deprecated(
        note = "use `Reader::default().with_file(path)`, or `Reader::from_context(context)` to configure trust anchors first"
    )]
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::default().with_file(path)
    }

    /// Returns the overall validation outcome, or [`ValidationState::Invalid`]
    /// if no asset has been loaded yet.
    pub fn validation_state(&self) -> ValidationState {
        match &self.report {
            Some(report) => report.validation_state.into(),
            None => ValidationState::Invalid,
        }
    }

    /// Returns the individual validation status codes recorded while
    /// reading, or `None` if none were recorded (including if no asset has
    /// been loaded yet).
    pub fn validation_status(&self) -> Option<Vec<ValidationStatus>> {
        let report = self.report.as_ref()?;

        if report.statuses.is_empty() {
            None
        } else {
            Some(
                report
                    .statuses
                    .iter()
                    .cloned()
                    .map(ValidationStatus::from)
                    .collect(),
            )
        }
    }

    /// Returns the active manifest — the last one in the store — if any.
    ///
    /// Reads position directly (`manifests.last()`) rather than going
    /// through [`ReadReport::active`], which resolves
    /// [`ReadReport::active_manifest`]'s label via a first-match search: the
    /// parser does not enforce unique labels, so a store with a duplicate
    /// would make that search return an earlier manifest instead of the
    /// last (active) one it is documented to mean.
    ///
    /// [`ReadReport::active`]: contentauth_c2pa_reader::ReadReport::active
    /// [`ReadReport::active_manifest`]: contentauth_c2pa_reader::ReadReport::active_manifest
    pub fn active_manifest(&self) -> Option<Manifest<'_>> {
        self.report.as_ref()?.manifests.last().map(Manifest)
    }

    /// Returns the active manifest's label, if any.
    pub fn active_label(&self) -> Option<&str> {
        self.report.as_ref()?.active_manifest.as_deref()
    }

    /// Returns the manifest with the given label, if the store contains
    /// one.
    pub fn get_manifest(&self, label: &str) -> Option<Manifest<'_>> {
        self.report
            .as_ref()?
            .manifests
            .iter()
            .find(|manifest| manifest.label == label)
            .map(Manifest)
    }

    /// Iterates over every manifest in the store, in store order.
    pub fn iter_manifests(&self) -> impl Iterator<Item = Manifest<'_>> {
        self.report
            .iter()
            .flat_map(|report| report.manifests.iter().map(Manifest))
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
    ///
    /// Answers `"{}"` directly, without touching the `json` module, if no
    /// asset has been loaded yet — there is nothing yet to serialize.
    pub fn json_checked(&self) -> Result<String, Error> {
        let Some(report) = &self.report else {
            return Ok("{}".to_string());
        };

        let value = crate::json::value(report)?;
        Ok(serde_json::to_string_pretty(&value)?)
    }
}
