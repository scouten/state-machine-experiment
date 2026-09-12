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

//! [`Context`]: a reusable, shareable bundle of configuration a [`crate::Reader`]
//! is built from — mirroring the shape of c2pa-rs's own `Context`/`Reader::from_context`
//! pattern, which that crate now recommends over its (deprecated)
//! standalone `Reader::from_file`.
//!
//! Real c2pa-rs's `Context` also carries HTTP resolvers, a signer, a
//! progress callback, and a cancellation flag — none of which apply to
//! this crate's read-only, single-use-case scope (see the crate-level
//! docs for what that scope is). What's mirrored here is the *shape*:
//! build a `Context`, configure it once, then hand it to
//! [`crate::Reader::from_context`] (or share it across several readers via
//! [`Context::into_shared`] and [`crate::Reader::from_shared_context`])
//! rather than passing configuration as loose arguments to each read.
//!
//! The one thing a `Context` here actually configures is
//! [`ReadSettings`] — concretely, the trust anchors a manifest's signer
//! must chain to in order to reach [`crate::ValidationState::Trusted`].
//! c2pa-rs's own `Context::with_settings` is generic over JSON, TOML, or
//! its own `Settings` struct and can fail to parse; this one only ever
//! takes a [`ReadSettings`] value directly, so configuring it can't fail.

use std::sync::Arc;

use contentauth_c2pa_file_reader::ReadSettings;

/// Configuration a [`crate::Reader`] is built from.
///
/// # Example
///
/// ```no_run
/// use contentauth_c2pa_rs_compat::{Context, ReadSettings, Reader};
///
/// let context = Context::new().with_settings(ReadSettings {
///     trust_anchors: vec![/* DER-encoded certificates */],
///     ..ReadSettings::default()
/// });
///
/// let reader = Reader::from_context(context).with_file("photo.jpg")?;
/// # Ok::<(), contentauth_c2pa_rs_compat::Error>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Context {
    settings: ReadSettings,
}

impl Context {
    /// Creates a new `Context` with default settings (no configured trust
    /// anchors, so no manifest can reach [`crate::ValidationState::Trusted`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Consumes this `Context` and wraps it in an [`Arc`] for sharing
    /// across readers — equivalent to `Arc::new(self)`, but chainable with
    /// the rest of this type's builder-style methods.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Configures this `Context` with `settings`, replacing any previous
    /// configuration.
    pub fn with_settings(mut self, settings: ReadSettings) -> Self {
        self.settings = settings;
        self
    }

    /// As [`Self::with_settings`], without consuming and returning `self`.
    pub fn set_settings(&mut self, settings: ReadSettings) {
        self.settings = settings;
    }

    /// Returns the configured settings.
    pub fn settings(&self) -> &ReadSettings {
        &self.settings
    }

    /// Returns the configured settings, mutably.
    pub fn settings_mut(&mut self) -> &mut ReadSettings {
        &mut self.settings
    }
}
