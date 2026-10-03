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

//! [`Manifest`]: a borrowed view over one
//! [`contentauth_c2pa_reader::Manifest`], with the subset of c2pa-rs's own
//! `Manifest` accessor methods this crate's read-only, single-asset use
//! case has a real answer for.
//!
//! c2pa-rs's `Manifest` also carries ingredients, assertions as decoded
//! values, thumbnails, and resource references — none of which
//! [`contentauth_c2pa_reader`] decodes yet (see its own README for what it
//! reads today). Rather than fabricate those, this wrapper exposes only
//! `label`, `title`, `format`, `instance_id`, `claim_generator`,
//! `claim_generator_info`, and `claim_version`; a
//! caller after the full manifest graph wants
//! [`crate::Reader::json`](crate::Reader::json) instead, or
//! [`contentauth_c2pa_reader::Manifest`] directly.

/// A read-only view over one manifest in a read [`crate::Reader`].
///
/// Named and shaped after `Manifest` in c2pa-rs, but borrowed from the
/// [`crate::Reader`] that produced it rather than owned, and carrying only
/// the fields this crate can actually populate.
#[derive(Clone, Copy, Debug)]
pub struct Manifest<'a>(pub(crate) &'a contentauth_c2pa_reader::Manifest);

impl<'a> Manifest<'a> {
    /// Returns the manifest label, as referenced in a manifest store.
    pub fn label(&self) -> &'a str {
        &self.0.label
    }

    /// Returns a user-displayable title for this manifest, if the claim
    /// carries one.
    pub fn title(&self) -> Option<&'a str> {
        self.0.claim.title.as_deref()
    }

    /// Returns a MIME content type for the asset this manifest describes,
    /// if the claim carries one.
    ///
    /// Only a v1 claim does: the v2 claim has no `dc:format` field (see
    /// [`Self::claim_version`]), so this is `None` for a v2 manifest.
    pub fn format(&self) -> Option<&'a str> {
        self.0.claim.format.as_deref()
    }

    /// Returns the instance identifier, or an empty string if the claim
    /// carries none.
    ///
    /// c2pa-rs's own `instance_id` is infallible because the specification
    /// requires the field; this crate returns an empty string in its place
    /// rather than widen the return type to `Option`, since a claim this
    /// core could decode at all but which omitted the field is exactly the
    /// "absent" case c2pa-rs's own signature has no way to represent.
    pub fn instance_id(&self) -> &'a str {
        self.0.claim.instance_id.as_deref().unwrap_or_default()
    }

    /// Returns a user-agent-formatted string identifying the software that
    /// produced this claim, if any.
    pub fn claim_generator(&self) -> Option<&'a str> {
        self.0.claim.claim_generator.as_deref()
    }

    /// Returns the structured descriptions of the software that produced
    /// this claim: the `claim_generator_info` array of a v1 claim, or the
    /// single `generator-info-map` of a v2 claim (the only form a v2 claim
    /// has — it carries no legacy [`Self::claim_generator`] string).
    pub fn claim_generator_info(&self) -> &'a [contentauth_c2pa_reader::GeneratorInfo] {
        &self.0.claim.claim_generator_info
    }

    /// Returns the version of the C2PA claim this manifest carries: `1`
    /// for a `c2pa.claim`, `2` for a `c2pa.claim.v2`.
    pub fn claim_version(&self) -> u8 {
        match self.0.claim.version {
            contentauth_c2pa_reader::ClaimVersion::V1 => 1,
            _ => 2,
        }
    }
}
