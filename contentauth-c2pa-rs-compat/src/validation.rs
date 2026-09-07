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

//! Validation types shaped after c2pa-rs's `ValidationState` and
//! `ValidationStatus`, rather than re-exported from
//! [`contentauth_c2pa_reader`] as-is.
//!
//! Two differences drive that choice: c2pa-rs's `ValidationState` has three
//! variants (`Invalid`, `Valid`, `Trusted`); `contentauth_c2pa_reader`'s has
//! a fourth, [`contentauth_c2pa_reader::ValidationState::Incomplete`], for a
//! check that never ran rather than one that failed — a distinction
//! c2pa-rs's own doc comment for `Invalid` acknowledges from the other
//! side ("this case may also occur if validation is disabled"). This crate
//! folds `Incomplete` into [`ValidationState::Invalid`], the conservative
//! reading, rather than inventing a fourth variant c2pa-rs callers would
//! not recognize. And c2pa-rs's `ValidationStatus` hides its fields behind
//! `code()`/`url()`/`explanation()` accessors rather than exposing them
//! directly, so this crate's [`ValidationStatus`] wraps
//! [`contentauth_c2pa_reader::ValidationStatus`] to present the same shape.

/// Overall validation outcome for a manifest store.
///
/// Mirrors `ValidationState` in c2pa-rs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationState {
    /// The manifest store failed validation, or nothing was validated, or
    /// the trust evaluation never ran at all —
    /// [`contentauth_c2pa_reader::ValidationState::Incomplete`] folds into
    /// this variant, since c2pa-rs has no equivalent of its own.
    Invalid,

    /// The manifest store is well-formed and every cryptographic check
    /// that ran passed, but the signer is not among the configured trust
    /// anchors.
    Valid,

    /// Valid, and the signer's credential chains to a configured trust
    /// anchor.
    Trusted,
}

impl From<Option<contentauth_c2pa_reader::ValidationState>> for ValidationState {
    fn from(state: Option<contentauth_c2pa_reader::ValidationState>) -> Self {
        use contentauth_c2pa_reader::ValidationState as Inner;

        match state {
            Some(Inner::Trusted) => Self::Trusted,
            Some(Inner::Valid) => Self::Valid,
            // `Inner::Invalid` and `Inner::Incomplete` both fold in here,
            // as does a future non-exhaustive variant added upstream: the
            // conservative reading is the safe default for one this crate
            // does not yet know how to interpret.
            Some(_) | None => Self::Invalid,
        }
    }
}

/// One validation status observation, in the vocabulary of the C2PA
/// specification's validation status codes.
///
/// Wraps [`contentauth_c2pa_reader::ValidationStatus`] behind accessor
/// methods rather than public fields, matching c2pa-rs's own
/// `ValidationStatus` shape.
#[derive(Clone, Debug)]
pub struct ValidationStatus(contentauth_c2pa_reader::ValidationStatus);

impl ValidationStatus {
    /// Returns the validation status code, e.g. `assertion.dataHash.match`.
    pub fn code(&self) -> &str {
        &self.0.code
    }

    /// Returns the JUMBF URI of the manifest store element this status
    /// pertains to, if any.
    pub fn url(&self) -> Option<&str> {
        self.0.url.as_deref()
    }

    /// Returns a human-readable explanation of the check performed, if
    /// any.
    pub fn explanation(&self) -> Option<&str> {
        self.0.explanation.as_deref()
    }
}

impl From<contentauth_c2pa_reader::ValidationStatus> for ValidationStatus {
    fn from(status: contentauth_c2pa_reader::ValidationStatus) -> Self {
        Self(status)
    }
}

#[cfg(test)]
mod tests {
    use contentauth_c2pa_reader::ValidationState as Inner;

    use super::ValidationState;

    #[test]
    fn trusted_and_valid_map_straight_across() {
        assert_eq!(
            ValidationState::from(Some(Inner::Trusted)),
            ValidationState::Trusted
        );
        assert_eq!(
            ValidationState::from(Some(Inner::Valid)),
            ValidationState::Valid
        );
    }

    #[test]
    fn invalid_incomplete_and_no_outcome_at_all_fold_into_invalid() {
        assert_eq!(
            ValidationState::from(Some(Inner::Invalid)),
            ValidationState::Invalid
        );
        assert_eq!(
            ValidationState::from(Some(Inner::Incomplete)),
            ValidationState::Invalid
        );
        assert_eq!(ValidationState::from(None), ValidationState::Invalid);
    }
}
