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

//! Errors from [`crate::NodeBuildSession`], shaped like the reader's: what
//! crosses into JavaScript is [`Error::js_message`], a c2pa-rs-style
//! `Debug` string such as `C2pa(UnsupportedType)`.

use contentauth_c2pa_js_compat::C2paError;

/// Errors surfaced by [`crate::NodeBuildSession`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The format, or another argument, is not one this build accepts —
    /// the same [`C2paError`] the reader uses for the same mistakes.
    #[error(transparent)]
    C2pa(#[from] C2paError),

    /// The manifest definition could not be used.
    #[error(transparent)]
    Definition(#[from] contentauth_c2pa_sign_baseline::Error),

    /// Building or signing failed (including a host reply of
    /// [`crate::Reply::Failed`] — e.g. the signer rejected).
    #[error(transparent)]
    Build(#[from] contentauth_c2pa_file_builder::Error),

    /// The engine asked for something this wrapper has no description
    /// for (today: an RFC 3161 timestamp).
    #[error("unsupported request: {0}")]
    Unsupported(String),
}

impl Error {
    /// The string this error crosses into JavaScript as, as the
    /// reader's does: for the shared [`C2paError`] cases, exactly c2pa-rs's
    /// `Debug` form (`C2pa(UnsupportedType)`); for the rest, the variant's
    /// name with its detail (`Definition(BadDefinition("..."))`).
    pub fn js_message(&self) -> String {
        match self {
            Self::C2pa(err) => format!("C2pa({err:?})"),
            Self::Definition(err) => format!("Definition({err:?})"),
            Self::Build(err) => format!("Build({err})"),
            Self::Unsupported(what) => format!("Unsupported({what})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_errors_use_the_readers_strings() {
        assert_eq!(
            Error::from(C2paError::UnsupportedType).js_message(),
            "C2pa(UnsupportedType)"
        );
        assert_eq!(
            Error::from(C2paError::BadParam("x".to_string())).js_message(),
            "C2pa(BadParam(\"x\"))"
        );
    }

    #[test]
    fn other_errors_name_their_kind() {
        assert!(Error::Unsupported("t".to_string())
            .js_message()
            .starts_with("Unsupported("));
    }
}
