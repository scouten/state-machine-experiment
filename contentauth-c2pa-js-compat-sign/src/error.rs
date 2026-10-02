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
//! Errors from [`crate::Builder`]. Like the reader's, they cross into
//! JavaScript as a string — [`Error::js_message`], the `Debug` form.

/// Why a build failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A `format` no handler in this build recognizes.
    #[error("type is unsupported")]
    UnsupportedType,

    /// The manifest definition could not be used.
    #[error("bad parameter: {0}")]
    BadParam(#[from] contentauth_c2pa_sign_baseline::Error),

    /// Building or signing failed — including the host's signer or blob
    /// failing.
    #[error(transparent)]
    Build(#[from] contentauth_c2pa_file_builder::Error),
}

impl Error {
    /// The string this error crosses into JavaScript as.
    pub fn js_message(&self) -> String {
        format!("{self:?}")
    }
}
