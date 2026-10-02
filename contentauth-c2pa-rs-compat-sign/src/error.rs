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
use std::path::PathBuf;

/// Errors from [`crate::Builder`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The manifest definition could not be used.
    #[error(transparent)]
    Definition(#[from] contentauth_c2pa_sign_baseline::Error),

    /// Named after c2pa-rs's `Error::UnsupportedType`.
    #[error("unsupported format {0:?} (supported: image/jpeg)")]
    UnsupportedType(String),

    /// `sign_file` could not work out a format from this path's extension.
    #[error("{path} has an extension this build does not support (supported: jpg, jpeg)")]
    UnsupportedPath {
        /// The offending path.
        path: PathBuf,
    },

    /// Building or signing failed.
    #[error(transparent)]
    Build(#[from] contentauth_c2pa_file_builder::Error),
}
