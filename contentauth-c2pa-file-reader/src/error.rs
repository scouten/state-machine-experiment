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

//! Errors from reading a manifest store from a file or byte buffer.

use std::path::PathBuf;

/// Errors surfaced by [`crate::read_manifest`] and
/// [`crate::read_manifest_from_file`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file could not be read from disk.
    #[error("could not read {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: PathBuf,

        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The format handler could not locate the manifest store in the
    /// asset's container.
    #[error(transparent)]
    Format(#[from] contentauth_c2pa_format::FormatError),

    /// The reader could not read or validate the manifest store once
    /// located.
    #[error(transparent)]
    Read(#[from] contentauth_c2pa_reader::Error),
}
