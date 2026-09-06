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

//! Errors from building and signing a manifest store into a file or byte
//! buffer.

use std::path::PathBuf;

use contentauth_c2pa_primitives::{ByteRange, HostError};
use contentauth_state_machine::RequestId;

/// Errors surfaced by [`crate::FileBuilderSession`],
/// [`crate::build_and_sign`], and [`crate::build_and_sign_file`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A file could not be read from or written to disk.
    #[error("could not access {path}: {source}")]
    Io {
        /// The path that could not be accessed.
        path: PathBuf,

        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// [`crate::FileBuilderSession`]'s own host used the
    /// [`contentauth_state_machine::Session`] API incorrectly.
    #[error(transparent)]
    Protocol(#[from] contentauth_state_machine::ProtocolError),

    /// The format handler could not plan the embedding, or commit the
    /// final manifest, into the asset's container.
    #[error(transparent)]
    Format(#[from] contentauth_c2pa_format::FormatError),

    /// The builder could not assemble or sign the manifest once the
    /// placeholder was embedded.
    #[error(transparent)]
    Build(#[from] contentauth_c2pa_builder::Error),

    /// A host operation this session issues directly (not one forwarded
    /// from the builder or the format handler) failed and the workflow
    /// cannot continue without it.
    #[error("host reported failure for {id}: {source}")]
    HostFailure {
        /// ID of the request the host could not fulfill.
        id: RequestId,

        /// Failure description reported by the host.
        source: HostError,
    },

    /// The host returned a different number of bytes than the range it
    /// was asked for, while this session was reading the whole source
    /// asset into memory.
    #[error(
        "host returned {actual} bytes for a request of {} at offset {}",
        range.len, range.start
    )]
    ReadLengthMismatch {
        /// The range that was requested.
        range: ByteRange,

        /// How many bytes the host actually returned.
        actual: u64,
    },

    /// An internal invariant this session relies on did not hold.
    ///
    /// Indicates a bug in this crate rather than a problem with the asset
    /// or a misbehaving host — kept here as fallback rather than a panic.
    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),
}
