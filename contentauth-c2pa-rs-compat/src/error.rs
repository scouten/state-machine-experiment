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

//! Errors from [`crate::Reader`], deliberately named and shaped after the
//! variants of c2pa-rs's own `Error` enum that this crate's use case
//! actually reaches.

use std::path::PathBuf;

/// Errors surfaced by [`crate::Reader`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No C2PA manifest store was found in the asset.
    ///
    /// Named after c2pa-rs's `Error::JumbfNotFound`, which `Reader::from_file`
    /// there returns in the same circumstance (absent a sidecar `.c2pa` file,
    /// which this crate does not look for).
    #[error("no JUMBF data found in {path}")]
    JumbfNotFound {
        /// The path that was read.
        path: PathBuf,
    },

    /// `path`'s extension names a container format no `FormatHandler` in
    /// this crate's build has been wired up for.
    ///
    /// c2pa-rs resolves this from a registry of format handlers keyed by
    /// MIME type; this crate has exactly one handler
    /// ([`contentauth_c2pa_format_jpeg::JpegFormat`]), so the check is a
    /// simple extension match today rather than a registry. See
    /// [`crate::Reader::supported_extensions`], and `src/format.rs` for
    /// where a second format handler would extend this.
    #[error("{path} has an extension this build does not support (supported: {supported:?})")]
    UnsupportedType {
        /// The path whose extension was not recognized.
        path: PathBuf,

        /// The extensions this build does recognize.
        supported: &'static [&'static str],
    },

    /// The read engine itself failed — a malformed manifest store,
    /// malformed container framing, or the host-protocol misuse this
    /// crate's own drive loop would be responsible for, not the caller.
    #[error(transparent)]
    Read(#[from] contentauth_c2pa_file_reader::Error),

    /// [`crate::Reader::json_checked`] could not serialize the report.
    ///
    /// Kept for parity with c2pa-rs's own fallible `json_checked`/`json`
    /// contract rather than because this crate's own JSON shape (plain
    /// strings and `Vec`s — see `src/json.rs`) can actually produce one:
    /// nothing in it can fail to serialize, so this variant is expected to
    /// stay unreachable in practice, the same way it does for c2pa-rs's own,
    /// richer report.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
