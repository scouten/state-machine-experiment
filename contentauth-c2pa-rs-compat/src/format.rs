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

//! Picks a `FormatHandler` for a file, by extension.
//!
//! c2pa-rs resolves this from a registry of handlers keyed by MIME type,
//! consulted by every one of `Reader`'s constructors
//! (`supported_mime_types` enumerates it). This crate has exactly one
//! handler — [`JpegFormat`] — so today this is a single extension check
//! rather than a registry.
//!
//! A second format handler crate (following [`JpegFormat`]'s lead — see the
//! root `CLAUDE.md`) would turn [`for_path`] into a real dispatch over more
//! than one `FormatHandler` type — most naturally by having it return a
//! small enum that itself implements the trait, one variant per handler,
//! since [`contentauth_c2pa_file_reader::read_manifest_from_file`] is
//! generic over the handler type rather than a trait object. Nothing about
//! [`crate::Reader`] itself is JPEG-specific: it only ever reaches a
//! handler through this seam.

use std::path::Path;

use contentauth_c2pa_format_jpeg::JpegFormat;

use crate::Error;

/// File extensions (lowercase, without the leading `.`) this build can
/// locate a manifest store within.
pub const EXTENSIONS: &[&str] = &["jpg", "jpeg"];

/// Picks a handler for `path` by its extension.
pub(crate) fn for_path(path: &Path) -> Result<JpegFormat, Error> {
    let matches = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            EXTENSIONS
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        });

    if matches {
        Ok(JpegFormat)
    } else {
        Err(Error::UnsupportedType {
            path: path.to_path_buf(),
            supported: EXTENSIONS,
        })
    }
}
