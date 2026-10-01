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

//! Picks a `FormatHandler` for the `format` string c2pa-wasm's `fromBlob`
//! takes.
//!
//! c2pa-rs accepts either a MIME type or a bare file extension there, and
//! resolves it through a registry of handlers; c2pa-web's own
//! `isSupportedReaderFormat` gate in front of it covers far more
//! containers than this. This crate has exactly one handler —
//! [`JpegFormat`] — so today this is a single string match rather than a
//! registry, and the seam a second `contentauth-c2pa-format-*` crate would
//! extend, exactly as `contentauth-c2pa-rs-compat`'s `format.rs` is: most
//! naturally by returning a small enum that itself implements
//! `FormatHandler`, one variant per handler, since [`crate::read_manifest`]
//! is generic over the handler type rather than a trait object.

use contentauth_c2pa_format_jpeg::JpegFormat;

use crate::error::C2paError;

/// The `format` strings this build can locate a manifest store within: a
/// MIME type or a bare extension, matched without regard to case.
pub const FORMATS: &[&str] = &["image/jpeg", "jpeg", "jpg"];

/// Picks a handler for `format`.
pub(crate) fn for_format(format: &str) -> Result<JpegFormat, C2paError> {
    if FORMATS
        .iter()
        .any(|candidate| format.eq_ignore_ascii_case(candidate))
    {
        Ok(JpegFormat)
    } else {
        Err(C2paError::UnsupportedType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_is_recognized_as_a_mime_type_or_an_extension_regardless_of_case() {
        for format in ["image/jpeg", "IMAGE/JPEG", "jpeg", "jpg", "JPG"] {
            assert!(for_format(format).is_ok(), "{format}");
        }
    }

    #[test]
    fn anything_else_is_unsupported() {
        for format in ["image/png", "png", "", "jpe", "image/jpg"] {
            assert!(
                matches!(for_format(format), Err(C2paError::UnsupportedType)),
                "{format}"
            );
        }
    }
}
