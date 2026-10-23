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
//! containers than this. Both bridges select from the workspace's standard
//! registry, including JPEG and TIFF/BigTIFF/DNG. The caller supplies the
//! format hint; detection and all asset I/O remain host-owned.

use contentauth_c2pa_format_registry::{AnyFormat, Registry};

use super::error::C2paError;

/// The `format` strings this build can locate a manifest store within: a
/// MIME type or a bare extension, matched without regard to case.
pub const FORMATS: &[&str] = &[
    "image/jpeg",
    "image/jpg",
    "jpeg",
    "jpg",
    "image/tiff",
    "image/dng",
    "image/x-adobe-dng",
    "tif",
    "tiff",
    "dng",
];

/// Picks a handler for `format`.
pub fn for_format(format: &str) -> Result<AnyFormat, C2paError> {
    let format = format.trim();
    let format = if format.eq_ignore_ascii_case("image/jpg") {
        "image/jpeg"
    } else {
        format
    };
    let registry = Registry::standard();
    registry
        .by_mime(format)
        .or_else(|| registry.by_extension(format))
        .cloned()
        .ok_or(C2paError::UnsupportedType)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_is_recognized_as_a_mime_type_or_an_extension_regardless_of_case() {
        for format in [
            "image/jpeg",
            "IMAGE/JPEG",
            "jpeg",
            "jpg",
            "JPG",
            "image/jpg",
        ] {
            assert!(
                matches!(for_format(format), Ok(handler) if handler.descriptor().name == "jpeg"),
                "{format}"
            );
        }
    }

    #[test]
    fn every_advertised_format_has_a_registered_handler() {
        for format in FORMATS {
            assert!(for_format(format).is_ok(), "{format}");
        }
    }

    #[test]
    fn tiff_and_dng_hints_select_the_tiff_handler() {
        for format in [
            "image/tiff",
            "image/dng",
            "image/x-adobe-dng",
            "tif",
            "TIFF",
            "dng",
            ".DNG",
            " image/tiff; charset=binary ",
        ] {
            assert!(
                matches!(for_format(format), Ok(handler) if handler.descriptor().name == "tiff"),
                "{format}"
            );
        }
    }

    #[test]
    fn anything_else_is_unsupported() {
        for format in ["image/png", "png", "", "jpe", "application/octet-stream"] {
            assert!(
                matches!(for_format(format), Err(C2paError::UnsupportedType)),
                "{format}"
            );
        }
    }
}
