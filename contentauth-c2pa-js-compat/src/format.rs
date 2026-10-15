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
//! containers than this. This host wires JPEG and TIFF/BigTIFF/DNG through
//! the workspace's registry. The type-erased handler still drives the same
//! sans-I/O sessions, and is shared by the read/sign browser and Node hosts.

use contentauth_c2pa_format_registry::{AnyFormat, Registry};

use crate::error::C2paError;

/// The `format` strings this build can locate a manifest store within: a
/// MIME type or a bare extension, matched without regard to case.
pub const FORMATS: &[&str] = &[
    "image/jpeg",
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

    #[test]
    fn tiff_and_dng_are_selected_through_the_shared_registry() {
        for format in [
            "image/tiff",
            "IMAGE/TIFF",
            "image/dng",
            "image/x-adobe-dng",
            "tif",
            "TIFF",
            "dng",
        ] {
            assert!(matches!(
                for_format(format).map(|handler| handler.descriptor().name),
                Ok("tiff")
            ));
        }
        let registry = Registry::standard();
        let mut advertised: Vec<_> = registry
            .formats()
            .iter()
            .flat_map(|handler| {
                let descriptor = handler.descriptor();
                descriptor
                    .mime_types
                    .iter()
                    .chain(descriptor.extensions.iter())
                    .copied()
            })
            .collect();
        let mut formats = FORMATS.to_vec();
        advertised.sort_unstable();
        formats.sort_unstable();
        assert_eq!(formats, advertised);
    }
}
