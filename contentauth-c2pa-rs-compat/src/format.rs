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

//! Picks a `FormatHandler` for a file: by what is in it, or failing that,
//! by what it is called.
//!
//! c2pa-rs resolves this from a registry of handlers keyed by MIME type,
//! consulted by every one of `Reader`'s constructors
//! (`supported_mime_types` enumerates it). This crate does the same with
//! a [`Registry`] from `contentauth-c2pa-format-registry`, and this module
//! is the whole of the *policy* around it — which is the point: the
//! registry offers detection by content, by extension and by media type;
//! how they combine is the host's call, and this host's call is:
//!
//! 1. **Content first.** Read the registry's [`Registry::window`] of
//!    leading bytes — one read, however many formats are registered — and
//!    take the format whose signature they carry. A `.dat` file that is a
//!    TIFF is a TIFF, and a `.jpg` that is a TIFF is read as one.
//! 2. **Extension second**, if no signature matched: the format that
//!    serves the file's extension. Its handler then reads the file and
//!    reports what is actually wrong with it, which is more useful than
//!    "unsupported" for a truncated `.jpg`.
//! 3. Otherwise [`Error::UnsupportedType`].
//!
//! Nothing here, and nothing in [`crate::Reader`], names a container
//! format: [`Registry::standard`] decides which are available, and a host
//! that wants others calls [`Registry::register`] in [`registry`].

use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::OnceLock,
};

use contentauth_c2pa_format_registry::{AnyFormat, Registry};

use crate::Error;

/// The formats this host is prepared to read.
pub(crate) fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::standard)
}

/// File extensions (lowercase, without the leading `.`) this build can
/// locate a manifest store within.
pub(crate) fn extensions() -> Vec<&'static str> {
    registry().extensions().collect()
}

/// Picks a handler for the file at `path`, which `source` has open.
///
/// Leaves `source` positioned wherever; the host seeks before each read.
pub(crate) fn choose<R: Read + Seek>(path: &Path, source: &mut R) -> Result<AnyFormat, Error> {
    let registry = registry();

    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };

    let mut header = Vec::new();
    source.seek(SeekFrom::Start(0)).map_err(io)?;
    source
        .take(registry.window())
        .read_to_end(&mut header)
        .map_err(io)?;

    registry
        .detect(&header)
        .or_else(|| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .and_then(|ext| registry.by_extension(ext))
        })
        .cloned()
        .ok_or_else(|| Error::UnsupportedType {
            path: path.to_path_buf(),
            supported: extensions(),
        })
}
