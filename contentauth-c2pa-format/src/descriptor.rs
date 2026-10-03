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

//! What a handler says about its format as plain data, so that something
//! other than the handler can decide whether an asset is one.
//!
//! A [`FormatDescriptor`] is deliberately *declarative*: names, media
//! types, extensions, and byte signatures — no function pointers, no
//! code. Detection ("which handler does this asset want?") therefore needs
//! nothing from a handler but its descriptor, and a descriptor survives
//! being written down as a JSON document or a table in another language.
//! The matching rule is here ([`FormatDescriptor::matches`]) so every host
//! applies it identically; *using* it — which bytes to read, in what
//! order to try formats, how to weigh a file extension against content —
//! is the host's business, and lives in the host's own crates.

/// One byte pattern that identifies a format: these bytes, at this offset
/// from the start of the asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    /// Offset of the first byte to compare.
    pub offset: u64,

    /// The bytes expected there.
    pub bytes: &'static [u8],
}

impl Signature {
    /// Describes a signature.
    pub const fn new(offset: u64, bytes: &'static [u8]) -> Self {
        Self { offset, bytes }
    }

    /// The number of leading asset bytes that must be available to
    /// evaluate this signature.
    pub const fn window(&self) -> u64 {
        self.offset.saturating_add(self.bytes.len() as u64)
    }

    /// True if `header` — the asset's leading bytes — carries this
    /// signature. A header too short to reach it does not.
    pub fn matches(&self, header: &[u8]) -> bool {
        let Ok(start) = usize::try_from(self.offset) else {
            return false;
        };
        start
            .checked_add(self.bytes.len())
            .and_then(|end| header.get(start..end))
            .is_some_and(|found| found == self.bytes)
    }
}

/// How a handler's format identifies itself.
///
/// Returned by [`FormatHandler::descriptor`](crate::FormatHandler::descriptor).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FormatDescriptor {
    /// A short, stable, lowercase name (`"jpeg"`, `"tiff"`): what a
    /// registry reports and what a person reads in a log. Not a MIME type.
    pub name: &'static str,

    /// The media types this handler serves, lowercase. The first is the
    /// canonical one; the rest are aliases some producers use.
    pub mime_types: &'static [&'static str],

    /// The file extensions this handler serves, lowercase, without the
    /// leading dot. Only a *hint*: an extension is a claim about the
    /// asset, not evidence.
    pub extensions: &'static [&'static str],

    /// Byte patterns that identify the format; an asset matching *any*
    /// one is taken to be this format. Empty if the format has no magic
    /// number, in which case it can only be chosen by hint.
    pub signatures: &'static [Signature],
}

impl FormatDescriptor {
    /// Describes a format. `signatures` may be empty.
    pub const fn new(
        name: &'static str,
        mime_types: &'static [&'static str],
        extensions: &'static [&'static str],
        signatures: &'static [Signature],
    ) -> Self {
        Self {
            name,
            mime_types,
            extensions,
            signatures,
        }
    }

    /// How many leading bytes of an asset [`Self::matches`] may look at.
    ///
    /// A host reads this many bytes (or the whole asset, if shorter) once
    /// and offers them to every candidate format.
    pub fn window(&self) -> u64 {
        self.signatures
            .iter()
            .map(Signature::window)
            .max()
            .unwrap_or(0)
    }

    /// True if `header` — the asset's leading bytes, at least
    /// [`Self::window`] of them where the asset is that long — carries one
    /// of this format's signatures.
    pub fn matches(&self, header: &[u8]) -> bool {
        self.signatures.iter().any(|sig| sig.matches(header))
    }

    /// True if `mime` names this format, ignoring case and any
    /// `; parameters`.
    pub fn serves_mime(&self, mime: &str) -> bool {
        let essence = mime.split(';').next().unwrap_or(mime).trim();
        self.mime_types
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(essence))
    }

    /// True if `extension` (with or without a leading dot, any case)
    /// names this format.
    pub fn serves_extension(&self, extension: &str) -> bool {
        let extension = extension.strip_prefix('.').unwrap_or(extension);
        self.extensions
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: FormatDescriptor = FormatDescriptor::new(
        "example",
        &["image/example", "image/x-example"],
        &["exm"],
        &[Signature::new(0, b"EX"), Signature::new(4, b"AMPL")],
    );

    #[test]
    fn a_signature_matches_at_its_offset_only() {
        assert!(EXAMPLE.matches(b"EX\0\0\0\0"));
        assert!(EXAMPLE.matches(b"\0\0\0\0AMPLE"));
        assert!(!EXAMPLE.matches(b"\0EX\0\0\0"));
        assert!(!EXAMPLE.matches(b"AMPL"));
    }

    #[test]
    fn a_header_too_short_to_reach_a_signature_does_not_match() {
        assert!(!EXAMPLE.matches(b""));
        assert!(!EXAMPLE.matches(b"E"));
        assert!(!EXAMPLE.matches(b"\0\0\0\0AMP"));
    }

    #[test]
    fn the_window_covers_the_farthest_signature() {
        assert_eq!(EXAMPLE.window(), 8);
        assert_eq!(FormatDescriptor::new("none", &[], &[], &[]).window(), 0);
    }

    #[test]
    fn an_absurd_offset_neither_panics_nor_matches() {
        let sig = Signature::new(u64::MAX, b"x");
        assert!(!sig.matches(b"xxxx"));
        assert_eq!(sig.window(), u64::MAX);
    }

    #[test]
    fn mime_types_ignore_case_and_parameters() {
        assert!(EXAMPLE.serves_mime("IMAGE/Example"));
        assert!(EXAMPLE.serves_mime("image/x-example; charset=binary"));
        assert!(!EXAMPLE.serves_mime("image/jpeg"));
    }

    #[test]
    fn extensions_ignore_case_and_a_leading_dot() {
        assert!(EXAMPLE.serves_extension("EXM"));
        assert!(EXAMPLE.serves_extension(".exm"));
        assert!(!EXAMPLE.serves_extension("jpg"));
    }
}
