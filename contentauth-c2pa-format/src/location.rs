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

//! What [`FormatHandler::locate`](crate::FormatHandler::locate) reports.

use contentauth_c2pa_primitives::ByteRange;

/// Where an asset's C2PA manifest store is — embedded in the asset,
/// referenced remotely, both, or neither.
///
/// Two independent optionals rather than an enum because the C2PA
/// specification allows both at once: a JPEG or PNG may carry an embedded
/// store *and* an XMP `dcterms:provenance` pointer to a remote one. A
/// handler that does not parse XMP simply never sets [`Self::remote`];
/// nothing about the contract stops a later handler from doing so.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ManifestLocation {
    /// The manifest store embedded in the asset, if any.
    pub embedded: Option<EmbeddedManifest>,

    /// A URL the asset names as the location of its manifest store, if
    /// any. Reported verbatim; nothing in this crate fetches it.
    pub remote: Option<String>,
}

impl ManifestLocation {
    /// No manifest store found, embedded or remote.
    pub fn none() -> Self {
        Self::default()
    }

    /// An embedded manifest store: its exact bytes, the range of the
    /// container structure that carries it, and the ranges a hard binding
    /// for the asset excludes (see [`EmbeddedManifest::range`] and
    /// [`EmbeddedManifest::exclusions`]).
    pub fn embedded(jumbf: Vec<u8>, range: ByteRange, exclusions: Vec<ByteRange>) -> Self {
        Self {
            embedded: Some(EmbeddedManifest::new(jumbf, range, exclusions)),
            remote: None,
        }
    }

    /// A remote manifest store reference and nothing embedded.
    pub fn remote(url: impl Into<String>) -> Self {
        Self {
            embedded: None,
            remote: Some(url.into()),
        }
    }

    /// Adds a remote reference to whatever this location already holds.
    pub fn with_remote(mut self, url: impl Into<String>) -> Self {
        self.remote = Some(url.into());
        self
    }

    /// True if neither an embedded store nor a remote reference was found.
    pub fn is_none(&self) -> bool {
        self.embedded.is_none() && self.remote.is_none()
    }
}

/// A manifest store embedded in an asset.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EmbeddedManifest {
    /// The manifest store's exact bytes — the JUMBF superbox, reassembled
    /// from however the container splits it (a JPEG spreads it across
    /// `APP11` segments, for instance), and byte-identical to what a
    /// builder embedded.
    ///
    /// Exactness matters beyond reading: a signer that carries this store
    /// forward as a parent manifest must reproduce these bytes verbatim,
    /// since the new claim's ingredient assertion hashes them.
    pub jumbf: Vec<u8>,

    /// The range of the asset occupied by the container structure carrying
    /// the store — framing included, so for a JPEG this spans the `APP11`
    /// segments' markers and headers, not just their payloads. This is
    /// the range a re-embed replaces
    /// ([`EmbedPlan::replaced`](crate::EmbedPlan::replaced)).
    pub range: ByteRange,

    /// The ranges a `c2pa.hash.data` hard binding written for this asset
    /// excludes: ascending, not overlapping, and exactly what the format's
    /// specification calls for. For a JPEG, the one [`Self::range`]; for
    /// TIFF, the entry's `count` field and the store, which are not
    /// adjacent — and which a validator compares exactly.
    pub exclusions: Vec<ByteRange>,
}

impl EmbeddedManifest {
    /// Describes an embedded manifest store.
    pub fn new(jumbf: Vec<u8>, range: ByteRange, exclusions: Vec<ByteRange>) -> Self {
        Self {
            jumbf,
            range,
            exclusions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_populate_the_right_halves() {
        let range = ByteRange { start: 20, len: 30 };

        assert!(ManifestLocation::none().is_none());

        let embedded = ManifestLocation::embedded(vec![1, 2, 3], range, vec![range]);
        assert!(!embedded.is_none());
        assert_eq!(
            embedded.embedded.as_ref().map(|e| (&e.jumbf[..], e.range)),
            Some((&[1u8, 2, 3][..], range))
        );
        assert_eq!(embedded.remote, None);

        let remote = ManifestLocation::remote("https://example.com/m.c2pa");
        assert!(!remote.is_none());
        assert!(remote.embedded.is_none());

        let both = embedded.with_remote("https://example.com/m.c2pa");
        assert!(both.embedded.is_some());
        assert_eq!(both.remote.as_deref(), Some("https://example.com/m.c2pa"));
    }
}
