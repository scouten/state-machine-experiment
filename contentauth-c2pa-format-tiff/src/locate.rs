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

//! Locating a manifest store.

use contentauth_c2pa_format::{ByteRange, FormatError, ManifestLocation, StreamId};

use crate::{
    op::{delegate_session, Goal, ScanOp},
    scan::Layout,
};

/// The operation [`TiffFormat`](crate::TiffFormat)'s
/// [`locate`](contentauth_c2pa_format::FormatHandler::locate) returns:
/// follows the TIFF's IFD chain and reads the manifest store out of the
/// entry tagged `0xCD41`.
///
/// Reports embedded stores only: this crate does not parse XMP, so a
/// `dcterms:provenance` reference to a remote store goes unreported.
///
/// The reported exclusions are the specification's two — the entry's
/// `count` field and the store — wherever the entry and the store are in
/// the file, so a store another tool laid out is described as exactly as
/// one this crate wrote. The reported range is what a re-embed replaces:
/// from the `count` field to the end of the file when the store is laid
/// out as this crate lays one out, and otherwise just the store's bytes
/// (such a store cannot be replaced; see
/// [`PlanEmbed`](crate::PlanEmbed)).
pub struct Locate(ScanOp<LocateGoal>);

impl Locate {
    pub(crate) fn new(stream: StreamId) -> Self {
        Self(ScanOp::new(stream, LocateGoal))
    }
}

delegate_session!(Locate, ManifestLocation);

struct LocateGoal;

impl Goal for LocateGoal {
    type Output = ManifestLocation;

    const READS_MANIFEST: bool = true;

    fn finalize(self, layout: Layout) -> Result<ManifestLocation, FormatError> {
        let Some(c2pa) = layout.c2pa else {
            return Ok(ManifestLocation::none());
        };
        let range = layout.trailing_store().unwrap_or(c2pa.data);
        let jumbf = layout.manifest.ok_or(FormatError::Malformed(
            "the manifest store was not read".to_string(),
        ))?;

        let count_field = ByteRange {
            start: c2pa.entry_offset + 4,
            len: layout.header.flavor.word_len(),
        };
        let mut exclusions = vec![count_field, c2pa.data];
        exclusions.sort_by_key(|range| range.start);
        if exclusions[0].start + exclusions[0].len > exclusions[1].start {
            return Err(FormatError::Malformed(
                "the manifest store overlaps its own entry".to_string(),
            ));
        }

        Ok(ManifestLocation::embedded(jumbf, range, exclusions))
    }
}
