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

use contentauth_c2pa_format::{FormatError, ManifestLocation, StreamId};

use crate::{
    op::{delegate_session, Goal, ScanOp},
    scan::{exclusion_of, Layout},
};

/// The operation [`RiffFormat`](crate::RiffFormat)'s
/// [`locate`](contentauth_c2pa_format::FormatHandler::locate) returns:
/// walks the RIFF chunk's top-level chunks and reads the `C2PA` chunk's
/// data.
///
/// Reports embedded stores only: RIFF assets can carry an XMP chunk with a
/// `dcterms:provenance` reference to a remote store, but this crate does
/// not parse XMP.
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

    const READ_MANIFEST: bool = true;

    fn finalize(self, layout: Layout) -> Result<ManifestLocation, FormatError> {
        Ok(match layout.manifest {
            Some(chunk) => {
                let exclusion = exclusion_of(&chunk);
                ManifestLocation::embedded(chunk.data, chunk.range, vec![exclusion])
            }
            None => ManifestLocation::none(),
        })
    }
}
