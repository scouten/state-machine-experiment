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
    scan::Layout,
};

/// The operation [`JpegFormat`](crate::JpegFormat)'s
/// [`locate`](contentauth_c2pa_format::FormatHandler::locate) returns:
/// scans the JPEG's header and reassembles the manifest store from its
/// `APP11` segments.
///
/// Reports embedded stores only: this crate does not parse XMP, so an
/// `APP1` XMP packet's `dcterms:provenance` reference to a remote store
/// goes unreported for now. The contract has room for it
/// ([`ManifestLocation::remote`]); the parsing is what is missing.
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

    fn finalize(self, layout: Layout) -> Result<ManifestLocation, FormatError> {
        Ok(match layout.manifest_run()? {
            Some(run) => ManifestLocation::embedded(run.jumbf, run.range, vec![run.range]),
            None => ManifestLocation::none(),
        })
    }
}
