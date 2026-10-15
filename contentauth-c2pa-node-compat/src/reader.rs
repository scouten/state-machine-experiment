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

//! [`Reader`]: the result of a finished read, shaped after c2pa-node's JS
//! `Reader` class.

use contentauth_c2pa_file_reader::ReadReport;
use contentauth_c2pa_js_compat::{Manifest, ManifestStore};

/// A validated manifest store, as c2pa-node's `Reader` reports one.
///
/// Like c2pa-node's, a snapshot: everything was read and validated before
/// it existed, and every accessor is synchronous and lock-free
/// and instant. (c2pa-node's reach a `tokio::sync::Mutex` by `block_on`;
/// there is nothing here to lock because nothing else holds this.)
#[derive(Debug)]
pub struct Reader {
    report: ReadReport,
    embedded: bool,
}

impl Reader {
    pub(crate) fn new(report: ReadReport, embedded: bool) -> Self {
        Self { report, embedded }
    }

    /// Borrows retained embedded bytes by their exact absolute self JUMBF URI.
    ///
    /// Unknown or ambiguous identifiers fail, without I/O or implicit fetching.
    /// Hosts copy these bytes into their own output buffers or files.
    pub fn resource_bytes(&self, uri: &str) -> Result<&[u8], crate::Error> {
        contentauth_c2pa_js_compat::resource_bytes(&self.report, uri)
    }

    /// The manifest store as a pretty-printed JSON string — c2pa-node's
    /// `json()`, which is c2pa-rs's `Reader::json`.
    ///
    /// Uses the shared legacy numeric-array formatting; serialization errors
    /// propagate instead of becoming an empty report.
    pub fn json(&self) -> Result<String, serde_json::Error> {
        ManifestStore::from_report(&self.report).json()
    }

    /// The active manifest's label, if any — c2pa-node's `activeLabel()`.
    pub fn active_label(&self) -> Option<String> {
        self.report.active_manifest.clone()
    }

    /// The active manifest, if any — c2pa-node's `getActive()`.
    pub fn active_manifest(&self) -> Option<Manifest> {
        self.report.manifests.last().map(Manifest::from_inner)
    }

    /// The remote manifest URL, or `""` — c2pa-node's `remoteUrl()`.
    ///
    /// Empty for embedded and caller-supplied detached manifest stores.
    pub fn remote_url(&self) -> &str {
        ""
    }

    /// Whether the manifest store was embedded in the asset —
    /// c2pa-node's `isEmbedded()`. False for caller-supplied detached bytes,
    /// even if the asset also contains an embedded store.
    pub fn is_embedded(&self) -> bool {
        self.embedded
    }
}
