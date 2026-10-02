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
/// it existed, and every accessor is synchronous, infallible, lock-free
/// and instant. (c2pa-node's reach a `tokio::sync::Mutex` by `block_on`;
/// there is nothing here to lock because nothing else holds this.)
#[derive(Debug)]
pub struct Reader {
    report: ReadReport,
}

impl Reader {
    pub(crate) fn new(report: ReadReport) -> Self {
        Self { report }
    }

    /// The manifest store as a pretty-printed JSON string — c2pa-node's
    /// `json()`, which is c2pa-rs's `Reader::json`.
    pub fn json(&self) -> String {
        serde_json::to_string_pretty(&ManifestStore::from_report(&self.report))
            .unwrap_or_else(|_| "{}".to_string())
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
    /// Always empty: this engine reads embedded manifest stores only.
    pub fn remote_url(&self) -> &str {
        ""
    }

    /// Whether the manifest store was embedded in the asset —
    /// c2pa-node's `isEmbedded()`. Always `true`; see [`Self::remote_url`].
    pub fn is_embedded(&self) -> bool {
        true
    }
}
