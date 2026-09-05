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

//! The shared "the host couldn't do it" error type.

/// Describes a failure that occurred in the host environment while
/// servicing a host request.
///
/// A host reports failures by fulfilling a request with a `Failed(..)`
/// reply carrying one of these. Depending on the request and the workflow,
/// a session may be able to continue (recording a validation status) or
/// may terminate with an error that wraps this one.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
#[non_exhaustive]
pub struct HostError {
    /// Human-readable description of the failure, intended for logs and
    /// error reports.
    pub message: String,
}

impl HostError {
    /// Creates a new host error with the given description.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
