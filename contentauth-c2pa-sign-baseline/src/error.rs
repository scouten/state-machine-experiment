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

/// Why a manifest definition could not become builder settings.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The definition is not valid JSON of the shape [`crate::Definition`]
    /// documents (including a field it does not support).
    #[error("invalid manifest definition: {0}")]
    BadDefinition(String),

    /// An assertion's `data` could not be encoded as CBOR.
    #[error("could not encode assertion {label:?}: {message}")]
    Assertion {
        /// The assertion's label.
        label: String,

        /// What went wrong.
        message: String,
    },

    /// The definition has no `claim_generator_info` entry. A v2 claim
    /// requires exactly one.
    #[error("manifest definition needs exactly one claim_generator_info entry")]
    ClaimGenerator,
}
