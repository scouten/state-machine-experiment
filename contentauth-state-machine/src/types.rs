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

//! Foundation types shared by every session built on this engine.

use std::fmt;

/// Identifies one outstanding request within a single session.
///
/// Request IDs are unique within a session (never reused, even after the
/// request is fulfilled) but carry no meaning across sessions or between
/// two sessions of different types. The host echoes the ID back when
/// reporting the outcome of a request, which is what lets a session issue
/// several requests at once and accept their outcomes in any order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(pub(crate) u64);

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "request #{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_identifies_the_request() {
        assert_eq!(RequestId(7).to_string(), "request #7");
    }
}
