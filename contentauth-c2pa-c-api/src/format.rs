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

use contentauth_c2pa_format_registry::{AnyFormat, Registry};

use crate::Error;

pub(crate) fn resolve_format(format_str: &str) -> Result<AnyFormat, Error> {
    let registry = Registry::standard();
    let lower = format_str.to_ascii_lowercase();
    let normalized = match lower.as_str() {
        "image/jpg" => "image/jpeg",
        other => other,
    };
    registry
        .by_mime(normalized)
        .or_else(|| registry.by_extension(normalized))
        .cloned()
        .ok_or_else(|| Error::Format(format!("unsupported format: {format_str}")))
}
