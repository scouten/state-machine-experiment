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

//! The **baseline signing case**: the smallest manifest worth generating,
//! defined once so every language binding of the signing path can be held
//! to the same bar.
//!
//! # The case
//!
//! Take a JPEG. Describe a manifest for it as c2pa-rs-shaped JSON
//! ([`BASELINE_DEFINITION`]): a title, one claim generator, and exactly
//! one assertion — `c2pa.actions.v2` with a single `c2pa.created` action.
//! Sign it with ES256 and a certificate chain the host holds. The result
//! must be a JPEG whose `APP11` segments carry a manifest store that
//! `contentauth-c2pa-reader` validates as `Trusted` against that chain,
//! whose active manifest has the label, title and assertions put in, and
//! whose hard binding excludes exactly the reported manifest range.
//!
//! That is deliberately *all*: no ingredients, thumbnails, timestamp, or
//! second assertion. What it exercises is every seam a signing binding
//! has — definition in, a host-held signing key reached through whatever
//! asynchrony the binding's language imposes, an asset in, an asset out —
//! so the differences between bindings are the differences that matter.
//!
//! # What this crate is
//!
//! Only the part of that which has no language in it: parsing the
//! definition ([`Definition`]) and turning it, plus what a signer
//! supplies (an algorithm and a chain), into the engine's
//! [`BuilderSettings`]. Bindings differ in how they reach the signer and
//! the asset, never in how a definition becomes a manifest.
//!
//! What the definition does *not* carry is randomness: `instance_id` and
//! `label` are required, because the engine holds no RNG and neither
//! does this crate; the host mints them (a UUID, typically).
//!
//! With the `fixtures` feature, [`fixtures`] exposes the test signer
//! and JPEG the repository's other crates already test with.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod definition;
mod error;

#[cfg(feature = "fixtures")]
pub mod fixtures;

pub use contentauth_c2pa_builder::{BuilderSettings, SigningAlg};
pub use definition::{AssertionDefinition, ClaimGenerator, Definition, BASELINE_DEFINITION};
pub use error::Error;
