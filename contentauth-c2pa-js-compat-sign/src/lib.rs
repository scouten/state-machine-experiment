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
//! The **JS/Wasm binding** of the baseline signing case (see
//! [`contentauth_c2pa_sign_baseline`]): an async [`Builder`] in the shape
//! of [`contentauth_c2pa_js_compat`]'s reader, whose signer is whatever
//! asynchronous thing the host has — in a browser, usually a `Promise`
//! from WebCrypto, a remote signing service, or a hardware token.
//!
//! # Where the async lives
//!
//! Exactly where it does on the read side: nowhere below [`sign`]'s
//! host loop. [`sign_blob`]'s only `.await` points are the host's
//! answers — a [`Blob`] slice read, or [`AsyncSigner::sign`] — and
//! between two of them the engine hashes, assembles JUMBF and COSE
//! synchronously. The engine, the format handler, and the file-level
//! session ([`contentauth_c2pa_file_builder::FileBuilderSession`]) are
//! the very ones `contentauth_c2pa_rs_compat_sign`'s blocking host
//! drives; only the loop differs.
//!
//! Timestamping follows the same shape: [`AsyncSigner::send_timestamp_request`]
//! is awaited like `sign` — there is no default, since nothing here has a
//! network — and the `web` feature's JavaScript signer takes an optional
//! `sendTimestampRequest` (typically a `fetch`) and `timeAuthorityUrl`.
//!
//! The signing key never needs to enter this crate's address space. That
//! matters most for Wasm: c2pa-rs's own Wasm build has no good answer to
//! "sign with a key held by the browser, or by a server", because its
//! `Signer` trait is synchronous.
//!
//! # Input and output
//!
//! The source is a [`Blob`] (`size` plus an async byte-range read — a
//! `web_sys::Blob` under the `web` feature). The output is a `Vec<u8>`:
//! a browser has no file to write, and the engine reads back what it has
//! written to hash it, so it is assembled in memory — the signed asset,
//! once, not the source.
//!
//! With the `web` feature (compiled only for `wasm32-unknown-unknown`),
//! `web` exports a `WasmBuilder` taking a JavaScript signer object.
//! Nothing there runs under `cargo test`; it is held to
//! `cargo check --target wasm32-unknown-unknown --all-features`.
//!
//! [`sign`]: Builder::sign
//! [`sign_blob`]: Builder::sign

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod builder;
mod drive;
mod error;
mod signer;

#[cfg(all(feature = "web", target_arch = "wasm32", target_os = "unknown"))]
pub mod web;

pub use builder::{Builder, SignedAsset};
pub use contentauth_c2pa_js_compat::Blob;
pub use contentauth_c2pa_primitives::{HostError, SigningAlg};
pub use error::Error;
pub use signer::AsyncSigner;
