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

//! An experimental compatibility layer: a slice of c2pa-js's `c2pa-wasm`
//! reader API, reproduced on top of this workspace's sans-I/O read engine
//! — with the asynchrony that API promises living *here*, at the
//! interface-specific layer, rather than anywhere in the engine.
//!
//! # Why
//!
//! [`contentauth-c2pa-rs-compat`](../contentauth_c2pa_rs_compat/index.html)
//! asked how much of c2pa-rs's *synchronous, blocking* `Reader` surface
//! this workspace's engine can reproduce faithfully. This crate asks the
//! same question of the other public surface built on c2pa-rs: the Rust
//! side of the C2PA web SDK, [c2pa-js]'s `c2pa-wasm` package, whose
//! `WasmReader::fromBlob(format, blob, contextJson)` is an `async fn`
//! handed to JavaScript as a `Promise`, followed by synchronous
//! `activeLabel()`, `manifestStore()`, `activeManifest()`, and `json()`
//! accessors.
//!
//! c2pa-wasm is async because c2pa-rs's `Reader::with_stream_async` is
//! async, and c2pa-rs's reader is async because parts of *it* (trust and
//! revocation checks that may reach the network) are. Asset bytes, by
//! contrast, must reach c2pa-rs through a synchronous `Read + Seek`
//! stream — which is why c2pa-wasm's `BlobStream` is built on
//! `FileReaderSync`, an API that exists only inside a Web Worker.
//!
//! This workspace's engine has no opinion about any of that: a
//! [`FileReadSession`](contentauth_c2pa_file_reader::FileReadSession)
//! never blocks, never awaits, and parks itself with a list of requests
//! whenever it needs bytes, the time, or the network. Which layer turns
//! those requests into `.await` points is therefore entirely the host's
//! choice — and this crate makes that choice at the c2pa-wasm-shaped
//! interface, where c2pa-wasm itself makes it. The result is an
//! interface with the same shape as c2pa-wasm's, under which every host
//! interaction — asset bytes *included* — is a real `.await`:
//! [`Reader::from_blob`] can be answered by `Blob.slice().arrayBuffer()`
//! (a `Promise`, available on the main thread) just as readily as by
//! `FileReaderSync`.
//!
//! # The shape
//!
//! * [`Blob`] — the asset, as the two operations a JavaScript `Blob`
//!   actually offers: a synchronous `size` and an asynchronous read of a
//!   byte range. Implemented for `[u8]`/`Vec<u8>` here (always ready), and
//!   for `web_sys::Blob` under the `web` feature.
//! * [`Platform`] — the two things a read needs that are not the asset:
//!   the current time and, optionally, an OCSP transport. c2pa-rs gets
//!   both implicitly from whatever platform it was compiled for; a
//!   sans-I/O engine gets them explicitly, so `from_blob` takes one more
//!   argument than c2pa-wasm's `fromBlob` does.
//! * [`read_manifest`] — the async host itself: the loop that drives a
//!   [`FileReadSession`](contentauth_c2pa_file_reader::FileReadSession),
//!   awaiting the [`Blob`] and [`Platform`] for each request. The only
//!   `.await`s in this crate are in that one function; the engine
//!   underneath it is exactly the synchronous one every other crate here
//!   uses.
//! * [`Reader`] — c2pa-wasm's `WasmReader`, method for method:
//!   [`Reader::from_blob`], [`Reader::active_label`],
//!   [`Reader::manifest_store`], [`Reader::active_manifest`],
//!   [`Reader::json`]. [`Error`] reproduces c2pa-wasm's error-string
//!   contract (`format!("{err:?}")`, which c2pa-web matches on) down to
//!   the `C2pa(JumbfNotFound)` string it turns into `null`.
//! * `web` (feature, `wasm32-unknown-unknown` only) — the browser end of
//!   all of the above: `Blob` for `web_sys::Blob`, a `WebPlatform` clock,
//!   and a `#[wasm_bindgen]`-exported `WasmReader` whose JavaScript
//!   surface (`fromBlob`, `activeLabel`, `manifestStore`,
//!   `activeManifest`, `json`) is c2pa-wasm's own.
//!
//! # What is not covered, and how it would be
//!
//! * **`fromBlobFragment`** — reading a fragmented BMFF asset from an
//!   initialization segment plus one fragment. No fragmented-BMFF
//!   `FormatHandler` exists in this workspace yet; once one does, this is
//!   a second constructor over the same [`read_manifest`] loop with two
//!   [`Blob`]s.
//! * **`resourceToBytes`, `crJson`** — both depend on resource and
//!   thumbnail data [`contentauth_c2pa_reader`] does not decode yet.
//! * **Every format but JPEG** — `src/format.rs` is the seam, exactly as
//!   it is in `contentauth-c2pa-rs-compat`.
//! * **The full `@contentauth/c2pa-types` `ManifestStore` shape** —
//!   ingredients, decoded assertion values, thumbnails. [`ManifestStore`]
//!   carries the top-level contract (a map of manifests keyed by label, an
//!   active label, validation state and status) populated with what the
//!   engine reports today; the rest grows as the engine decodes more.
//! * **A real `fetch`-backed OCSP transport for the browser** — a
//!   [`Platform`] whose `ocsp` posts through `fetch`. `WebPlatform`
//!   declines OCSP today (fail-open, per the engine's own rules); a host
//!   that wants it implements [`Platform`] itself.
//!
//! [c2pa-js]: https://github.com/contentauth/c2pa-js

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod blob;
mod context;
mod drive;
mod error;
mod format;
mod manifest_store;
mod platform;
mod reader;

#[cfg(all(feature = "web", target_arch = "wasm32", target_os = "unknown"))]
pub mod web;

pub use blob::Blob;
pub use context::Context;
pub use drive::read_manifest;
pub use error::{C2paError, Error};
pub use format::{for_format, FORMATS};
pub use manifest_store::{Manifest, ManifestStore, ValidationState, ValidationStatus};
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use platform::OfflinePlatform;
pub use platform::Platform;
pub use reader::Reader;
