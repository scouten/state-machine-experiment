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

//! An experimental compatibility layer for [c2pa-node]'s reader, built on
//! the opposite premise from [`contentauth-c2pa-js-compat`]: **Rust does no
//! asynchronous work at all, and Node.js does all of it.**
//!
//! # c2pa-node today
//!
//! c2pa-node's Rust side (a [Neon] addon) hands each `Reader.fromAsset`
//! call to a process-wide multi-threaded tokio runtime. The whole read —
//! opening the file, every `Read + Seek` call, hashing, parsing, any OCSP
//! request — runs on a runtime worker thread; the finished `c2pa::Reader`
//! is put behind a `tokio::sync::Mutex` so the synchronous JS accessors
//! (`json()`, `isEmbedded()`, …) can reach it from the JS thread, which
//! they do by `block_on`-ing the lock. Node, the host that owns the event
//! loop, the filesystem, `fetch` and the worker threads, is relegated to
//! carrying arguments in and results out.
//!
//! # This crate
//!
//! A [`NodeSession`] is a plain synchronous object with three methods —
//! [`advance`](NodeSession::advance), [`fulfill`](NodeSession::fulfill) and
//! [`finish`](NodeSession::finish) — which is exactly the engine's own
//! interaction contract, with the engine's types flattened into plain data
//! ([`PendingRequest`], [`Reply`]) that cross an FFI boundary without
//! ceremony. There is no runtime, no thread, no lock, no `async`, and no
//! blocking call anywhere in this crate or below it. Everything that
//! might take time is a [`PendingRequest`] handed *up* to the host:
//!
//! * a byte-range read of the asset — Node answers with
//!   `FileHandle.read()`, which libuv runs on its own thread pool;
//! * the wall clock — `Date.now()`;
//! * an OCSP round trip — Node's `fetch`.
//!
//! The conversation is a loop on the JavaScript side: `advance`; start
//! whichever requests are new, concurrently if it likes (the engine
//! typically has several chunk reads outstanding at once); `fulfill` each
//! as it settles; `advance` again. Which of those happen in parallel, on
//! which thread, with what back-pressure, is entirely Node's business —
//! and the JS thread is only ever busy for the length of one `advance`,
//! which does at most one bounded slice of parsing or hashing.
//!
//! The Neon binding that exposes this to JavaScript, and the JavaScript
//! driver loop itself, live in `c2pa-node-compat-addon/` at the
//! repository root; see its README. They are kept out of this workspace
//! because a Neon `cdylib` cannot link outside a Node process.
//!
//! # Reused, not rewritten
//!
//! c2pa-node and c2pa-wasm both sit on c2pa-rs's `Reader`, so the
//! settings-JSON parsing ([`Context`]), the manifest-store JSON reporting
//! ([`ManifestStore`]) and the error-string contract ([`Error`]) are the
//! very ones `contentauth-c2pa-js-compat` already reproduces. This crate
//! adds only what is specific to c2pa-node: the synchronous session
//! surface and the `Reader` accessors c2pa-node's JS class offers.
//!
//! # What is not covered
//!
//! `fromManifestDataAndAsset` (no detached-manifest read path in the
//! engine yet), `resourceToAsset` (the engine does not decode resources
//! yet), the whole of c2pa-node's `Builder`, signers, identity assertions
//! and Trustmark, and every format but JPEG. A `Builder` counterpart
//! would follow the same shape — `BuilderSession`'s
//! `Sign`/`Timestamp` requests are exactly the ones Node's `CallbackSigner`
//! already answers asynchronously by calling back into JavaScript.
//!
//! [c2pa-node]: https://github.com/contentauth/c2pa-js/tree/main/packages/c2pa-node
//! [Neon]: https://neon-bindings.com
//! [`contentauth-c2pa-js-compat`]: ../contentauth_c2pa_js_compat/index.html

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod reader;
mod session;

pub use contentauth_c2pa_js_compat::{
    C2paError, Context, Error, Manifest, ManifestStore, ValidationState, ValidationStatus,
};
pub use reader::Reader;
pub use session::{NodeSession, PendingRequest, Reply, Step};
