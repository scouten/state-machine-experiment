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

//! An experimental compatibility layer: a slice of c2pa-rs's public
//! `Reader` API, reproduced on top of this workspace's sans-I/O read
//! engine rather than c2pa-rs's own `Store`.
//!
//! # Why
//!
//! Every other crate in this workspace exposes its own, new interaction
//! contract (`Session`/`advance`/`fulfill`/`finish` — see the root
//! `CLAUDE.md`). That is the right shape for a host willing to adopt it,
//! but it is not a drop-in replacement for an application already written
//! against c2pa-rs. This crate explores the other direction: how much of
//! c2pa-rs's existing, synchronous, blocking-I/O `Reader` surface can be
//! reproduced *faithfully* — same method names, same signatures where
//! std's ownership rules allow it, same error/JSON contracts — while
//! everything underneath it is this workspace's engine. A caller that
//! only needs [`Reader::from_context`]/[`Reader::json`] should not be able
//! to tell the difference; one that reaches for a part of c2pa-rs's
//! surface this crate has not built yet has a clear seam to extend rather
//! than a rewrite to do.
//!
//! # What this covers
//!
//! One use case, worked through end to end: **read and validate a C2PA
//! manifest store embedded in a local JPEG file, and report the result as
//! JSON** — [`Context::new`] configuring trust anchors,
//! [`Reader::from_context`] and [`Reader::with_file`], then
//! [`Reader::json`], [`Reader::validation_state`], or the borrowed
//! [`Manifest`] accessors. That case was chosen because it is the one most
//! c2pa-rs integrations reach for first, and because every piece it needs
//! — [`contentauth_c2pa_file_reader::read_manifest_from_file`], a
//! [`contentauth_c2pa_format_jpeg::JpegFormat`] handler, and
//! [`contentauth_c2pa_reader`]'s validation — already exists in this
//! workspace; this crate's own work is entirely the compatibility surface
//! ([`Context`], `Reader`, [`Manifest`], [`ValidationState`],
//! [`ValidationStatus`], [`Error`], and the JSON shape in `src/json.rs`),
//! not new read or validation logic.
//!
//! The `Context`/`Reader::from_context`/`with_file` shape is deliberately
//! the preferred one here, not merely one of several equally-supported
//! paths: it's what c2pa-rs's own docs now recommend over the (deprecated,
//! but still present, on both sides) standalone `Reader::from_file`. See
//! [`Context`]'s own docs for what it configures and what it deliberately
//! leaves out of c2pa-rs's own, much larger `Context`.
//!
//! # What is not covered, and how it would be
//!
//! * **`Reader::from_stream`** and the other constructors — trivial to add
//!   alongside [`Reader::with_file`]: swap
//!   [`contentauth_c2pa_file_reader::read_manifest_from_file`] for
//!   [`contentauth_c2pa_file_reader::read_manifest`], which already takes
//!   any `Read + Seek`, and drop the file-extension-based format lookup in
//!   `src/format.rs` for a caller-supplied format hint instead.
//! * **More container formats** — `src/format.rs` is the seam: it is the
//!   only place this crate names [`contentauth_c2pa_format_jpeg::JpegFormat`]
//!   specifically. A second `contentauth-c2pa-format-*` handler crate (see
//!   the root `CLAUDE.md`) plugs in there, same as it would for any other
//!   host in this workspace.
//! * **A `Builder` counterpart** — the write-side use case (build, sign,
//!   and embed a manifest into a file) would follow the same shape,
//!   wrapping `contentauth_c2pa_file_builder::build_and_sign_file` behind
//!   a `Builder`/`Signer` compat surface, in its own module here or its
//!   own crate. Deliberately not attempted alongside this one: the two use
//!   cases don't share code, and working through one first is what this
//!   experiment asked for.
//! * **The full `Manifest`/`Ingredient` object graph, thumbnails,
//!   resources, `to_folder`** — all downstream of assertion *values* being
//!   decoded, which [`contentauth_c2pa_reader`] does not do yet (it reads
//!   assertion labels and hashes for integrity, not their content). Once it
//!   does, [`Manifest`] grows accessors for them the same way it already
//!   exposes `title`/`format`/`instance_id`.
//! * **Ingredients, remote manifests, revocation** — not yet modeled by
//!   [`contentauth_c2pa_reader`] itself (see its own README's "not yet
//!   checked" list), so there's nothing here yet to make compatible.
//!
//! None of that is a design decision baked into this crate's shape — it's
//! simply the boundary of "one use case, worked through," per the brief.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod context;
mod error;
mod format;
mod json;
mod manifest;
mod reader;
mod validation;

// Re-exported so a caller configuring trust anchors does not also need a
// direct dependency on `contentauth-c2pa-file-reader` just for this type.
pub use contentauth_c2pa_file_reader::ReadSettings;
pub use context::Context;
pub use error::Error;
pub use manifest::Manifest;
pub use reader::Reader;
pub use validation::{ValidationState, ValidationStatus};
