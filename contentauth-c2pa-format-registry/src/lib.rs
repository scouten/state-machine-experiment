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

//! Host-side format detection and run-time handler dispatch.
//!
//! # Where this sits, and why
//!
//! The sans-I/O sessions in this workspace — the reader, the builder, and
//! the file sessions that compose them with a container format — never
//! decide *which* format they are handling. They are generic over a
//! [`FormatHandler`](contentauth_c2pa_format::FormatHandler) the host
//! hands them. This crate is the host's half of that bargain: a
//! [`Registry`] of handlers, to pick one from what the host knows (the
//! asset's first bytes, a file name, a media type), and [`AnyFormat`], a
//! handler that is whichever one was picked.
//!
//! Nothing below the host depends on this crate, and this crate depends
//! on formats only through its optional features: adding a format means
//! writing a crate that implements the contract and registering it — in
//! the host that wants it — and touches no session.
//!
//! # Using it
//!
//! ```
//! use contentauth_c2pa_format::{test_util::MemoryHost, FormatHandler, StreamId};
//! use contentauth_c2pa_format_registry::Registry;
//!
//! let registry = Registry::standard();
//!
//! // The host reads however it likes — here, a byte slice — but only as
//! // much as the registry says it needs…
//! let asset = b"II\x2a\0\x08\0\0\0\x01\0\0\x01\x03\0\x01\0\0\0\x01\0\0\0\0\0\0\0".to_vec();
//! let header = &asset[..asset.len().min(registry.window() as usize)];
//!
//! // …and the content names the format, whatever the file is called.
//! let format = registry.detect(header).expect("a TIFF");
//! assert_eq!(format.descriptor().name, "tiff");
//!
//! // The chosen handler drives like any other.
//! let stream = StreamId::new(0);
//! let location = MemoryHost::new()
//!     .with_stream(stream, asset)
//!     .run(format.locate(stream))?;
//! assert!(location.is_none());
//! # Ok::<(), contentauth_c2pa_format::FormatError>(())
//! ```

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod erased;
mod registry;

pub use erased::{AnyFormat, BoxedOp, DynFormatHandler};
pub use registry::Registry;
