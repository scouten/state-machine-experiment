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

//! An experimental Node.js binding of the baseline signing case (see
//! [`contentauth_c2pa_sign_baseline`]), built on the same premise as
//! `contentauth-c2pa-node-compat`'s reader: **Rust does no asynchronous work
//! at all, and Node.js does all of it** — including holding the signing key.
//!
//! [`NodeBuildSession`] is a purely synchronous
//! `advance`/`fulfill`/`finish` wrapper over
//! [`FileBuilderSession`](contentauth_c2pa_file_builder::FileBuilderSession),
//! with the engine's types flattened to plain data ([`PendingRequest`],
//! [`Reply`]). Node owns the event loop, the source and output files, and
//! the key: a [`PendingRequest::Sign`] is just another request, answered
//! whenever a `Promise` (a KMS call, an HSM, WebCrypto) settles.
//!
//! Only JPEG is supported, and no timestamping: the engine would issue a
//! `Timestamp` request, but the baseline never asks for one, and this
//! wrapper reports it as [`Error::Unsupported`] rather than guess.
//!
//! The driving loop is exactly the reader's:
//!
//! ```no_run
//! # use contentauth_c2pa_node_compat_sign::{NodeBuildSession, Step};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (json, cert) = (String::new(), Vec::new());
//! let mut session = NodeBuildSession::new(&json, "image/jpeg", "es256", vec![cert])?;
//! while let Step::Pending(requests) = session.advance()? {
//!     for request in requests {
//!         // read / write / sign ... then session.fulfill(request.id(), reply)?;
//!     }
//! }
//! let report = session.finish()?;
//! # Ok(()) }
//! ```

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod error;
mod session;

pub use error::Error;
pub use session::{NodeBuildSession, PendingRequest, Reply, SignReport, Step, Stream};
