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
//! An experimental compatibility layer reproducing a slice of
//! [c2pa-rs](https://github.com/contentauth/c2pa-rs)'s signing API —
//! `Builder::from_json`, `Builder::sign`, `Builder::sign_file` and the
//! `Signer` trait — over this workspace's sans-I/O build engine.
//!
//! This is the *synchronous Rust* binding of the baseline signing case
//! (see [`contentauth_c2pa_sign_baseline`]), and the simplest one: the
//! caller's ordinary `Read + Seek` / `Write` types answer every I/O request,
//! and a blocking [`Signer`] answers the one signature the claim needs.
//!
//! ```no_run
//! # use contentauth_c2pa_rs_compat_sign::{Builder, Signer, SigningAlg, HostError};
//! # struct MySigner;
//! # impl Signer for MySigner {
//! #     fn alg(&self) -> SigningAlg { SigningAlg::Es256 }
//! #     fn certs(&self) -> Vec<Vec<u8>> { vec![] }
//! #     fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, HostError> { Ok(vec![]) }
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let builder = Builder::from_json(
//!     r#"{ "instance_id": "xmp:iid:1",
//!     "label": "urn:uuid:1",
//!     "claim_generator_info": [{ "name": "app", "version": "1" }] }"#,
//! )?;
//! builder.sign_file(&MySigner, "in.jpg", "out.jpg")?;
//! # Ok(()) }
//! ```
//!
//! # Where this differs from c2pa-rs
//!
//! * `instance_id` and `label` are required in the definition JSON: the
//!   engine has no RNG, so the host mints them.
//! * [`Signer::certs`] is infallible and [`Signer::sign`] reports a
//!   [`HostError`]; no `reserve_size`, no async signer — the engine can do
//!   some of that, but this baseline deliberately does not.
//! * Timestamping is on when the definition has `ta_url` or the signer
//!   reports [`Signer::time_authority_url`]. The request is sent by
//!   [`Signer::send_timestamp_request`], whose default is a blocking HTTP
//!   `POST` — which makes this crate, like `contentauth-c2pa-rs-compat`,
//!   one with a network dependency (and so not Wasm-portable).
//! * Only JPEG.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod builder;
mod error;
mod signer;
mod tsa;

pub use builder::Builder;
pub use contentauth_c2pa_file_builder::FileBuilderReport as SignReport;
pub use contentauth_c2pa_primitives::{HostError, SigningAlg};
pub use error::Error;
pub use signer::Signer;
