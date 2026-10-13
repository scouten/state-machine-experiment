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

//! C API for synchronous, sans-I/O C2PA reading and signing workflows.
//!
//! Exposes a callback-free, thread-free, runtime-free C ABI over
//! [`FileReadSession`](contentauth_c2pa_file_reader::FileReadSession) and
//! [`FileBuilderSession`](contentauth_c2pa_file_builder::FileBuilderSession).
//!
//! # Architecture
//!
//! - **No threads**: The library never spawns threads, schedules background work,
//!   or manages task pools.
//! - **No host-I/O waits**: Session work never reads, writes, signs, timestamps,
//!   or performs network I/O. cimpl serializes handle borrows and can briefly
//!   wait if the same handle is used concurrently; hosts should drive each
//!   session from one task at a time.
//! - **No callbacks**: The session parks with plain request structures describing
//!   what it needs from the host. The host answers by calling fulfillment functions.
//! - **QoS and scheduling owned by host**: Work runs synchronously inside
//!   host-initiated calls, so Rust creates no worker threads and does not
//!   change the caller's QoS.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]

pub mod build;
pub mod error;
pub mod ffi;
pub mod read;

pub use build::{
    BuildSession, C2paSmBuildRequest, C2paSmExclusion, C2PA_SM_BUILD_REQ_LENGTH,
    C2PA_SM_BUILD_REQ_READ, C2PA_SM_BUILD_REQ_SIGN, C2PA_SM_BUILD_REQ_TIMESTAMP,
    C2PA_SM_BUILD_REQ_WRITE, C2PA_SM_STREAM_OUTPUT, C2PA_SM_STREAM_SOURCE,
};
pub use error::Error;
pub use ffi::*;
pub use read::{
    C2paSmReadRequest, ReadSession, C2PA_SM_READ_REQ_CURRENT_DATE_TIME, C2PA_SM_READ_REQ_LENGTH,
    C2PA_SM_READ_REQ_OCSP, C2PA_SM_READ_REQ_READ, C2PA_SM_STEP_COMPLETE, C2PA_SM_STEP_ERROR,
    C2PA_SM_STEP_PENDING,
};
