// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

//! Runtime-neutral synchronous adapters for C2PA language bindings.
//!
//! [`read::ReadSessionBridge`] and [`build::BuildSessionBridge`] expose numeric
//! handles and owned, plain-data requests/replies. Their hosts own I/O, clocks,
//! networking, signing and scheduling. Neither bridge awaits, spawns or holds
//! a signing key. Wasm and Neon are consumers, not dependencies.
//!
//! [`compat`] owns the existing JavaScript SDK-shaped settings, errors, format
//! selection and reports. Those are compatibility policy, not generic engine
//! behavior or a universal foreign-function ABI. The bridges currently use
//! that policy and support JPEG and the existing baseline definition.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod build;
pub mod compat;
pub mod read;

pub use compat::{
    C2paError, Context, Error, Manifest, ManifestStore, ValidationState, ValidationStatus,
};
pub use contentauth_c2pa_primitives::Bytes;
