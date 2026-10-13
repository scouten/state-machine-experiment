//! Loadable browser packaging for the existing sans-I/O reader and signer hosts.
//!
//! The exported classes only delegate to the compatibility crates; no decoding,
//! validation, signing, or container policy is implemented here.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod web;
