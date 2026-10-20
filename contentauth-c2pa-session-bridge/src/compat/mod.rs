//! Compatibility policy shared by bindings and the alternative async Rust host.
//!
//! These conversions retain the existing SDK-shaped contracts. Other languages
//! can adapt them, but need not adopt them to drive the underlying typed sessions.

pub mod context;
pub mod error;
pub mod format;
pub mod manifest_store;

pub use context::Context;
pub use error::{C2paError, Error};
pub use format::{detect, detect_window, for_format, FORMATS};
pub use manifest_store::{
    ClaimGeneratorInfo, Manifest, ManifestStore, ValidationState, ValidationStatus,
};
