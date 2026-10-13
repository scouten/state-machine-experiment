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

//! Error types for the C API.

use thiserror::Error;

/// Errors produced across the C API.
#[derive(Debug, Error)]
pub enum Error {
    /// A required pointer argument was null.
    #[error("null pointer argument: {0}")]
    NullParameter(&'static str),

    /// A string argument was not valid UTF-8.
    #[error("invalid UTF-8 string: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// A string argument contained an interior null byte.
    #[error("interior null byte: {0}")]
    NulError(#[from] std::ffi::NulError),

    /// Format detection or handler error.
    #[error("format error: {0}")]
    Format(String),

    /// Reader engine error.
    #[cfg(feature = "read")]
    #[error("reader error: {0}")]
    Reader(#[from] contentauth_c2pa_file_reader::Error),

    /// Builder engine error.
    #[cfg(feature = "build")]
    #[error("builder error: {0}")]
    Builder(#[from] contentauth_c2pa_file_builder::Error),

    /// Baseline definition error.
    #[cfg(feature = "build")]
    #[error("definition error: {0}")]
    Baseline(#[from] contentauth_c2pa_sign_baseline::Error),

    /// JSON serialization/deserialization error.
    #[cfg(feature = "read")]
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Compatibility layer error.
    #[cfg(feature = "read")]
    #[error("compat error: {0}")]
    JsCompat(#[from] contentauth_c2pa_js_compat::C2paError),

    /// The session was already finished.
    #[error("session has already been finished")]
    AlreadyFinished,

    /// An invalid parameter or state was encountered.
    #[error("bad parameter: {0}")]
    BadParam(String),

    /// A Rust panic occurred.
    #[error("internal panic: {0}")]
    Panic(String),
}

impl From<Error> for cimpl::Error {
    fn from(error: Error) -> Self {
        Self::from_error(error)
    }
}
