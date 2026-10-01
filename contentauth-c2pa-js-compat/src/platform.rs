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

//! [`Platform`]: what a read needs from its environment besides the asset.

use contentauth_c2pa_primitives::HostError;

/// The two things a read needs that are not the asset itself: the current
/// time, and (optionally) a way to reach an OCSP responder.
///
/// c2pa-rs obtains both implicitly, from whatever platform it was compiled
/// for — `chrono`/`js_sys::Date` for the clock, `reqwest`/`fetch` for the
/// network — which is why c2pa-wasm's `fromBlob` never mentions either. A
/// sans-I/O engine obtains them from its host, explicitly, so
/// [`crate::Reader::from_blob`] takes a `Platform` as the one argument
/// c2pa-wasm's signature does not have.
///
/// Both operations are `async` for the same reason [`crate::Blob::bytes`]
/// is: a host may well answer them with a `Promise`, and the engine does
/// not care either way. Neither future is required to be `Send`; see
/// [`crate::Blob`] for why.
#[allow(async_fn_in_trait)]
pub trait Platform {
    /// The current time, as seconds since the Unix epoch (UTC) — what the
    /// engine judges certificate validity windows against, absent a
    /// trusted timestamp.
    ///
    /// Failing this is allowed: rather than guess, the engine evaluates
    /// only what a trusted timestamp can vouch for and leaves every other
    /// signer's validity window unevaluated — reported here as
    /// [`ValidationState::Invalid`](crate::ValidationState::Invalid). On
    /// `wasm32-unknown-unknown` there *is* no system clock to fall back
    /// on, which is exactly why this is the host's to answer.
    async fn current_date_time(&self) -> Result<i64, HostError>;

    /// POSTs a DER-encoded OCSP request to `url` and returns the responder's
    /// DER-encoded response, verbatim.
    ///
    /// A platform with no network access — or one that would rather not
    /// make this particular request — fails it, which is safe: online OCSP
    /// checking is fail-open (see
    /// [`ReadSettings::check_ocsp`](contentauth_c2pa_reader::ReadSettings::check_ocsp)),
    /// so the manifest reads exactly as it would have with checking
    /// disabled. A response that *is* returned is judged by the
    /// specification's own, stricter rule, so a platform should only
    /// return bytes a responder actually sent.
    ///
    /// `url` comes from a certificate embedded in whatever asset is being
    /// read — untrusted input. A platform that does make network requests
    /// is responsible for deciding which destinations it is willing to
    /// reach; see `contentauth-c2pa-rs-compat`'s host for what that
    /// involves.
    async fn ocsp(&self, url: &str, request_der: &[u8]) -> Result<Vec<u8>, HostError>;
}

/// A [`Platform`] with the system clock and no network access.
///
/// The natural platform for a native or WASI host that does not want to
/// make OCSP requests. Not available on `wasm32-unknown-unknown`, where
/// [`std::time::SystemTime::now`] has no clock to consult — the `web`
/// feature's `WebPlatform` is the equivalent there, reading
/// `js_sys::Date` instead.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Clone, Copy, Debug, Default)]
pub struct OfflinePlatform;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Platform for OfflinePlatform {
    async fn current_date_time(&self) -> Result<i64, HostError> {
        Ok(unix_seconds(std::time::SystemTime::now()))
    }

    async fn ocsp(&self, _url: &str, _request_der: &[u8]) -> Result<Vec<u8>, HostError> {
        Err(HostError::new(
            "OfflinePlatform has no network access for OCSP",
        ))
    }
}

/// `time` as Unix seconds, falling back to the epoch for a time before it
/// — a hypothetical this crate has no better answer for, and the engine
/// treats as any other implausible time.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn unix_seconds(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;

    /// Polls `future` to completion on the current thread. Both of
    /// `OfflinePlatform`'s futures are ready on their first poll, so a
    /// no-op waker suffices.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    #[test]
    fn the_offline_platform_reports_the_system_clock_as_unix_seconds() {
        let before = unix_seconds(SystemTime::now());
        let reported = block_on(OfflinePlatform.current_date_time()).expect("has a clock");
        let after = unix_seconds(SystemTime::now());

        assert!(
            (before..=after).contains(&reported),
            "{reported} is not between {before} and {after}"
        );
    }

    #[test]
    fn the_offline_platform_declines_ocsp_requests() {
        let result = block_on(OfflinePlatform.ocsp("http://ocsp.example/", &[1, 2, 3]));
        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn unix_seconds_converts_a_time_after_the_epoch() {
        assert_eq!(unix_seconds(UNIX_EPOCH + Duration::from_secs(3_600)), 3_600);
    }

    #[test]
    fn unix_seconds_falls_back_to_the_epoch_for_a_time_before_it() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("this platform can represent an instant before the epoch");
        assert_eq!(unix_seconds(before_epoch), 0);
    }
}
