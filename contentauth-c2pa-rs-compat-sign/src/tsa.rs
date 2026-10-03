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
//! The default network half of a timestamp round trip: an HTTP `POST` of a
//! DER `TimeStampReq` to the authority, per RFC 3161 §3.4. Encoding the
//! request and unwrapping the response are
//! `contentauth_c2pa_primitives::tsa`'s; this is only the transport,
//! which is why it lives in the one signing crate that may have a network
//! dependency (compare `contentauth-c2pa-rs-compat`'s OCSP host).
//!
//! The URL comes from the signing party — the definition's `tsa_url` or the
//! signer — never from an untrusted asset, so unlike an OCSP responder URL
//! (which a certificate in the asset chooses) it needs no SSRF safeguard
//! beyond being restricted to `http`/`https` when the definition is parsed.

use std::{io::Read, time::Duration};

use contentauth_c2pa_primitives::HostError;

/// More than any real token plus a certificate chain; a bound so a
/// misbehaving authority cannot make this buffer without limit.
const MAX_RESPONSE: u64 = 1024 * 1024;

const TIMEOUT: Duration = Duration::from_secs(30);

/// POSTs `request` to `url`, returning the response body.
pub(crate) fn post(url: &str, request: &[u8]) -> Result<Vec<u8>, HostError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|err| HostError::new(format!("could not build an HTTP client: {err}")))?;

    let response = client
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .body(request.to_vec())
        .send()
        .map_err(|err| HostError::new(format!("timestamp request to {url} failed: {err}")))?;

    if !response.status().is_success() {
        return Err(HostError::new(format!(
            "the timestamp authority at {url} answered {}",
            response.status()
        )));
    }

    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut body)
        .map_err(|err| HostError::new(format!("could not read the timestamp response: {err}")))?;
    if body.len() as u64 > MAX_RESPONSE {
        return Err(HostError::new(
            "the timestamp response is implausibly large",
        ));
    }
    Ok(body)
}
