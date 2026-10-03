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
use contentauth_c2pa_primitives::{HostError, SigningAlg};

/// A signer whose signature may take its time: shaped after the
/// synchronous `Signer` in `contentauth-c2pa-rs-compat-sign`, with only
/// `sign` asynchronous.
///
/// `async fn` in a trait, with no `Send` bound: like [`Blob`](crate::Blob),
/// the futures here are meant for a single-threaded executor such as a
/// browser's.
#[allow(async_fn_in_trait)]
pub trait AsyncSigner {
    /// The algorithm this signer signs with.
    fn alg(&self) -> SigningAlg;

    /// The DER certificate chain, signer's own certificate first.
    fn certs(&self) -> Vec<Vec<u8>>;

    /// Signs `data` (a COSE `Sig_structure`) and returns the raw
    /// signature as COSE wants it for `alg` (for ECDSA, fixed-width
    /// `r || s` — which is what WebCrypto's `crypto.subtle.sign` returns,
    /// unlike Node's default DER).
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError>;

    /// The URL of an RFC 3161 time-stamp authority to countersign claim
    /// signatures with. `None` (the default) means no timestamp, unless
    /// the definition's `ta_url` asks for one — which then takes
    /// precedence.
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// Sends one RFC 3161 request to the authority at `url`: `request` is
    /// a DER `TimeStampReq`, and the result must be the DER
    /// `TimeStampResp` it answers with — in a browser, a `fetch` `POST`
    /// with `Content-Type: application/timestamp-query`.
    ///
    /// Unlike the blocking sibling crate's, there is no default: nothing
    /// below this crate touches a network, so a signer that is asked for a
    /// timestamp must say how to get one. The default fails the build.
    async fn send_timestamp_request(
        &self,
        url: &str,
        _request: &[u8],
    ) -> Result<Vec<u8>, HostError> {
        Err(HostError::new(format!(
            "this signer cannot reach the time-stamp authority at {url}; \
             implement send_timestamp_request"
        )))
    }
}
