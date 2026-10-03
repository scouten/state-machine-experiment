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

/// Something that holds a signing key, shaped after c2pa-rs's `Signer`.
pub trait Signer {
    /// The algorithm this signer signs with.
    fn alg(&self) -> SigningAlg;

    /// The DER certificate chain, signer's own certificate first.
    fn certs(&self) -> Vec<Vec<u8>>;

    /// Signs `data` (a COSE `Sig_structure`) and returns the raw
    /// signature, in the form COSE wants for `alg` (for ECDSA, the
    /// fixed-width `r || s`, not DER).
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HostError>;

    /// The URL of an RFC 3161 time-stamp authority to countersign claim
    /// signatures with, as c2pa-rs's `Signer::time_authority_url`. `None`
    /// (the default) means no timestamp, unless the definition's `tsa_url`
    /// asks for one — which then takes precedence.
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// Sends one RFC 3161 request to the authority at `url`: `request` is a
    /// DER `TimeStampReq`, and the result must be the DER `TimeStampResp`
    /// it answers with.
    ///
    /// The default POSTs it over HTTP (`application/timestamp-query`);
    /// override it to reach an authority some other way — a proxy, a
    /// client certificate, an in-process fake. Unlike c2pa-rs's
    /// `send_timestamp_request`, which receives the bytes to timestamp and
    /// builds the request itself, this receives the request already built
    /// and unwraps the token afterwards, so an override is only transport.
    fn send_timestamp_request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, HostError> {
        crate::tsa::post(url, request)
    }
}
