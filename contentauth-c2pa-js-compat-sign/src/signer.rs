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
}
