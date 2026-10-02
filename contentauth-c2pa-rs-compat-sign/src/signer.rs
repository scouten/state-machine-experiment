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
}
