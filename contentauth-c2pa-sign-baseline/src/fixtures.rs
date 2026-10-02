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

//! Test material shared by every binding's tests, so they all start from
//! byte-identical inputs. The signer is self-signed and its key protects
//! nothing.

/// The test signer's DER certificate: both the sole chain entry and the
/// trust anchor tests configure the reader with.
pub const TEST_SIGNER_CERT: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.der");

/// The test signer's PKCS#8 PEM private key (ES256).
pub const TEST_SIGNER_KEY_PEM: &[u8] =
    include_bytes!("../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem");

/// A real JPEG already carrying a c2pa-rs manifest store, which signing
/// replaces.
pub const SOURCE_JPEG: &[u8] = include_bytes!("../../contentauth-c2pa-reader/tests/fixtures/C.jpg");

/// Where [`SOURCE_JPEG`] lives, relative to the repository root, for
/// bindings (Node) that read it from disk.
pub const SOURCE_JPEG_PATH: &str = "contentauth-c2pa-reader/tests/fixtures/C.jpg";
