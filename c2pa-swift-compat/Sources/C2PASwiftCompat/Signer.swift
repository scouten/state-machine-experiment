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

import Foundation
import CryptoKit

/// Supported signing algorithms.
public enum SigningAlgorithm: String, Sendable {
    case es256 = "es256"
    case es384 = "es384"
    case es512 = "es512"
    case ps256 = "ps256"
    case ps384 = "ps384"
    case ps512 = "ps512"
    case ed25519 = "ed25519"
}

/// Asynchronous cryptographic signer protocol.
///
/// Implementations may run in Secure Enclave, Keychain, Cloud KMS,
/// or web services without blocking any Swift concurrency executor threads.
public protocol AsyncSigner: Sendable {
    /// Signing algorithm.
    var algorithm: SigningAlgorithm { get }

    /// DER-encoded certificate chain (leaf first).
    var certificatesDER: [Data] { get }

    /// Cryptographically signs `data` and returns the raw signature bytes.
    func sign(_ data: Data) async throws -> Data
}

/// Synchronous signer adapter conforming to AsyncSigner.
public struct Signer: AsyncSigner {
    public let algorithm: SigningAlgorithm
    public let certificatesDER: [Data]
    private let signHandler: @Sendable (Data) throws -> Data

    public init(
        algorithm: SigningAlgorithm,
        certificatesDER: [Data],
        sign: @escaping @Sendable (Data) throws -> Data
    ) {
        self.algorithm = algorithm
        self.certificatesDER = certificatesDER
        self.signHandler = sign
    }

    public func sign(_ data: Data) async throws -> Data {
        return try signHandler(data)
    }
}

/// Built-in P-256 (ES256) signer using Apple's CryptoKit framework.
public struct CryptoKitP256Signer: AsyncSigner {
    public let algorithm: SigningAlgorithm = .es256
    public let certificatesDER: [Data]
    private let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey, certificatesDER: [Data]) {
        self.privateKey = privateKey
        self.certificatesDER = certificatesDER
    }

    public func sign(_ data: Data) async throws -> Data {
        let signature = try privateKey.signature(for: data)
        return signature.rawRepresentation
    }
}
