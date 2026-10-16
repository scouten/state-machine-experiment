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

/// C2PA configuration context governing trust anchors and network access.
public final class C2PAContext: Sendable {
    /// DER-encoded trust anchor certificates.
    public let trustAnchors: [Data]

    /// PEM-formatted trust anchor certificate bundle.
    public let trustAnchorsPEM: String?

    /// URLSession used for asynchronous OCSP revocation queries and TSA timestamps.
    public let urlSession: URLSession

    /// Whether to perform online OCSP revocation checks.
    public let checkOcsp: Bool

    /// Initializes a context with optional PEM bundle, trust anchors, and URLSession.
    public init(
        trustAnchorsPEM: String? = nil,
        trustAnchors: [Data] = [],
        checkOcsp: Bool = false,
        urlSession: URLSession = .shared
    ) {
        self.trustAnchorsPEM = trustAnchorsPEM
        self.trustAnchors = trustAnchors
        self.checkOcsp = checkOcsp
        self.urlSession = urlSession
    }

    /// Serializes context settings into a JSON string formatted for the engine.
    func settingsJSON() throws -> String? {
        var pemBundle = trustAnchorsPEM ?? ""
        if !trustAnchors.isEmpty {
            for der in trustAnchors {
                let base64 = der.base64EncodedString(options: [.lineLength64Characters])
                pemBundle += "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
            }
        }

        if pemBundle.isEmpty && !checkOcsp {
            return nil
        }

        var dict: [String: Any] = [:]
        if !pemBundle.isEmpty {
            dict["trust"] = [
                "anchors": [
                    [
                        "trust_anchors": pemBundle,
                        "trust_kind": "manifest"
                    ]
                ]
            ]
        }
        dict["verify"] = [
            "ocsp_fetch": checkOcsp
        ]

        let data = try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
        return String(data: data, encoding: .utf8)
    }
}
