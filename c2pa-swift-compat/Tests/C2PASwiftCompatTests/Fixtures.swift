// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

import Foundation
import CryptoKit
@testable import C2PASwiftCompat

enum Fixtures {
    static var repoRoot: URL {
        var url = URL(fileURLWithPath: #filePath)
        // c2pa-swift-compat/Tests/C2PASwiftCompatTests/Fixtures.swift -> repo root is 4 levels up
        for _ in 0..<4 {
            url.deleteLastPathComponent()
        }
        return url
    }

    static var cJpgData: Data {
        let path = repoRoot.appendingPathComponent("contentauth-c2pa-reader/tests/fixtures/C.jpg")
        return try! Data(contentsOf: path)
    }

    static var testSignerDer: Data {
        let path = repoRoot.appendingPathComponent("contentauth-c2pa-builder/tests/fixtures/test-signer.der")
        return try! Data(contentsOf: path)
    }

    static var testSignerKeyPem: String {
        let path = repoRoot.appendingPathComponent("contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem")
        return try! String(contentsOf: path, encoding: .utf8)
    }

    static var baselineDefinition: String {
        """
        {
          "title": "baseline.jpg",
          "instance_id": "xmp:iid:00000000-0000-4000-8000-000000000001",
          "label": "urn:uuid:00000000-0000-4000-8000-000000000002",
          "claim_generator_info": [
            { "name": "c2pa-swift-compat", "version": "0.1" }
          ],
          "assertions": [
            {
              "label": "c2pa.actions.v2",
              "data": {
                "actions": [
                  {
                    "action": "c2pa.created",
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                  }
                ]
              }
            }
          ]
        }
        """
    }

    static func makeTestSigner() throws -> CryptoKitP256Signer {
        let privateKey = try P256.Signing.PrivateKey(pemRepresentation: testSignerKeyPem)
        return CryptoKitP256Signer(privateKey: privateKey, certificatesDER: [testSignerDer])
    }
}
