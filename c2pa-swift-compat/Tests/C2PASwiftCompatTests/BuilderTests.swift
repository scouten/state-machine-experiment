// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

import Testing
import Foundation
@testable import C2PASwiftCompat

struct BuilderTests {
    @Test func signAndReadBackTrusted() async throws {
        // Source image (C.jpg)
        let sourceData = Fixtures.cJpgData
        let destination = InMemoryByteStream()

        let signer = try Fixtures.makeTestSigner()
        let definition = Fixtures.baselineDefinition

        // Sign the asset
        try await Builder.sign(
            format: "image/jpeg",
            manifestJson: definition,
            source: sourceData,
            destination: destination,
            signer: signer
        )

        let signedBytes = await destination.data()
        #expect(!signedBytes.isEmpty)
        #expect(signedBytes.count > 10_000)

        // Read back with trust anchor set to testSignerDer
        let context = C2PAContext(trustAnchors: [Fixtures.testSignerDer])
        let reader = try await Reader.read(context: context, format: "image/jpeg", source: signedBytes)

        let label = reader.activeManifestLabel
        #expect(label == "urn:uuid:00000000-0000-4000-8000-000000000002")

        let state = reader.validationState
        #expect(state == .trusted)

        let json = reader.json()
        #expect(json.contains("c2pa-swift-compat"))
    }
}
