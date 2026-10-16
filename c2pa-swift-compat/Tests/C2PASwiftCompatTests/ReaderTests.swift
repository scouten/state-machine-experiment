// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

import Testing
import Foundation
@testable import C2PASwiftCompat

struct ReaderTests {
    @Test func readAsyncFromData() async throws {
        let data = Fixtures.cJpgData
        let reader = try await Reader.read(format: "image/jpeg", source: data)

        let label = reader.activeManifestLabel
        #expect(label != nil && !label!.isEmpty)

        let json = reader.json()
        #expect(!json.isEmpty)
        #expect(json.contains("active_manifest"))

        let state = reader.validationState
        // C.jpg is signed with a cert whose trust root is not configured by default
        #expect(state == .valid)
    }

    @Test func readSyncFromStream() throws {
        let data = Fixtures.cJpgData
        let stream = Stream(data: data)
        let reader = try Reader.readSync(format: "image/jpeg", stream: stream)

        let label = reader.activeManifestLabel
        #expect(label != nil && !label!.isEmpty)

        let json = reader.json()
        #expect(!json.isEmpty)
    }

    @Test func readWithCustomContext() async throws {
        let data = Fixtures.cJpgData
        let context = C2PAContext(trustAnchors: [Fixtures.testSignerDer])
        let reader = try await Reader.read(context: context, format: "image/jpeg", source: data)

        let json = reader.json()
        #expect(!json.isEmpty)
    }

    @Test func readNonC2PAImageThrowsJumbfNotFound() async throws {
        // Minimal valid JPEG with no C2PA manifest
        var jpeg = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00])
        jpeg.append(contentsOf: [0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F])
        jpeg.append(contentsOf: [0xFF, 0xD9])

        await #expect(throws: C2PAError.self) {
            try await Reader.read(format: "image/jpeg", source: jpeg)
        }
    }
}
