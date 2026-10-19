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
import CContentauthC2pa

/// Exclusion range identifying bytes outside the hard binding hash.
public struct ExclusionRange: Sendable, Equatable {
    /// Starting byte offset in output asset.
    public let start: UInt64
    /// Byte length.
    public let length: UInt64

    public init(start: UInt64, length: UInt64) {
        self.start = start
        self.length = length
    }
}

/// Result returned upon successfully building and signing a manifest store.
public struct SignResult: Sendable {
    /// JUMBF manifest store bytes embedded into the asset.
    public let manifest: Data
    /// Byte exclusion ranges recorded in the manifest's hard binding.
    public let exclusions: [ExclusionRange]

    public init(manifest: Data, exclusions: [ExclusionRange]) {
        self.manifest = manifest
        self.exclusions = exclusions
    }
}

/// Asynchronous C2PA manifest builder and signer.
public final class Builder: Sendable {
    /// Manifest definition JSON string.
    public let manifestJSON: String

    public init(manifestJSON: String) {
        self.manifestJSON = manifestJSON
    }

    /// Builds and cryptographically signs a C2PA manifest store, embedding it into the output destination.
    public func sign(
        format: String,
        source: any AsyncByteSource,
        destination: any AsyncByteSource & AsyncByteSink,
        signer: any AsyncSigner,
        urlSession: URLSession = .shared
    ) async throws -> SignResult {
        var errOut: UnsafeMutablePointer<CChar>? = nil

        let certs = signer.certificatesDER
        guard !certs.isEmpty else {
            throw C2PAError.invalidParameter("Signer must provide at least one certificate")
        }

        // Prepare pointers for certificates.
        var certPtrs: [UnsafePointer<UInt8>?] = []
        var certLens: [UInt] = []
        var retainedData: [Data] = []

        for cert in certs {
            retainedData.append(cert)
        }

        for i in 0..<retainedData.count {
            retainedData[i].withUnsafeBytes { raw in
                let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
                certPtrs.append(ptr)
                certLens.append(UInt(retainedData[i].count))
            }
        }

        let session: OpaquePointer? = format.withCString { fmtCStr in
            manifestJSON.withCString { defCStr in
                signer.algorithm.rawValue.withCString { algCStr in
                    certPtrs.withUnsafeBufferPointer { ptrsBuf in
                        certLens.withUnsafeBufferPointer { lensBuf in
                            c2pa_sm_build_new(
                                fmtCStr,
                                defCStr,
                                algCStr,
                                ptrsBuf.baseAddress,
                                lensBuf.baseAddress,
                                UInt(certs.count),
                                &errOut
                            )
                        }
                    }
                }
            }
        }

        if let err = checkAndFreeError(&errOut) {
            throw err
        }
        guard let session = session else {
            throw C2PAError.internalError("Failed to allocate build session")
        }
        defer {
            c2pa_sm_build_free(session)
        }

        while true {
            try Task.checkCancellation()

            var requestsPtr: UnsafePointer<C2paSmBuildRequest>? = nil
            var requestCount: Int = 0

            let step = c2pa_sm_build_advance(session, &requestsPtr, &requestCount, &errOut)
            if let err = checkAndFreeError(&errOut) {
                throw err
            }

            if step == C2PA_SM_STEP_COMPLETE {
                break
            }
            if step == C2PA_SM_STEP_ERROR {
                throw C2PAError.internalError("Engine reported step error during build")
            }

            guard let reqs = requestsPtr, requestCount > 0 else {
                throw C2PAError.internalError("Build session parked without requests")
            }

            let requestBuffer = UnsafeBufferPointer(start: reqs, count: requestCount)
            for req in requestBuffer {
                try Task.checkCancellation()

                switch req.kind {
                case UInt32(C2PA_SM_BUILD_REQ_LENGTH):
                    guard req.stream == UInt32(C2PA_SM_STREAM_SOURCE) else {
                        throw C2PAError.internalError("Length requested for unexpected stream: \(req.stream)")
                    }
                    let len = try await source.length()
                    let rc = c2pa_sm_build_fulfill_length(session, req.id, len, &errOut)
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("build fulfill_length failed") }

                case UInt32(C2PA_SM_BUILD_REQ_READ):
                    let data: Data
                    if req.stream == UInt32(C2PA_SM_STREAM_SOURCE) {
                        data = try await source.read(at: req.offset, count: Int(req.len))
                    } else if req.stream == UInt32(C2PA_SM_STREAM_OUTPUT) {
                        data = try await destination.read(at: req.offset, count: Int(req.len))
                    } else {
                        throw C2PAError.internalError("Read requested for unknown stream: \(req.stream)")
                    }

                    let rc: Int32 = data.withUnsafeBytes { rawBuf in
                        let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        return c2pa_sm_build_fulfill_bytes(session, req.id, ptr, UInt(data.count), &errOut)
                    }
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("build fulfill_bytes failed") }

                case UInt32(C2PA_SM_BUILD_REQ_WRITE):
                    guard req.stream == UInt32(C2PA_SM_STREAM_OUTPUT) else {
                        throw C2PAError.internalError("Write requested for non-output stream: \(req.stream)")
                    }
                    let dataToWrite: Data
                    if let ptr = req.data, req.len > 0 {
                        dataToWrite = Data(bytes: ptr, count: Int(req.len))
                    } else {
                        dataToWrite = Data()
                    }
                    try await destination.write(at: req.offset, data: dataToWrite)

                    let rc = c2pa_sm_build_fulfill_written(session, req.id, &errOut)
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("build fulfill_written failed") }

                case UInt32(C2PA_SM_BUILD_REQ_SIGN):
                    guard let ptr = req.data, req.data_len > 0 else {
                        throw C2PAError.internalError("Sign request missing data")
                    }
                    let dataToSign = Data(bytes: ptr, count: Int(req.data_len))
                    let signature = try await signer.sign(dataToSign)

                    let rc: Int32 = signature.withUnsafeBytes { rawBuf in
                        let sigPtr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        return c2pa_sm_build_fulfill_signature(session, req.id, sigPtr, UInt(signature.count), &errOut)
                    }
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("build fulfill_signature failed") }

                case UInt32(C2PA_SM_BUILD_REQ_TIMESTAMP):
                    guard let urlStr = req.url.map({ String(cString: $0) }),
                          let url = URL(string: urlStr) else {
                        let _ = "invalid TSA URL".withCString { msgCStr in
                            c2pa_sm_build_fulfill_failed(session, req.id, msgCStr, &errOut)
                        }
                        continue
                    }

                    guard let reqPtr = req.data, req.data_len > 0 else {
                        let _ = "missing TSA request body".withCString { msgCStr in
                            c2pa_sm_build_fulfill_failed(session, req.id, msgCStr, &errOut)
                        }
                        continue
                    }

                    let bodyData = Data(bytes: reqPtr, count: Int(req.data_len))
                    var urlReq = URLRequest(url: url)
                    urlReq.httpMethod = "POST"
                    urlReq.setValue("application/timestamp-query", forHTTPHeaderField: "Content-Type")
                    urlReq.httpBody = bodyData

                    do {
                        let (respData, _) = try await urlSession.data(for: urlReq)
                        let rc: Int32 = respData.withUnsafeBytes { rawBuf in
                            let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                            return c2pa_sm_build_fulfill_timestamp(session, req.id, ptr, UInt(respData.count), &errOut)
                        }
                        if let err = checkAndFreeError(&errOut) { throw err }
                        if rc != 0 { throw C2PAError.internalError("fulfill_timestamp failed") }
                    } catch {
                        let _ = error.localizedDescription.withCString { msgCStr in
                            c2pa_sm_build_fulfill_failed(session, req.id, msgCStr, &errOut)
                        }
                    }

                default:
                    throw C2PAError.internalError("Unknown build request kind: \(req.kind)")
                }
            }
        }

        var manifestPtr: UnsafeMutablePointer<UInt8>? = nil
        var manifestLen: Int = 0
        var exclusionsPtr: OpaquePointer? = nil
        var exclusionsCount: Int = 0

        let rc = c2pa_sm_build_finish(
            session,
            &manifestPtr,
            &manifestLen,
            &exclusionsPtr,
            &exclusionsCount,
            &errOut
        )
        if let err = checkAndFreeError(&errOut) {
            throw err
        }
        if rc != 0 {
            throw C2PAError.internalError("build_finish returned error code \(rc)")
        }

        guard let mPtr = manifestPtr, manifestLen > 0 else {
            throw C2PAError.internalError("build_finish returned empty manifest")
        }

        let manifestData = Data(bytes: mPtr, count: manifestLen)
        c2pa_sm_bytes_free(mPtr, UInt(manifestLen))

        var exclusions: [ExclusionRange] = []
        if let exclusionsPtr {
            defer { c2pa_sm_exclusions_free(exclusionsPtr) }
            let ePtr = c2pa_sm_exclusions_data(exclusionsPtr, &errOut)
            if let err = checkAndFreeError(&errOut) {
                throw err
            }
            if exclusionsCount > 0 {
                guard let ePtr else {
                    throw C2PAError.internalError("build_finish returned no exclusion data")
                }
                let buf = UnsafeBufferPointer(start: ePtr, count: exclusionsCount)
                for ex in buf {
                    exclusions.append(ExclusionRange(start: ex.start, length: ex.len))
                }
            }
        }

        return SignResult(manifest: manifestData, exclusions: exclusions)
    }

    /// Static convenience method to sign an asset with a builder.
    @discardableResult
    public static func sign(
        format: String,
        manifestJson: String,
        source: any AsyncByteSource,
        destination: any AsyncByteSource & AsyncByteSink,
        signer: any AsyncSigner,
        urlSession: URLSession = .shared
    ) async throws -> SignResult {
        let builder = Builder(manifestJSON: manifestJson)
        return try await builder.sign(
            format: format,
            source: source,
            destination: destination,
            signer: signer,
            urlSession: urlSession
        )
    }
}
