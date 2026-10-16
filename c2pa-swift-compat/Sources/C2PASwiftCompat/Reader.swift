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

/// Validation outcome for a manifest store.
public enum ValidationState: String, Sendable, Codable {
    /// Cryptographically valid and trusted by configured trust anchors.
    case trusted = "Trusted"
    /// Cryptographically valid but not trusted by trust anchors.
    case valid = "Valid"
    /// Signature, hash integrity, or certificate validation failed.
    case invalid = "Invalid"
}

/// Asynchronous C2PA manifest reader.
///
/// Drives the sans-I/O C2PA state machine without spawning threads,
/// blocking cooperative concurrency executors, or creating priority inversions.
public final class Reader: Sendable {
    /// Full JSON manifest store report.
    public let jsonString: String

    /// Overall validation state.
    public let validationState: ValidationState

    /// Label of the active manifest, if present.
    public let activeManifestLabel: String?

    init(jsonString: String, validationState: ValidationState, activeManifestLabel: String?) {
        self.jsonString = jsonString
        self.validationState = validationState
        self.activeManifestLabel = activeManifestLabel
    }

    /// Returns the JSON representation of the manifest store.
    public func json() -> String {
        return jsonString
    }

    /// Reads and validates a manifest store from an asynchronous byte source.
    public static func read(
        context: C2PAContext = C2PAContext(),
        format: String,
        source: any AsyncByteSource
    ) async throws -> Reader {
        var errOut: UnsafeMutablePointer<CChar>? = nil
        let settingsJson = try context.settingsJSON()

        let session: OpaquePointer? = format.withCString { fmtCStr in
            if let settings = settingsJson {
                return settings.withCString { settingsCStr in
                    c2pa_sm_read_new(fmtCStr, settingsCStr, &errOut)
                }
            } else {
                return c2pa_sm_read_new(fmtCStr, nil, &errOut)
            }
        }

        if let err = checkAndFreeError(&errOut) {
            throw err
        }
        guard let session = session else {
            throw C2PAError.internalError("Failed to allocate read session")
        }
        defer {
            c2pa_sm_read_free(session)
        }

        while true {
            try Task.checkCancellation()

            var requestsPtr: UnsafePointer<C2paSmReadRequest>? = nil
            var requestCount: Int = 0

            let step = c2pa_sm_read_advance(session, &requestsPtr, &requestCount, &errOut)
            if let err = checkAndFreeError(&errOut) {
                throw err
            }

            if step == C2PA_SM_STEP_COMPLETE {
                break
            }
            if step == C2PA_SM_STEP_ERROR {
                throw C2PAError.internalError("Engine reported step error")
            }

            guard let reqs = requestsPtr, requestCount > 0 else {
                throw C2PAError.internalError("Session parked without requests")
            }

            let requestBuffer = UnsafeBufferPointer(start: reqs, count: requestCount)
            for req in requestBuffer {
                try Task.checkCancellation()

                switch req.kind {
                case UInt32(C2PA_SM_READ_REQ_LENGTH):
                    let len = try await source.length()
                    let rc = c2pa_sm_read_fulfill_length(session, req.id, len, &errOut)
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("fulfill_length failed") }

                case UInt32(C2PA_SM_READ_REQ_READ):
                    let data = try await source.read(at: req.start, count: Int(req.len))
                    let rc: Int32 = data.withUnsafeBytes { rawBuf in
                        let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        return c2pa_sm_read_fulfill_bytes(session, req.id, ptr, UInt(data.count), &errOut)
                    }
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("fulfill_bytes failed") }

                case UInt32(C2PA_SM_READ_REQ_CURRENT_DATE_TIME):
                    let now = Int64(Date().timeIntervalSince1970)
                    let rc = c2pa_sm_read_fulfill_time(session, req.id, now, &errOut)
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("fulfill_time failed") }

                case UInt32(C2PA_SM_READ_REQ_OCSP):
                    guard let urlStr = req.url.map({ String(cString: $0) }),
                          let url = URL(string: urlStr) else {
                        let _ = "invalid OCSP URL".withCString { msgCStr in
                            c2pa_sm_read_fulfill_failed(session, req.id, msgCStr, &errOut)
                        }
                        continue
                    }

                    let derData: Data
                    if let derPtr = req.request_der, req.request_der_len > 0 {
                        derData = Data(bytes: derPtr, count: Int(req.request_der_len))
                    } else {
                        derData = Data()
                    }

                    var urlReq = URLRequest(url: url)
                    urlReq.httpMethod = "POST"
                    urlReq.setValue("application/ocsp-request", forHTTPHeaderField: "Content-Type")
                    urlReq.httpBody = derData

                    do {
                        let (respData, _) = try await context.urlSession.data(for: urlReq)
                        let rc: Int32 = respData.withUnsafeBytes { rawBuf in
                            let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                            return c2pa_sm_read_fulfill_ocsp(session, req.id, ptr, UInt(respData.count), &errOut)
                        }
                        if let err = checkAndFreeError(&errOut) { throw err }
                        if rc != 0 { throw C2PAError.internalError("fulfill_ocsp failed") }
                    } catch {
                        let _ = error.localizedDescription.withCString { msgCStr in
                            c2pa_sm_read_fulfill_failed(session, req.id, msgCStr, &errOut)
                        }
                    }

                default:
                    throw C2PAError.internalError("Unknown read request kind: \(req.kind)")
                }
            }
        }

        var jsonOut: UnsafeMutablePointer<CChar>? = nil
        var hasManifest: Bool = false

        let rc = c2pa_sm_read_finish(session, &jsonOut, &hasManifest, &errOut)
        if let err = checkAndFreeError(&errOut) {
            throw err
        }
        if rc != 0 {
            throw C2PAError.internalError("read_finish returned error code \(rc)")
        }

        guard hasManifest, let cJson = jsonOut else {
            throw C2PAError.jumbfNotFound
        }

        let jsonString = String(cString: cJson)
        c2pa_sm_string_free(jsonOut)

        // Parse validation state and active manifest label from JSON.
        let (valState, activeLabel) = parseManifestMetadata(from: jsonString)
        return Reader(jsonString: jsonString, validationState: valState, activeManifestLabel: activeLabel)
    }

    /// Synchronously reads and validates a manifest store from a synchronous Stream.
    public static func readSync(
        context: C2PAContext = C2PAContext(),
        format: String,
        stream: Stream
    ) throws -> Reader {
        var errOut: UnsafeMutablePointer<CChar>? = nil
        let settingsJson = try context.settingsJSON()

        let session: OpaquePointer? = format.withCString { fmtCStr in
            if let settings = settingsJson {
                return settings.withCString { settingsCStr in
                    c2pa_sm_read_new(fmtCStr, settingsCStr, &errOut)
                }
            } else {
                return c2pa_sm_read_new(fmtCStr, nil, &errOut)
            }
        }

        if let err = checkAndFreeError(&errOut) {
            throw err
        }
        guard let session = session else {
            throw C2PAError.internalError("Failed to allocate read session")
        }
        defer {
            c2pa_sm_read_free(session)
        }

        while true {
            var requestsPtr: UnsafePointer<C2paSmReadRequest>? = nil
            var requestCount: Int = 0

            let step = c2pa_sm_read_advance(session, &requestsPtr, &requestCount, &errOut)
            if let err = checkAndFreeError(&errOut) {
                throw err
            }

            if step == C2PA_SM_STEP_COMPLETE {
                break
            }
            if step == C2PA_SM_STEP_ERROR {
                throw C2PAError.internalError("Engine reported step error")
            }

            guard let reqs = requestsPtr, requestCount > 0 else {
                throw C2PAError.internalError("Session parked without requests")
            }

            let requestBuffer = UnsafeBufferPointer(start: reqs, count: requestCount)
            for req in requestBuffer {
                switch req.kind {
                case UInt32(C2PA_SM_READ_REQ_LENGTH):
                    let len = try stream.lengthSync()
                    let rc = c2pa_sm_read_fulfill_length(session, req.id, len, &errOut)
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("fulfill_length failed") }

                case UInt32(C2PA_SM_READ_REQ_READ):
                    let data = try stream.readSync(at: req.start, count: Int(req.len))
                    let rc: Int32 = data.withUnsafeBytes { rawBuf in
                        let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        return c2pa_sm_read_fulfill_bytes(session, req.id, ptr, UInt(data.count), &errOut)
                    }
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("fulfill_bytes failed") }

                case UInt32(C2PA_SM_READ_REQ_CURRENT_DATE_TIME):
                    let now = Int64(Date().timeIntervalSince1970)
                    let rc = c2pa_sm_read_fulfill_time(session, req.id, now, &errOut)
                    if let err = checkAndFreeError(&errOut) { throw err }
                    if rc != 0 { throw C2PAError.internalError("fulfill_time failed") }

                case UInt32(C2PA_SM_READ_REQ_OCSP):
                    let _ = "synchronous read does not support online OCSP".withCString { msgCStr in
                        c2pa_sm_read_fulfill_failed(session, req.id, msgCStr, &errOut)
                    }

                default:
                    throw C2PAError.internalError("Unknown read request kind: \(req.kind)")
                }
            }
        }

        var jsonOut: UnsafeMutablePointer<CChar>? = nil
        var hasManifest: Bool = false

        let rc = c2pa_sm_read_finish(session, &jsonOut, &hasManifest, &errOut)
        if let err = checkAndFreeError(&errOut) {
            throw err
        }
        if rc != 0 {
            throw C2PAError.internalError("read_finish returned error code \(rc)")
        }

        guard hasManifest, let cJson = jsonOut else {
            throw C2PAError.jumbfNotFound
        }

        let jsonString = String(cString: cJson)
        c2pa_sm_string_free(jsonOut)

        let (valState, activeLabel) = parseManifestMetadata(from: jsonString)
        return Reader(jsonString: jsonString, validationState: valState, activeManifestLabel: activeLabel)
    }
}

func checkAndFreeError(_ errOut: inout UnsafeMutablePointer<CChar>?) -> C2PAError? {
    guard let cStr = errOut else { return nil }
    let msg = String(cString: cStr)
    c2pa_sm_string_free(cStr)
    errOut = nil

    if msg.contains("JumbfNotFound") {
        return .jumbfNotFound
    }
    if msg.contains("Unsupported") || msg.contains("unsupported") {
        return .unsupportedType
    }
    return .internalError(msg)
}

func parseManifestMetadata(from json: String) -> (ValidationState, String?) {
    guard let data = json.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return (.invalid, nil)
    }

    let activeLabel = obj["active_manifest"] as? String
    let stateStr = obj["validation_state"] as? String ?? "Invalid"
    let state = ValidationState(rawValue: stateStr) ?? .invalid

    return (state, activeLabel)
}
