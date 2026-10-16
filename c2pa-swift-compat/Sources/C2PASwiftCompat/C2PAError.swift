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

/// Errors produced by C2PA reading and signing operations.
public enum C2PAError: Error, CustomStringConvertible, Sendable {
    /// Manifest store was not found in the container.
    case jumbfNotFound
    /// Container format is unsupported.
    case unsupportedType
    /// An I/O error occurred while servicing asset or stream requests.
    case ioError(String)
    /// Operation was cancelled.
    case cancelled
    /// An internal engine or C ABI error occurred.
    case internalError(String)
    /// An invalid parameter was passed to an operation.
    case invalidParameter(String)

    public var description: String {
        switch self {
        case .jumbfNotFound:
            return "C2PA(JumbfNotFound): manifest store not found"
        case .unsupportedType:
            return "C2PA(UnsupportedType): unsupported container format"
        case .ioError(let msg):
            return "C2PA(IoError): \(msg)"
        case .cancelled:
            return "C2PA(Cancelled): operation was cancelled"
        case .internalError(let msg):
            return "C2PA(InternalError): \(msg)"
        case .invalidParameter(let msg):
            return "C2PA(InvalidParameter): \(msg)"
        }
    }
}
