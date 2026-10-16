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

/// Asynchronous byte source providing random-access read capability.
public protocol AsyncByteSource: Sendable {
    /// Returns total length of the asset in bytes.
    func length() async throws -> UInt64

    /// Reads up to `count` bytes starting at `offset`.
    func read(at offset: UInt64, count: Int) async throws -> Data
}

/// Asynchronous byte sink providing positional write capability.
public protocol AsyncByteSink: Sendable {
    /// Writes `data` starting at `offset`.
    func write(at offset: UInt64, data: Data) async throws
}

/// In-memory asynchronous byte buffer conforming to both Source and Sink.
public actor InMemoryByteStream: AsyncByteSource, AsyncByteSink {
    private var buffer: Data

    public init(data: Data = Data()) {
        self.buffer = data
    }

    public func length() async throws -> UInt64 {
        return UInt64(buffer.count)
    }

    public func read(at offset: UInt64, count: Int) async throws -> Data {
        let start = Int(offset)
        guard start < buffer.count else { return Data() }
        let end = min(start + count, buffer.count)
        return buffer.subdata(in: start..<end)
    }

    public func write(at offset: UInt64, data: Data) async throws {
        let start = Int(offset)
        let end = start + data.count
        if end > buffer.count {
            buffer.count = end
        }
        buffer.replaceSubrange(start..<end, with: data)
    }

    public func data() -> Data {
        return buffer
    }
}

/// In-memory Data wrapped as an AsyncByteSource.
public struct DataByteSource: AsyncByteSource {
    private let data: Data

    public init(data: Data) {
        self.data = data
    }

    public func length() async throws -> UInt64 {
        return UInt64(data.count)
    }

    public func read(at offset: UInt64, count: Int) async throws -> Data {
        let start = Int(offset)
        guard start < data.count else { return Data() }
        let end = min(start + count, data.count)
        return data.subdata(in: start..<end)
    }
}

/// File-backed asynchronous byte source.
public actor FileByteSource: AsyncByteSource {
    private let fileHandle: FileHandle
    private let fileSize: UInt64

    public init(url: URL) throws {
        self.fileHandle = try FileHandle(forReadingFrom: url)
        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        self.fileSize = UInt64(values.fileSize ?? 0)
    }

    deinit {
        try? fileHandle.close()
    }

    public func length() async throws -> UInt64 {
        return fileSize
    }

    public func read(at offset: UInt64, count: Int) async throws -> Data {
        try fileHandle.seek(toOffset: offset)
        return fileHandle.readData(ofLength: count)
    }
}

/// Synchronous Stream compatible with c2pa-swift's Stream interface.
public final class Stream: @unchecked Sendable {
    public typealias ReadHandler = @Sendable (Int) throws -> Data
    public typealias SeekHandler = @Sendable (Int64, SeekOrigin) throws -> UInt64
    public typealias WriteHandler = @Sendable (Data) throws -> Int

    public enum SeekOrigin: Sendable {
        case start
        case current
        case end
    }

    private let readHandler: ReadHandler
    private let seekHandler: SeekHandler
    private let writeHandler: WriteHandler?
    private let lock = NSLock()

    public init(
        read: @escaping ReadHandler,
        seek: @escaping SeekHandler,
        write: WriteHandler? = nil
    ) {
        self.readHandler = read
        self.seekHandler = seek
        self.writeHandler = write
    }

    public func readSync(at offset: UInt64, count: Int) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        _ = try seekHandler(Int64(offset), .start)
        return try readHandler(count)
    }

    public func lengthSync() throws -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let current = try seekHandler(0, .current)
        let total = try seekHandler(0, .end)
        _ = try seekHandler(Int64(current), .start)
        return total
    }

    public func writeSync(at offset: UInt64, data: Data) throws {
        guard let write = writeHandler else {
            throw C2PAError.ioError("Stream does not support writing")
        }
        lock.lock()
        defer { lock.unlock() }
        _ = try seekHandler(Int64(offset), .start)
        _ = try write(data)
    }
}

extension Stream: AsyncByteSource {
    public func length() async throws -> UInt64 {
        try lengthSync()
    }

    public func read(at offset: UInt64, count: Int) async throws -> Data {
        try readSync(at: offset, count: count)
    }
}

extension Stream: AsyncByteSink {
    public func write(at offset: UInt64, data: Data) async throws {
        try writeSync(at: offset, data: data)
    }
}

extension Data: AsyncByteSource {
    public func length() async throws -> UInt64 {
        return UInt64(count)
    }

    public func read(at offset: UInt64, count: Int) async throws -> Data {
        let start = Int(offset)
        guard start < self.count else { return Data() }
        let end = Swift.min(start + count, self.count)
        return subdata(in: start..<end)
    }
}

final class StreamBuffer: @unchecked Sendable {
    private var buffer: Data
    private var position: Int = 0
    private let lock = NSLock()

    init(data: Data = Data()) {
        self.buffer = data
    }

    var data: Data {
        lock.lock()
        defer { lock.unlock() }
        return buffer
    }

    func read(count: Int) -> Data {
        lock.lock()
        defer { lock.unlock() }
        let start = position
        guard start < buffer.count else { return Data() }
        let end = Swift.min(start + count, buffer.count)
        position = end
        return buffer.subdata(in: start..<end)
    }

    func seek(offset: Int64, whence: Stream.SeekOrigin) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        switch whence {
        case .start:
            position = max(0, Int(offset))
        case .current:
            position = max(0, position + Int(offset))
        case .end:
            position = max(0, buffer.count + Int(offset))
        }
        return UInt64(position)
    }

    func write(data toWrite: Data) -> Int {
        lock.lock()
        defer { lock.unlock() }
        let start = position
        if start > buffer.count {
            buffer.append(Data(repeating: 0, count: start - buffer.count))
        }
        let end = start + toWrite.count
        if end <= buffer.count {
            buffer.replaceSubrange(start..<end, with: toWrite)
        } else {
            let replaceCount = buffer.count - start
            if replaceCount > 0 {
                buffer.replaceSubrange(start..<buffer.count, with: toWrite.prefix(replaceCount))
                buffer.append(toWrite.dropFirst(replaceCount))
            } else {
                buffer.append(toWrite)
            }
        }
        position = end
        return toWrite.count
    }
}

extension Stream {
    /// Convenience initializer creating an in-memory stream backed by `Data`.
    public convenience init(data: Data = Data()) {
        let storage = StreamBuffer(data: data)
        self.init(
            read: { count in
                storage.read(count: count)
            },
            seek: { offset, whence in
                storage.seek(offset: offset, whence: whence)
            },
            write: { toWrite in
                storage.write(data: toWrite)
            }
        )
    }
}

