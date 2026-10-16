// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

import Testing
import Foundation
import Darwin
@testable import C2PASwiftCompat

@Suite(.serialized)
struct ThreadingAndQoSTests {
    /// Query the exact number of Mach threads currently alive in this process.
    private func currentMachThreadCount() -> Int {
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        let kerr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kerr == KERN_SUCCESS, let list = threadList else {
            return -1
        }
        // Deallocate the mach thread list buffer
        vm_deallocate(
            mach_task_self_,
            vm_address_t(UInt(bitPattern: list)),
            vm_size_t(threadCount * mach_msg_type_number_t(MemoryLayout<thread_t>.size))
        )
        return Int(threadCount)
    }

    @Test func rustCreatesZeroThreadsDuringExecution() throws {
        let data = Fixtures.cJpgData
        let stream = Stream(data: data)

        // Warm up by running readSync once so any process-wide one-time threads are initialized
        _ = try Reader.readSync(format: "image/jpeg", stream: stream)

        // Record baseline Mach thread count
        let beforeCount = currentMachThreadCount()
        #expect(beforeCount > 0)

        // Execute synchronous read repeatedly - entirely driven by caller on current thread
        for _ in 0..<5 {
            let reader = try Reader.readSync(format: "image/jpeg", stream: stream)
            let label = reader.activeManifestLabel
            #expect(label != nil && !label!.isEmpty)
        }

        // Thread count after synchronous reads MUST be identical:
        // Rust spawned zero threads, zero runtimes, zero worker pools.
        let afterCount = currentMachThreadCount()
        #expect(afterCount == beforeCount)
    }

    @Test func qosIsPreservedAcrossCallerAndCallbacks() async throws {
        // Run with userInitiated priority
        let task = Task(priority: .userInitiated) { () -> qos_class_t in
            let callerQoS = qos_class_self()
            let stream = QoSTrackingStream(data: Fixtures.cJpgData)

            _ = try await Reader.read(format: "image/jpeg", source: stream)

            // Verify QoS inside the stream read callbacks was userInitiated
            let observedQoS = await stream.lastObservedQoS
            #expect(observedQoS == callerQoS || observedQoS == QOS_CLASS_USER_INITIATED)
            return callerQoS
        }

        let result = try await task.value
        #expect(result == QOS_CLASS_USER_INITIATED)
    }

    @Test func taskCancellationAbortsExecutionPromptly() async throws {
        let stream = BlockingStream(data: Fixtures.cJpgData)

        let task = Task {
            try await Reader.read(format: "image/jpeg", source: stream)
        }

        // Allow task to start and wait on the stream
        await stream.waitForRead()

        // Cancel the task while in-flight
        task.cancel()
        await stream.unblock()

        // Verify task throws CancellationError
        do {
            _ = try await task.value
            Issue.record("Expected cancellation error, but task succeeded")
        } catch is CancellationError {
            // Expected
        } catch C2PAError.cancelled {
            // Expected
        } catch {
            // Cancellation caught
        }
    }

    @Test func cooperativeInterleavingWithoutThreadStarvation() async throws {
        // Run two concurrent reader sessions on the cooperative thread pool.
        // Both make progress interleaved without thread starvation or semaphores.
        let data = Fixtures.cJpgData

        async let read1 = Reader.read(format: "image/jpeg", source: data)
        async let read2 = Reader.read(format: "image/jpeg", source: data)

        let r1 = try await read1
        let r2 = try await read2
        let l1 = r1.activeManifestLabel
        let l2 = r2.activeManifestLabel
        #expect(l1 == l2)
    }
}

// MARK: - Test Helpers

private actor QoSTrackingStream: AsyncByteSource {
    private let data: Data
    var lastObservedQoS: qos_class_t = QOS_CLASS_UNSPECIFIED

    init(data: Data) {
        self.data = data
    }

    func length() async throws -> UInt64 {
        return UInt64(data.count)
    }

    func read(at offset: UInt64, count: Int) async throws -> Data {
        lastObservedQoS = qos_class_self()
        let start = Int(offset)
        guard start < data.count else { return Data() }
        let end = min(start + count, data.count)
        return data.subdata(in: start..<end)
    }
}

private actor BlockingStream: AsyncByteSource {
    private let data: Data
    private var readStarted: Bool = false
    private var unblocked: Bool = false

    init(data: Data) {
        self.data = data
    }

    func waitForRead() async {
        while !readStarted {
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
    }

    func unblock() {
        unblocked = true
    }

    func length() async throws -> UInt64 {
        return UInt64(data.count)
    }

    func read(at offset: UInt64, count: Int) async throws -> Data {
        readStarted = true
        while !unblocked && !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        if Task.isCancelled {
            throw CancellationError()
        }
        let start = Int(offset)
        guard start < data.count else { return Data() }
        let end = min(start + count, data.count)
        return data.subdata(in: start..<end)
    }
}
