// ChannelBatchingTests.swift - Tests for channel-level batching behavior

@testable import OmertaMesh
import XCTest

// MARK: - Mock that tracks buffered vs immediate sends

private actor BatchingMockChannelProvider: ChannelProvider {
    let peerId: PeerId = "batch-test-peer"

    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]

    /// Records of immediate (unbuffered) sends
    private(set) var immediateSends: [(to: String, channel: String, data: Data)] = []

    /// Buffers keyed by "\(channel):\(destination)"
    private var buffers: [String: (packets: [Data], totalSize: Int)] = [:]
    private var flushTasks: [String: Task<Void, Never>] = [:]

    /// Batch config per channel (defaults to BatchConfig.default)
    private var batchConfigs: [String: BatchConfig] = [:]

    /// Records of flushed batches (each entry = one flush call that produced a send)
    private(set) var flushedBatches: [(channel: String, packetCount: Int, totalSize: Int)] = []

    /// Number of times flushChannel was called (including no-op flushes)
    private(set) var flushCallCount = 0

    // MARK: - Configuration

    func setBatchConfig(_ config: BatchConfig, for channel: String) {
        batchConfigs[channel] = config
    }

    // MARK: - ChannelProvider

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        try await onChannel(channel, handler: handler)
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    // MARK: - Immediate (unbuffered) send

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        immediateSends.append((to: peerId, channel: channel, data: data))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        immediateSends.append((to: machineId, channel: channel, data: data))
    }

    // MARK: - Buffered send

    func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws {
        let key = "\(channel):peer:\(peerId)"
        appendToBuffer(key, data: data, channel: channel)
    }

    func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        let key = "\(channel):machine:\(machineId)"
        appendToBuffer(key, data: data, channel: channel)
    }

    func flushChannel(_ channel: String) async throws {
        flushCallCount += 1
        let prefix = "\(channel):"
        let keysToFlush = buffers.keys.filter { $0.hasPrefix(prefix) }
        for key in keysToFlush {
            await doFlush(key, channel: channel)
        }
    }

    // MARK: - Internal buffering logic (mirrors MeshNode)

    private func appendToBuffer(_ key: String, data: Data, channel: String) {
        var entry = buffers[key] ?? (packets: [], totalSize: 0)
        entry.packets.append(data)
        entry.totalSize += data.count
        buffers[key] = entry

        let config = batchConfigs[channel] ?? .default

        // Size threshold auto-flush
        if config.maxBufferSize > 0 && entry.totalSize >= config.maxBufferSize {
            let ch = channel
            let k = key
            Task { [weak self] in
                await self?.doFlush(k, channel: ch)
            }
            return
        }

        // Auto-flush timer
        if flushTasks[key] == nil {
            let delay = config.maxFlushDelay
            let ch = channel
            let k = key
            flushTasks[key] = Task { [weak self] in
                try? await Task.sleep(for: delay)
                guard !Task.isCancelled else { return }
                await self?.doFlush(k, channel: ch)
            }
        }
    }

    private func doFlush(_ key: String, channel: String) {
        flushTasks[key]?.cancel()
        flushTasks.removeValue(forKey: key)

        guard let entry = buffers.removeValue(forKey: key), !entry.packets.isEmpty else {
            return
        }

        flushedBatches.append((channel: channel, packetCount: entry.packets.count, totalSize: entry.totalSize))

        // Also record as an immediate send (the flush produces a real send)
        let batchData = Data(entry.packets.joined())
        immediateSends.append((to: "flushed", channel: channel, data: batchData))
    }

    // MARK: - Test helpers

    func getBufferState(channel: String, destination: String) -> (packetCount: Int, totalSize: Int)? {
        let key = "\(channel):\(destination)"
        guard let entry = buffers[key] else { return nil }
        return (entry.packets.count, entry.totalSize)
    }

    func clearRecords() {
        immediateSends.removeAll()
        flushedBatches.removeAll()
        flushCallCount = 0
    }
}

// MARK: - Tests

final class ChannelBatchingTests: XCTestCase {

    // MARK: 1. testSendOnChannelBufferedAccumulates

    func testSendOnChannelBufferedAccumulates() async throws {
        let mock = BatchingMockChannelProvider()
        // Use a very long flush delay so auto-flush won't fire during the test
        await mock.setBatchConfig(
            BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 0),
            for: "data"
        )

        // Send 3 buffered messages
        try await mock.sendOnChannelBuffered(Data([1, 2]), to: "peerA", channel: "data")
        try await mock.sendOnChannelBuffered(Data([3, 4]), to: "peerA", channel: "data")
        try await mock.sendOnChannelBuffered(Data([5, 6]), to: "peerA", channel: "data")

        // No immediate sends should have been triggered
        let sends = await mock.immediateSends
        XCTAssertEqual(sends.count, 0, "Buffered sends should not trigger immediate sends")

        // Buffer should have accumulated 3 packets
        let state = await mock.getBufferState(channel: "data", destination: "peer:peerA")
        XCTAssertNotNil(state)
        XCTAssertEqual(state?.packetCount, 3)
        XCTAssertEqual(state?.totalSize, 6)
    }

    // MARK: 2. testFlushChannelSendsAll

    func testFlushChannelSendsAll() async throws {
        let mock = BatchingMockChannelProvider()
        await mock.setBatchConfig(
            BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 0),
            for: "data"
        )

        // Accumulate buffered sends
        try await mock.sendOnChannelBuffered(Data([1, 2, 3]), to: "peerA", channel: "data")
        try await mock.sendOnChannelBuffered(Data([4, 5]), to: "peerA", channel: "data")

        // Flush
        try await mock.flushChannel("data")

        // Should have produced exactly one flushed batch containing both packets
        let batches = await mock.flushedBatches
        XCTAssertEqual(batches.count, 1)
        XCTAssertEqual(batches[0].packetCount, 2)
        XCTAssertEqual(batches[0].totalSize, 5)
        XCTAssertEqual(batches[0].channel, "data")

        // Buffer should now be empty
        let state = await mock.getBufferState(channel: "data", destination: "peer:peerA")
        XCTAssertNil(state, "Buffer should be empty after flush")
    }

    // MARK: 3. testAutoFlushTimerFires

    func testAutoFlushTimerFires() async throws {
        let mock = BatchingMockChannelProvider()
        // Short auto-flush delay
        await mock.setBatchConfig(
            BatchConfig(maxFlushDelay: .milliseconds(50), maxBufferSize: 0),
            for: "events"
        )

        // Buffer a message — auto-flush timer starts
        try await mock.sendOnChannelBuffered(Data([0xAA]), to: "peerB", channel: "events")

        // Immediately, no flush yet
        let sendsBefore = await mock.flushedBatches
        XCTAssertEqual(sendsBefore.count, 0)

        // Wait for auto-flush to fire
        try await Task.sleep(for: .milliseconds(150))

        let sendsAfter = await mock.flushedBatches
        XCTAssertEqual(sendsAfter.count, 1, "Auto-flush timer should have fired")
        XCTAssertEqual(sendsAfter[0].packetCount, 1)
    }

    // MARK: 4. testAutoFlushTimerResetsOnFlush

    func testAutoFlushTimerResetsOnFlush() async throws {
        let mock = BatchingMockChannelProvider()
        await mock.setBatchConfig(
            BatchConfig(maxFlushDelay: .milliseconds(100), maxBufferSize: 0),
            for: "ctrl"
        )

        // Buffer a message — starts auto-flush timer
        try await mock.sendOnChannelBuffered(Data([1]), to: "peerC", channel: "ctrl")

        // Manually flush before timer fires
        try await mock.flushChannel("ctrl")

        let batchesAfterManual = await mock.flushedBatches
        XCTAssertEqual(batchesAfterManual.count, 1)

        // Wait for what would have been the auto-flush time
        try await Task.sleep(for: .milliseconds(200))

        // No additional flush should have occurred (timer was cancelled)
        let batchesAfterWait = await mock.flushedBatches
        XCTAssertEqual(batchesAfterWait.count, 1, "Manual flush should cancel pending auto-flush timer")
    }

    // MARK: 5. testEmptyFlushIsNoop

    func testEmptyFlushIsNoop() async throws {
        let mock = BatchingMockChannelProvider()

        // Flush with nothing buffered
        try await mock.flushChannel("nonexistent")

        let sends = await mock.immediateSends
        XCTAssertEqual(sends.count, 0, "Flushing an empty buffer should produce no sends")

        let batches = await mock.flushedBatches
        XCTAssertEqual(batches.count, 0)

        let callCount = await mock.flushCallCount
        XCTAssertEqual(callCount, 1, "flushChannel should still have been called once")
    }

    // MARK: 6. testSendAndFlushBypassesBuffer

    func testSendAndFlushBypassesBuffer() async throws {
        let mock = BatchingMockChannelProvider()

        // Use unbuffered sendOnChannel — should send immediately
        try await mock.sendOnChannel(Data([0xFF]), to: "peerD", channel: "urgent")

        let sends = await mock.immediateSends
        XCTAssertEqual(sends.count, 1)
        XCTAssertEqual(sends[0].to, "peerD")
        XCTAssertEqual(sends[0].channel, "urgent")
        XCTAssertEqual(sends[0].data, Data([0xFF]))

        // No buffered batches
        let batches = await mock.flushedBatches
        XCTAssertEqual(batches.count, 0)

        // Buffer should be empty
        let state = await mock.getBufferState(channel: "urgent", destination: "peer:peerD")
        XCTAssertNil(state)
    }

    // MARK: 7. testBufferSizeTrigger

    func testBufferSizeTrigger() async throws {
        let mock = BatchingMockChannelProvider()
        // Auto-flush at 10 bytes, long timer so only size triggers
        await mock.setBatchConfig(
            BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 10),
            for: "bulk"
        )

        // Send 8 bytes — below threshold
        try await mock.sendOnChannelBuffered(Data(repeating: 0x01, count: 8), to: "peerE", channel: "bulk")

        // Give the Task a moment (size flush is dispatched as a Task)
        try await Task.sleep(for: .milliseconds(50))

        let batchesBefore = await mock.flushedBatches
        XCTAssertEqual(batchesBefore.count, 0, "Below threshold should not trigger flush")

        // Send 4 more bytes — total 12, exceeds threshold
        try await mock.sendOnChannelBuffered(Data(repeating: 0x02, count: 4), to: "peerE", channel: "bulk")

        // Give the size-triggered Task time to run
        try await Task.sleep(for: .milliseconds(50))

        let batchesAfter = await mock.flushedBatches
        XCTAssertEqual(batchesAfter.count, 1, "Exceeding maxBufferSize should trigger auto-flush")
        XCTAssertEqual(batchesAfter[0].packetCount, 2)
        XCTAssertEqual(batchesAfter[0].totalSize, 12)
    }

    // MARK: 8. testConcurrentBufferedSends

    func testConcurrentBufferedSends() async throws {
        let mock = BatchingMockChannelProvider()
        await mock.setBatchConfig(
            BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 0),
            for: "concurrent"
        )

        let sendCount = 100

        // Fire off many concurrent buffered sends
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<sendCount {
                group.addTask {
                    try? await mock.sendOnChannelBuffered(
                        Data([UInt8(i % 256)]),
                        to: "peerF",
                        channel: "concurrent"
                    )
                }
            }
        }

        // All sends should be in the buffer without corruption
        let state = await mock.getBufferState(channel: "concurrent", destination: "peer:peerF")
        XCTAssertNotNil(state)
        XCTAssertEqual(state?.packetCount, sendCount, "All concurrent sends should be buffered")
        XCTAssertEqual(state?.totalSize, sendCount, "Each send is 1 byte")

        // No immediate sends should have occurred
        let sends = await mock.immediateSends
        XCTAssertEqual(sends.count, 0)

        // Flush and verify all data comes out
        try await mock.flushChannel("concurrent")

        let batches = await mock.flushedBatches
        XCTAssertEqual(batches.count, 1)
        XCTAssertEqual(batches[0].packetCount, sendCount)
    }
}
